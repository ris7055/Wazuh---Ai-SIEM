# threat_hunter.py
#
# Standalone Conversational Wazuh SOC Assistant
# - FastAPI + WebSocket Chat UI
# - RAG over local Wazuh logs (alerts / archives)
# - Direct SOC authentication analysis from Wazuh Indexer API
# - Session memory per chat connection
# - Analyst-style responses, comparison, top IPs, recommendations
#
# Example:
#   sudo python3 /var/ossec/integrations/threat_hunter.py --days 2 --source alerts --agent all

import sys
sys.path.append("/opt/ai-soc")

import json
import os
import gzip
import argparse
import secrets
import urllib3
import re

from datetime import datetime, timedelta, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, status, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import uvicorn

from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_ollama import ChatOllama
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.documents import Document

from soc_utils import (
    set_config,
    get_latest_alerts,
    build_per_host_summary,
    parse_ai_json,
    normalize_ai_report,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =========================
# Globals / Configuration
# =========================

qa_chain = None
context = None

days_range = 2
agent_filter = "all"
log_source = "alerts"

username = "admin"
password = "admin"

ssh_username = "<SSH_USERNAME>"
ssh_password = "<SSH_PASSWORD>"
remote_host = None

WAZUH_API = "https://localhost:55000"
INDEXER_API = "https://localhost:9200"

WAZUH_USER = "wazuh"
WAZUH_PASS = "rVlSP38A6hQC3+X0zY5Gvt9d?6Oy+MI3"

INDEXER_USER = "admin"
INDEXER_PASS = "?uzRHjvR6+x3mAw?Aq9FiN??3I3CRVp*"

VERIFY_TLS = False
OLLAMA_MODEL = "llama3"

security = HTTPBasic()

# =========================
# Auth
# =========================

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    username_match = secrets.compare_digest(credentials.username, username)
    password_match = secrets.compare_digest(credentials.password, password)
    if not (username_match and password_match):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# =========================
# Session helpers
# =========================

def session_defaults():
    return {
        "agent": agent_filter,
        "hours": 1,
        "source": log_source,
        "days": days_range,
        "watch_enabled": False,
        "watch_interval": 60,
        "last_mode": "soc_auth",
        "last_question": None,
    }


def apply_session_updates(session: dict, updates: dict):
    for key, value in updates.items():
        if value is not None:
            session[key] = value

# =========================
# Generic helpers
# =========================

def parse_wazuh_timestamp(ts: str):
    if not ts:
        return None

    ts = ts.strip()

    try:
        if ts.endswith("Z"):
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if len(ts) >= 5 and (ts[-5] in ["+", "-"]) and ts[-2:].isdigit():
            if ts[-3] != ":":
                ts = ts[:-2] + ":" + ts[-2:]
        return datetime.fromisoformat(ts)
    except Exception:
        pass

    try:
        return datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")
    except Exception:
        pass

    try:
        return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    except Exception:
        return None


def format_history(history_pairs, max_turns=12):
    trimmed = history_pairs[-max_turns:]
    lines = []
    for role, text in trimmed:
        prefix = "User" if role == "user" else "Assistant"
        lines.append(f"{prefix}: {text}")
    return "\n".join(lines).strip()


def event_to_text(evt: dict) -> str:
    agent = evt.get("agent") or {}
    agent_name = agent.get("name", "unknown-agent")
    agent_id = agent.get("id", "unknown-id")
    agent_ip = agent.get("ip", "unknown-ip")

    rule = evt.get("rule") or {}
    rule_id = rule.get("id", "")
    rule_level = rule.get("level", "")
    rule_desc = rule.get("description", "")

    ts = evt.get("timestamp") or evt.get("@timestamp") or ""
    location = evt.get("location", "") or ""
    decoder = (evt.get("decoder") or {}).get("name", "")

    data = evt.get("data") or {}

    parts = [
        f"timestamp: {ts}",
        f"agent: {agent_name} (id={agent_id}, ip={agent_ip})",
        f"rule: id={rule_id} level={rule_level} desc={rule_desc}",
        f"decoder: {decoder}",
        f"location: {location}",
    ]

    if data:
        parts.append("data: " + json.dumps(data, ensure_ascii=False))

    full_log = evt.get("full_log", "")
    if isinstance(full_log, str) and full_log.strip():
        parts.append("full_log: " + full_log.strip())

    parts.append("raw_event: " + json.dumps(evt, ensure_ascii=False))
    return "\n".join(parts)


def get_stats(logs):
    total = len(logs)
    parsed = []

    for evt in logs:
        ts = evt.get("timestamp") or evt.get("@timestamp") or ""
        t = parse_wazuh_timestamp(ts)
        if t:
            parsed.append(t)

    if parsed:
        earliest = min(parsed)
        latest = max(parsed)
        return f"Events loaded: {total} | range: {earliest} -> {latest}"
    return f"Events loaded: {total}"

# =========================
# Local file loaders for RAG
# =========================

def load_alerts_from_days(past_days=1, selected_agent="all"):
    base = "/var/ossec/logs/alerts/alerts.json"
    if not os.path.exists(base):
        print(f"⚠️ alerts.json not found at {base}", flush=True)
        return []

    logs = []
    cutoff = datetime.now(timezone.utc) - timedelta(days=past_days)

    with open(base, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = evt.get("timestamp") or evt.get("@timestamp") or ""
            t = parse_wazuh_timestamp(ts)
            if t:
                if t.tzinfo is None:
                    t = t.replace(tzinfo=timezone.utc)
                if t < cutoff:
                    continue

            if selected_agent != "all":
                a = (evt.get("agent") or {}).get("name", "")
                if a.lower() != selected_agent.lower():
                    continue

            logs.append(evt)

    return logs


def load_logs_from_remote(host, user, password, past_days, selected_agent="all"):
    import paramiko

    logs = []
    today = datetime.now()

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=user, password=password, timeout=10)
        sftp = ssh.open_sftp()

        for i in range(past_days):
            day = today - timedelta(days=i)
            year = day.year
            month_name = day.strftime("%b")
            day_num = day.strftime("%d")

            base_path = f"/var/ossec/logs/archives/{year}/{month_name}"
            json_path = f"{base_path}/ossec-archive-{day_num}.json"
            gz_path = f"{base_path}/ossec-archive-{day_num}.json.gz"

            remote_file = None
            try:
                if sftp.stat(json_path).st_size > 0:
                    remote_file = sftp.open(json_path, "r")
                elif sftp.stat(gz_path).st_size > 0:
                    remote_file = gzip.GzipFile(fileobj=sftp.open(gz_path, "rb"))
            except IOError:
                print(f"⚠️ Remote log not found or unreadable: {json_path} / {gz_path}", flush=True)
                continue

            if remote_file:
                try:
                    for line in remote_file:
                        if isinstance(line, bytes):
                            line = line.decode("utf-8", errors="ignore")
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        if selected_agent != "all":
                            a = (evt.get("agent") or {}).get("name", "")
                            if a and a.lower() != selected_agent.lower():
                                continue

                        logs.append(evt)
                except Exception as e:
                    print(f"⚠️ Error reading remote file: {e}", flush=True)

        sftp.close()
        ssh.close()
    except Exception as e:
        print(f"❌ Remote connection failed: {e}", flush=True)

    return logs


def load_archives_from_days(past_days=7, selected_agent="all"):
    if remote_host:
        return load_logs_from_remote(remote_host, ssh_username, ssh_password, past_days, selected_agent)

    logs = []
    today = datetime.now()

    for i in range(past_days):
        day = today - timedelta(days=i)
        year = day.year
        month_name = day.strftime("%b")
        day_num = day.strftime("%d")

        json_path = f"/var/ossec/logs/archives/{year}/{month_name}/ossec-archive-{day_num}.json"
        gz_path = f"/var/ossec/logs/archives/{year}/{month_name}/ossec-archive-{day_num}.json.gz"

        file_path = None
        open_func = None

        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            file_path = json_path
            open_func = open
        elif os.path.exists(gz_path) and os.path.getsize(gz_path) > 0:
            file_path = gz_path
            open_func = gzip.open
        else:
            print(f"⚠️ Log file missing or empty: {json_path} / {gz_path}", flush=True)
            continue

        try:
            with open_func(file_path, "rt", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if selected_agent != "all":
                        a = (evt.get("agent") or {}).get("name", "")
                        if a and a.lower() != selected_agent.lower():
                            continue

                    logs.append(evt)
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}", flush=True)

    return logs


def load_logs_from_days(past_days=7, selected_source="alerts", selected_agent="all"):
    if selected_source == "alerts":
        return load_alerts_from_days(past_days=past_days, selected_agent=selected_agent)
    return load_archives_from_days(past_days=past_days, selected_agent=selected_agent)

# =========================
# Vector store + chain (file RAG)
# =========================

def create_vectorstore(logs, embedding_model):
    text_splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=100)
    documents = []

    for evt in logs:
        text = event_to_text(evt)
        if not text.strip():
            continue
        for chunk in text_splitter.split_text(text):
            documents.append(Document(page_content=chunk))

    return FAISS.from_documents(documents, embedding_model)


def initialize_assistant_context():
    return (
        "You are a security analyst performing threat hunting.\n"
        "You analyze Wazuh events provided as context.\n"
        "Identify security threats, suspicious patterns, and answer user questions using the retrieved Wazuh context.\n"
        "If the logs do not contain enough information, clearly say what is missing.\n"
        "When useful, summarize by affected agents, usernames, source IPs, timeframe, and suggested next steps."
    )


def setup_chain(past_days=7, selected_source="alerts", selected_agent="all"):
    global qa_chain, context

    print(
        f"🔄 Initializing retrieval chain | source={selected_source} | "
        f"agent={selected_agent} | past_days={past_days}",
        flush=True
    )

    logs = load_logs_from_days(
        past_days=past_days,
        selected_source=selected_source,
        selected_agent=selected_agent,
    )

    if not logs:
        print("❌ No logs found. Skipping chain setup.", flush=True)
        qa_chain = None
        return

    print(f"✅ {len(logs)} events loaded.", flush=True)
    print("📦 Creating vectorstore...", flush=True)

    embedding_model = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")
    vectorstore = create_vectorstore(logs, embedding_model)

    retriever = vectorstore.as_retriever(search_kwargs={"k": 4})
    llm = ChatOllama(model=OLLAMA_MODEL)

    context = initialize_assistant_context()

    prompt = ChatPromptTemplate.from_messages([
        ("system", context),
        (
            "human",
            "Chat history:\n{chat_history}\n\n"
            "User question: {input}\n\n"
            "Use the following retrieved Wazuh context to answer:\n{context}\n"
        )
    ])

    combine_docs_chain = create_stuff_documents_chain(llm, prompt)
    qa_chain = create_retrieval_chain(retriever, combine_docs_chain)

    print("✅ Retrieval chain initialized successfully.", flush=True)

# =========================
# Conversational intent / filter extraction
# =========================

def extract_hours_from_text(text: str, default_hours=None):
    low = text.lower()

    patterns = [
        r"last\s+(\d+)\s+hours?",
        r"past\s+(\d+)\s+hours?",
        r"in\s+the\s+last\s+(\d+)\s+hours?",
        r"last\s+(\d+)\s+days?",
        r"past\s+(\d+)\s+days?",
    ]

    for pattern in patterns:
        m = re.search(pattern, low)
        if m:
            value = int(m.group(1))
            if "day" in pattern:
                return value * 24
            return value

    if "today" in low or "last day" in low or "past day" in low:
        return 24

    return default_hours


def extract_agent_from_text(text: str):
    low = text.lower().strip()

    patterns = [
        r"show only ([a-zA-Z0-9._-]+)",
        r"only host ([a-zA-Z0-9._-]+)",
        r"only agent ([a-zA-Z0-9._-]+)",
        r"for host ([a-zA-Z0-9._-]+)",
        r"for agent ([a-zA-Z0-9._-]+)",
        r"on host ([a-zA-Z0-9._-]+)",
        r"on agent ([a-zA-Z0-9._-]+)",
    ]

    for pattern in patterns:
        m = re.search(pattern, low)
        if m:
            return m.group(1)

    return None


def extract_compare_hosts(text: str):
    low = text.lower()

    patterns = [
        r"compare\s+([a-zA-Z0-9._-]+)\s+and\s+([a-zA-Z0-9._-]+)",
        r"compare host\s+([a-zA-Z0-9._-]+)\s+and\s+([a-zA-Z0-9._-]+)",
    ]

    for pattern in patterns:
        m = re.search(pattern, low)
        if m:
            return m.group(1), m.group(2)

    return None


def extract_session_updates_from_text(text: str):
    updates = {}

    hours = extract_hours_from_text(text, default_hours=None)
    if hours is not None:
        updates["hours"] = hours

    agent = extract_agent_from_text(text)
    if agent:
        updates["agent"] = agent

    low = text.lower()
    if "archives" in low:
        updates["source"] = "archives"
    elif "alerts" in low:
        updates["source"] = "alerts"

    return updates


def detect_intent(text: str) -> str:
    low = text.lower()

    if extract_compare_hosts(text):
        return "compare_hosts"

    if "top attacking ip" in low or "top source ip" in low or "top source ips" in low:
        return "top_ips"

    if "what should i do next" in low or "next step" in low or "recommended action" in low:
        return "recommendation"

    auth_keywords = [
        "login",
        "log in",
        "authentication",
        "auth",
        "brute force",
        "bruteforce",
        "failed password",
        "unauthorized",
        "authorized",
        "username",
        "usernames",
        "source ip",
        "source ips",
        "under attack",
        "suspicious login",
        "suspicious authentication",
        "failed login",
        "successful login",
    ]

    if any(k in low for k in auth_keywords):
        return "soc_auth"

    return "rag"

# =========================
# AI-based auth analysis
# =========================

def analyze_auth_activity_with_ai(alerts):
    per_host_summary = build_per_host_summary(alerts)

    prompt = f"""
You are a senior SOC analyst assistant.

Your job is to analyze Wazuh authentication activity and produce structured security findings.
Be precise, concise, and practical.
Focus on analyst usefulness rather than generic wording.

Return ONLY valid JSON.
Do not add markdown.
Do not add explanation before or after the JSON.
Do not use code fences.

The JSON format MUST be exactly:

{{
  "hosts": [
    {{
      "affected_host": "host-name",
      "possible_attacks": [
        "attack 1",
        "attack 2"
      ],
      "source_ips": [
        {{"ip": "1.2.3.4", "attempts": 10}},
        {{"ip": "5.6.7.8", "attempts": 4}}
      ],
      "authorized_login_names": [
        {{"username": "user1", "attempts": 2}}
      ],
      "unauthorized_login_names": [
        {{"username": "root", "attempts": 14}}
      ],
      "severity": "HIGH",
      "recommended_mitigation": [
        "mitigation 1",
        "mitigation 2"
      ]
    }}
  ]
}}

Rules:
- Return one object per affected host.
- Do not merge hosts together.
- severity must be one of: HIGH, MEDIUM, LOW, INFORMATIONAL
- If no authorized usernames are found, return an empty list.
- If no unauthorized usernames are found, return an empty list.
- If no major attack pattern exists, possible_attacks should still contain one short statement.
- recommended_mitigation must always be present and must always be a list.
- source_ips must always be a list of objects with ip and attempts.

Per-host summary:
{json.dumps(per_host_summary, indent=2)}
"""

    llm = ChatOllama(model=OLLAMA_MODEL)
    result = llm.invoke(prompt)
    raw = result.content.strip() if hasattr(result, "content") else str(result).strip()
    return normalize_ai_report(parse_ai_json(raw))

# =========================
# Report builders
# =========================

def build_analyst_response(report: dict, session: dict) -> str:
    if not report.get("hosts"):
        if report.get("error"):
            return (
                "SOC Summary\n\n"
                "Executive Summary:\n"
                f"No report could be generated because of an error: {report['error']}\n\n"
                "Recommended Action:\n"
                "• Check Wazuh Indexer connectivity\n"
                "• Check Ollama availability\n"
                "• Retry the query"
            )

        return (
            "SOC Summary\n\n"
            "Executive Summary:\n"
            "No suspicious authentication activity was found in the selected scope.\n\n"
            "Current Scope:\n"
            f"• Agent: {session['agent']}\n"
            f"• Hours: {session['hours']}\n"
            f"• Source: {session['source']}\n"
        )

    lines = []
    lines.append("SOC Summary")
    lines.append("")
    lines.append("Executive Summary:")

    high_count = sum(1 for h in report["hosts"] if h.get("severity") == "HIGH")
    med_count = sum(1 for h in report["hosts"] if h.get("severity") == "MEDIUM")
    host_names = [h.get("affected_host", "unknown-host") for h in report["hosts"]]

    lines.append(
        f"Detected suspicious authentication activity across {len(report['hosts'])} host(s): "
        + ", ".join(host_names)
    )
    lines.append(f"Severity distribution: HIGH={high_count}, MEDIUM={med_count}")
    lines.append("")

    for idx, host in enumerate(report["hosts"], start=1):
        lines.append(f"[Host {idx}] {host['affected_host']}")
        lines.append(f"Severity: {host['severity']}")
        lines.append("")

        lines.append("Evidence:")
        if host.get("possible_attacks"):
            for item in host["possible_attacks"]:
                lines.append(f"• {item}")

        if host.get("source_ips"):
            for ip_item in host["source_ips"][:3]:
                lines.append(f"• Source IP {ip_item['ip']} observed {ip_item['attempts']} time(s)")

        if host.get("unauthorized_login_names"):
            for user_item in host["unauthorized_login_names"][:3]:
                lines.append(f"• Failed username {user_item['username']} seen {user_item['attempts']} time(s)")

        if host.get("authorized_login_names"):
            for user_item in host["authorized_login_names"][:2]:
                lines.append(f"• Successful username {user_item['username']} seen {user_item['attempts']} time(s)")

        lines.append("")
        lines.append("Recommended Action:")
        if host.get("recommended_mitigation"):
            for item in host["recommended_mitigation"]:
                lines.append(f"• {item}")
        else:
            lines.append("• Continue monitoring this host")
        lines.append("")

    lines.append("Analyst Note:")
    lines.append(
        f"This assessment used agent={session['agent']}, hours={session['hours']}, source={session['source']}."
    )

    return "\n".join(lines)


def top_ips_report(alerts, limit=5):
    ip_counts = {}

    for item in build_per_host_summary(alerts):
        for ip, attempts in item.get("top_source_ips", {}).items():
            ip_counts[ip] = ip_counts.get(ip, 0) + attempts

    ranked = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    if not ranked:
        return "No source IP activity was found in the selected scope."

    lines = []
    lines.append("Top Attacking Source IPs")
    lines.append("")

    for idx, (ip, count) in enumerate(ranked, start=1):
        lines.append(f"{idx}. {ip} — {count} event(s)")

    return "\n".join(lines)


def compare_hosts_report(alerts, host_a: str, host_b: str) -> str:
    summary = build_per_host_summary(alerts)

    selected = [
        h for h in summary
        if h["affected_host"].lower() in {host_a.lower(), host_b.lower()}
    ]

    if not selected:
        return f"No matching data found for hosts '{host_a}' and '{host_b}'."

    lines = []
    lines.append(f"Host Comparison: {host_a} vs {host_b}")
    lines.append("")

    for host in selected:
        lines.append(f"Host: {host['affected_host']}")
        lines.append(f"• Severity: {host.get('severity', 'INFORMATIONAL')}")
        lines.append(f"• Authorized attempts: {host.get('authorized_attempts', 0)}")
        lines.append(f"• Unauthorized attempts: {host.get('unauthorized_attempts', 0)}")
        lines.append(f"• Unknown user attempts: {host.get('unknown_user_attempts', 0)}")

        top_ips = host.get("top_source_ips", {})
        if top_ips:
            ip_text = ", ".join([f"{ip} ({cnt})" for ip, cnt in list(top_ips.items())[:3]])
            lines.append(f"• Top source IPs: {ip_text}")
        else:
            lines.append("• Top source IPs: None")

        top_users = host.get("unauthorized_login_names", {})
        if top_users:
            user_text = ", ".join([f"{u} ({cnt})" for u, cnt in list(top_users.items())[:3]])
            lines.append(f"• Failed usernames: {user_text}")
        else:
            lines.append("• Failed usernames: None")

        lines.append("")

    return "\n".join(lines)


def recommended_next_steps(report: dict) -> str:
    if not report.get("hosts"):
        return (
            "Recommended Next Steps\n\n"
            "• Continue monitoring\n"
            "• Expand the time range if you suspect earlier activity\n"
            "• Check other hosts if this one looks clean"
        )

    actions = []
    for host in report["hosts"]:
        for item in host.get("recommended_mitigation", []):
            if item not in actions:
                actions.append(item)

    lines = []
    lines.append("Recommended Next Steps")
    lines.append("")

    for item in actions[:8]:
        lines.append(f"• {item}")

    return "\n".join(lines)

# =========================
# FastAPI lifespan
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting FastAPI app and loading vector store...", flush=True)

    set_config(
        wazuh_api=WAZUH_API,
        indexer_api=INDEXER_API,
        wazuh_user=WAZUH_USER,
        wazuh_pass=WAZUH_PASS,
        indexer_user=INDEXER_USER,
        indexer_pass=INDEXER_PASS,
        verify_tls=VERIFY_TLS,
    )

    setup_chain(
        past_days=days_range,
        selected_source=log_source,
        selected_agent=agent_filter,
    )
    yield
    print("🛑 Shutting down FastAPI app...", flush=True)


app = FastAPI(lifespan=lifespan)

# =========================
# WebSocket Chat
# =========================

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    global qa_chain, context
    await websocket.accept()

    session = session_defaults()
    chat_history = []

    try:
        if not context or qa_chain is None:
            await websocket.send_json({"role": "bot", "message": "⚠️ Assistant not ready yet. Please wait."})
            await websocket.close()
            return

        await websocket.send_json({
            "role": "bot",
            "message": (
                "👋 Hello! I’m your Wazuh SOC assistant.\n"
                f"(Default: source={session['source']}, agent={session['agent']}, hours={session['hours']}, days={session['days']})\n"
                "You can ask naturally, for example:\n"
                "• Is any server under attack right now?\n"
                "• Show only payment host for the last 6 hours\n"
                "• Show top attacking IPs\n"
                "• Compare payment and wazuh-server\n"
                "Type /help for commands."
            )
        })

        while True:
            data = await websocket.receive_text()
            data = (data or "").strip()
            if not data:
                continue

            low = data.lower()

            # =========================
            # Commands
            # =========================

            if low == "/help":
                help_msg = (
                    "📋 Help Menu:\n"
                    "/reload - Reload the vector store using current session source/agent/days.\n"
                    "/set days <number> - Set number of past days to load for RAG (1-365).\n"
                    "/set agent <name|all> - Set active agent filter.\n"
                    "/set source alerts|archives - Set active RAG source.\n"
                    "/stat - Show quick stats for the current session filters.\n"
                    "/soc auth <hours> - Run direct SOC authentication analysis.\n"
                    "/session - Show current session values.\n"
                    "/reset - Reset session values to defaults.\n"
                    "/refresh - Re-run SOC analysis with current session scope.\n"
                    "/watch on - Enable watch mode flag.\n"
                    "/watch off - Disable watch mode flag.\n"
                    "\nNatural examples:\n"
                    "• Is any server under attack right now?\n"
                    "• Show only payment host for the last 6 hours\n"
                    "• Show top source IPs\n"
                    "• Compare payment and wazuh-server\n"
                    "• What should I do next?"
                )
                await websocket.send_json({"role": "bot", "message": help_msg})
                continue

            if low == "/session":
                await websocket.send_json({
                    "role": "bot",
                    "message": (
                        "Current Session\n\n"
                        f"• agent: {session['agent']}\n"
                        f"• hours: {session['hours']}\n"
                        f"• source: {session['source']}\n"
                        f"• days: {session['days']}\n"
                        f"• watch_enabled: {session['watch_enabled']}\n"
                        f"• watch_interval: {session['watch_interval']}"
                    )
                })
                continue

            if low == "/reset":
                session = session_defaults()
                await websocket.send_json({
                    "role": "bot",
                    "message": "✅ Session filters reset to defaults."
                })
                continue

            if low == "/watch on":
                session["watch_enabled"] = True
                await websocket.send_json({
                    "role": "bot",
                    "message": (
                        f"✅ Watch mode enabled. Current scope:\n"
                        f"• agent={session['agent']}\n"
                        f"• hours={session['hours']}\n"
                        f"• source={session['source']}\n"
                        f"• interval={session['watch_interval']} seconds\n\n"
                        "Note: this version stores the watch preference in session."
                    )
                })
                continue

            if low == "/watch off":
                session["watch_enabled"] = False
                await websocket.send_json({
                    "role": "bot",
                    "message": "✅ Watch mode disabled."
                })
                continue

            if low == "/refresh":
                try:
                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔄 Refreshing SOC view | agent={session['agent']} | "
                            f"hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent=session["agent"]
                    )

                    report_json = analyze_auth_activity_with_ai(alerts)
                    answer = build_analyst_response(report_json, session)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({"role": "bot", "message": f"❌ Refresh failed: {str(e)}"})
                continue

            if low == "/reload":
                await websocket.send_json({
                    "role": "bot",
                    "message": (
                        f"🔄 Reloading vector store | source={session['source']} | "
                        f"agent={session['agent']} | days={session['days']} ..."
                    )
                })

                setup_chain(
                    past_days=session["days"],
                    selected_source=session["source"],
                    selected_agent=session["agent"],
                )

                if qa_chain:
                    chat_history = []
                    await websocket.send_json({"role": "bot", "message": "✅ Reload complete."})
                else:
                    await websocket.send_json({
                        "role": "bot",
                        "message": "❌ Reload failed: no logs found or error initializing chain."
                    })
                continue

            if low.startswith("/set days"):
                try:
                    parts = data.split()
                    new_days = int(parts[-1])
                    if new_days < 1 or new_days > 365:
                        await websocket.send_json({
                            "role": "bot",
                            "message": "⚠️ Please specify a number between 1 and 365."
                        })
                        continue
                    session["days"] = new_days
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"✅ days set to {session['days']} (effective on next /reload)."
                    })
                except Exception:
                    await websocket.send_json({
                        "role": "bot",
                        "message": "⚠️ Invalid format. Use: /set days <number>."
                    })
                continue

            if low.startswith("/set agent"):
                try:
                    parts = data.split(maxsplit=2)
                    new_agent = parts[-1].strip()
                    if not new_agent:
                        await websocket.send_json({
                            "role": "bot",
                            "message": "⚠️ Usage: /set agent <name|all>"
                        })
                        continue
                    session["agent"] = new_agent
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"✅ agent filter set to '{session['agent']}'."
                    })
                except Exception:
                    await websocket.send_json({
                        "role": "bot",
                        "message": "⚠️ Usage: /set agent <name|all>"
                    })
                continue

            if low.startswith("/set source"):
                try:
                    parts = data.split(maxsplit=2)
                    new_source = parts[-1].strip().lower()
                    if new_source not in ("alerts", "archives"):
                        await websocket.send_json({
                            "role": "bot",
                            "message": "⚠️ Usage: /set source alerts|archives"
                        })
                        continue
                    session["source"] = new_source
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"✅ log source set to '{session['source']}'."
                    })
                except Exception:
                    await websocket.send_json({
                        "role": "bot",
                        "message": "⚠️ Usage: /set source alerts|archives"
                    })
                continue

            if low == "/stat":
                logs = load_logs_from_days(
                    past_days=session["days"],
                    selected_source=session["source"],
                    selected_agent=session["agent"],
                )
                await websocket.send_json({"role": "bot", "message": get_stats(logs)})
                continue

            if low.startswith("/soc auth"):
                try:
                    parts = data.split()
                    hours = session["hours"]
                    if len(parts) >= 3:
                        hours = int(parts[2])
                        session["hours"] = hours

                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔎 Running SOC authentication analysis | "
                            f"agent={session['agent']} | hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent=session["agent"]
                    )

                    if not alerts:
                        await websocket.send_json({
                            "role": "bot",
                            "message": "No matching alerts found for the requested SOC analysis."
                        })
                        continue

                    report_json = analyze_auth_activity_with_ai(alerts)
                    answer = build_analyst_response(report_json, session)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"❌ SOC auth analysis failed: {str(e)}"
                    })
                continue

            # =========================
            # Natural language routing
            # =========================

            updates = extract_session_updates_from_text(data)
            apply_session_updates(session, updates)

            intent = detect_intent(data)
            session["last_question"] = data
            session["last_mode"] = intent

            if intent == "soc_auth":
                try:
                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔎 Analyzing authentication activity | "
                            f"agent={session['agent']} | hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent=session["agent"]
                    )

                    report_json = analyze_auth_activity_with_ai(alerts)
                    answer = build_analyst_response(report_json, session)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"❌ SOC analysis failed: {str(e)}"
                    })
                continue

            if intent == "top_ips":
                try:
                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔎 Ranking top source IPs | agent={session['agent']} | "
                            f"hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent=session["agent"]
                    )

                    answer = top_ips_report(alerts)
                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"❌ Top IP analysis failed: {str(e)}"
                    })
                continue

            if intent == "compare_hosts":
                try:
                    hosts = extract_compare_hosts(data)
                    if not hosts:
                        await websocket.send_json({
                            "role": "bot",
                            "message": "⚠️ Please specify two hosts to compare."
                        })
                        continue

                    host_a, host_b = hosts

                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔎 Comparing hosts {host_a} and {host_b} | "
                            f"hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent="all"
                    )

                    answer = compare_hosts_report(alerts, host_a, host_b)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"❌ Host comparison failed: {str(e)}"
                    })
                continue

            if intent == "recommendation":
                try:
                    await websocket.send_json({
                        "role": "bot",
                        "message": (
                            f"🔎 Generating recommended actions | "
                            f"agent={session['agent']} | hours={session['hours']} ..."
                        )
                    })

                    alerts = get_latest_alerts(
                        hours=session["hours"],
                        size=100,
                        target_agent=session["agent"]
                    )

                    report_json = analyze_auth_activity_with_ai(alerts)
                    answer = recommended_next_steps(report_json)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({
                        "role": "bot",
                        "message": f"❌ Recommendation generation failed: {str(e)}"
                    })
                continue

            # =========================
            # RAG fallback
            # =========================

            chat_history.append(("user", data))
            print(f"🧠 Received question: {data}", flush=True)

            history_text = format_history(chat_history)
            result = qa_chain.invoke({"input": data, "chat_history": history_text})
            answer = (result.get("answer", "") or "").replace("\\n", "\n").strip()

            if not answer:
                answer = "⚠️ Sorry, I couldn't generate a response."

            chat_history.append(("bot", answer))
            await websocket.send_json({"role": "bot", "message": answer})

    except WebSocketDisconnect:
        print("⚠️ Client disconnected.", flush=True)
    except Exception as e:
        print(f"❌ Error in websocket: {e}", flush=True)
        try:
            await websocket.send_json({"role": "bot", "message": f"❌ Error: {str(e)}"})
            await websocket.close()
        except Exception:
            pass

# =========================
# HTML UI
# =========================

HTML_PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Wazuh SOC Assistant</title>
<style>
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        background-color: #1e1e1e;
        color: white;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
    }
    .chat-container {
        display: flex;
        flex-direction: column;
        height: 92vh;
        width: 860px;
        max-width: 96vw;
        border: 1px solid #3595F9;
        border-radius: 10px;
        background-color: #252931;
        box-shadow: 0 0 14px #3595F9aa;
    }
    .header {
        padding: 14px 18px;
        border-bottom: 1px solid #3595F9;
        background-color: #20242b;
        font-weight: bold;
        color: #d7e9ff;
    }
    .messages {
        flex-grow: 1;
        overflow-y: auto;
        padding: 15px;
        display: flex;
        flex-direction: column;
    }
    .message {
        max-width: 84%;
        margin: 6px 0;
        padding: 12px 16px;
        border-radius: 15px;
        word-wrap: break-word;
        white-space: pre-wrap;
        line-height: 1.45;
    }
    .message.user {
        background-color: #3595F9;
        align-self: flex-start;
        color: white;
        border-bottom-left-radius: 0;
    }
    .message.bot {
        background-color: #2c2f38;
        align-self: flex-end;
        color: #ddd;
        border-bottom-right-radius: 0;
    }
    .input-container {
        display: flex;
        padding: 10px 15px;
        background-color: #1e1e1e;
        border-top: 1px solid #3595F9;
        border-bottom-left-radius: 10px;
        border-bottom-right-radius: 10px;
    }
    input[type="text"] {
        flex-grow: 1;
        padding: 12px 15px;
        border: none;
        border-radius: 25px;
        background-color: #2c2f38;
        color: white;
        font-size: 16px;
        outline: none;
    }
    button {
        margin-left: 10px;
        padding: 12px 20px;
        background-color: #3595F9;
        border: none;
        border-radius: 25px;
        color: white;
        font-weight: bold;
        font-size: 16px;
        cursor: pointer;
        transition: background-color 0.2s ease-in-out;
    }
    button:hover {
        background-color: #1c6dd0;
    }
</style>
</head>
<body>
<div class="chat-container">
    <div class="header">Wazuh SOC Assistant</div>
    <div class="messages" id="messages"></div>
    <div class="input-container">
        <input type="text" id="user-input" placeholder="Ask naturally, e.g. 'Show only payment host for the last 6 hours'" autocomplete="off" />
        <button onclick="sendMessage()">Send</button>
    </div>
</div>

<script>
    const messagesDiv = document.getElementById('messages');
    const userInput = document.getElementById('user-input');
    const socket = new WebSocket(`ws://${window.location.host}/ws/chat`);

    socket.onopen = () => {
        console.log("✅ WebSocket connected");
    };

    socket.onmessage = function(event) {
        const data = JSON.parse(event.data);
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', data.role);
        messageDiv.textContent = data.message;
        messagesDiv.appendChild(messageDiv);
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
    };

    socket.onclose = () => {
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', 'bot');
        messageDiv.textContent = '⚠️ Connection closed.';
        messagesDiv.appendChild(messageDiv);
    };

    socket.onerror = (error) => {
        console.error("WebSocket error:", error);
        const messageDiv = document.createElement('div');
        messageDiv.classList.add('message', 'bot');
        messageDiv.textContent = '⚠️ WebSocket error.';
        messagesDiv.appendChild(messageDiv);
    };

    function sendMessage() {
        const message = userInput.value.trim();
        if (message && socket.readyState === WebSocket.OPEN) {
            const messageDiv = document.createElement('div');
            messageDiv.classList.add('message', 'user');
            messageDiv.textContent = message;
            messagesDiv.appendChild(messageDiv);
            messagesDiv.scrollTop = messagesDiv.scrollHeight;

            socket.send(message);
            userInput.value = '';
            userInput.focus();
        }
    }

    userInput.addEventListener("keyup", function(event) {
        if (event.key === "Enter") {
            sendMessage();
        }
    });
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def get(_: str = Depends(authenticate)):
    return HTML_PAGE

# =========================
# Main
# =========================

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", type=str, help="Optional remote host IP address to load logs from")
    parser.add_argument("-d", "--days", type=int, default=2, help="How many past days of logs to load at startup (default: 2)")
    parser.add_argument("-s", "--source", type=str, default="alerts", help="Log source: alerts or archives (default: alerts)")
    parser.add_argument("-a", "--agent", type=str, default="all", help="Agent filter: name or 'all' (default: all)")
    args = parser.parse_args()

    if args.host:
        remote_host = args.host

    days_range = args.days

    log_source = (args.source or "alerts").strip().lower()
    if log_source not in ("alerts", "archives"):
        log_source = "alerts"

    agent_filter = (args.agent or "all").strip()

    uvicorn.run(app, host="0.0.0.0", port=8000)
