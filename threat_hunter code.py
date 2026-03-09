# threat_hunter.py
#
# Conversational Wazuh Threat Hunting Chat UI
# - FastAPI + WebSocket
# - RAG over local logs (alerts / archives)
# - Direct conversational SOC auth analysis from Wazuh Indexer API
#
# Example:
#   sudo python3 /var/ossec/integrations/threat_hunter.py --days 2
#
# Example conversational prompts:
#   Is any server under attack right now?
#   Which hosts show suspicious login activity?
#   Show unauthorized login names for payment in the last hour
#   Summarize authentication threats in the last 6 hours

import sys
sys.path.append("/opt/ai-soc")

import json
import os
import gzip
import argparse
import secrets
import urllib3

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
    render_auth_report,
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
WAZUH_PASS = "pass"

INDEXER_USER = "admin"
INDEXER_PASS = "pass"

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

# =========================
# Local file loaders for RAG
# =========================

def load_alerts_from_days(past_days=1):
    base = "/var/ossec/logs/alerts/alerts.json"
    if not os.path.exists(base):
        print(f"⚠️ alerts.json not found at {base}")
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

            if agent_filter != "all":
                a = (evt.get("agent") or {}).get("name", "")
                if a.lower() != agent_filter.lower():
                    continue

            logs.append(evt)

    return logs


def load_logs_from_remote(host, user, password, past_days):
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
                print(f"⚠️ Remote log not found or unreadable: {json_path} / {gz_path}")
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

                        if agent_filter != "all":
                            a = (evt.get("agent") or {}).get("name", "")
                            if a and a.lower() != agent_filter.lower():
                                continue

                        logs.append(evt)
                except Exception as e:
                    print(f"⚠️ Error reading remote file: {e}")

        sftp.close()
        ssh.close()
    except Exception as e:
        print(f"❌ Remote connection failed: {e}")

    return logs


def load_archives_from_days(past_days=7):
    if remote_host:
        return load_logs_from_remote(remote_host, ssh_username, ssh_password, past_days)

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
            print(f"⚠️ Log file missing or empty: {json_path} / {gz_path}")
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

                    if agent_filter != "all":
                        a = (evt.get("agent") or {}).get("name", "")
                        if a and a.lower() != agent_filter.lower():
                            continue

                    logs.append(evt)
        except Exception as e:
            print(f"⚠️ Error reading {file_path}: {e}")

    return logs


def load_logs_from_days(past_days=7):
    if log_source == "alerts":
        return load_alerts_from_days(past_days=past_days)
    return load_archives_from_days(past_days=past_days)

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


def setup_chain(past_days=7):
    global qa_chain, context, days_range

    days_range = past_days
    print(f"🔄 Initializing retrieval chain | source={log_source} | agent={agent_filter} | past_days={past_days}")

    logs = load_logs_from_days(past_days)
    if not logs:
        print("❌ No logs found. Skipping chain setup.")
        qa_chain = None
        return

    print(f"✅ {len(logs)} events loaded.")
    print("📦 Creating vectorstore...")

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

    print("✅ Retrieval chain initialized successfully.")


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
# Direct AI-based auth analysis
# =========================

def analyze_auth_activity_with_ai(alerts):
    per_host_summary = build_per_host_summary(alerts)

    prompt = f"""
You are a SOC cybersecurity analyst.

Analyze the following Wazuh per-host authentication activity summary.

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
# Conversational intent detection
# =========================

def extract_hours_from_question(text: str, default_hours: int = 1) -> int:
    low = text.lower()

    parts = low.replace("?", " ").replace(",", " ").split()
    for i, token in enumerate(parts):
        if token.isdigit():
            value = int(token)
            if i + 1 < len(parts):
                nxt = parts[i + 1]
                if nxt.startswith("hour"):
                    return value
                if nxt.startswith("day"):
                    return value * 24

    if "last day" in low or "past day" in low or "today" in low:
        return 24

    return default_hours


def is_soc_auth_question(text: str) -> bool:
    low = text.lower()

    keywords = [
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

    return any(k in low for k in keywords)

# =========================
# FastAPI lifespan
# =========================

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 Starting FastAPI app and loading vector store...")

    set_config(
        wazuh_api=WAZUH_API,
        indexer_api=INDEXER_API,
        wazuh_user=WAZUH_USER,
        wazuh_pass=WAZUH_PASS,
        indexer_user=INDEXER_USER,
        indexer_pass=INDEXER_PASS,
        verify_tls=VERIFY_TLS,
    )

    setup_chain(past_days=days_range)
    yield
    print("🛑 Shutting down FastAPI app...")


app = FastAPI(lifespan=lifespan)

# =========================
# WebSocket Chat
# =========================

chat_history = []

@app.websocket("/ws/chat")
async def websocket_endpoint(websocket: WebSocket):
    global qa_chain, context, chat_history, days_range, agent_filter, log_source
    await websocket.accept()

    try:
        if not context or qa_chain is None:
            await websocket.send_json({"role": "bot", "message": "⚠️ Assistant not ready yet. Please wait."})
            await websocket.close()
            return

        chat_history = []
        await websocket.send_json({
            "role": "bot",
            "message": (
                "👋 Hello! Ask me anything about Wazuh logs.\n"
                f"(Default: source={log_source}, agent={agent_filter}, days={days_range})\n"
                "You can ask naturally, for example:\n"
                "• Is any server under attack right now?\n"
                "• Which hosts show suspicious login activity?\n"
                "• Show unauthorized login names for payment in the last hour\n"
                "Type /help for commands."
            )
        })

        while True:
            data = await websocket.receive_text()
            data = (data or "").strip()
            if not data:
                continue

            low = data.lower()

            if low == "/help":
                help_msg = (
                    "📋 Help Menu:\n"
                    "/reload - Reload the vector store with current filters.\n"
                    "/set days <number> - Set number of past days to load (1-365).\n"
                    "/set agent <name|all> - Filter by agent name (e.g. payment).\n"
                    "/set source alerts|archives - Choose alerts.json (recommended) or archives.\n"
                    "/stat - Show quick stats for current filters.\n"
                    "/soc auth <hours> - Direct SOC authentication analysis from Wazuh Indexer API.\n"
                    "\nConversational examples:\n"
                    "• Is any server under attack right now?\n"
                    "• Which hosts show suspicious login activity?\n"
                    "• Show unauthorized login names for payment in the last hour\n"
                    "• Summarize authentication threats in the last 6 hours"
                )
                await websocket.send_json({"role": "bot", "message": help_msg})
                continue

            if low == "/reload":
                await websocket.send_json({
                    "role": "bot",
                    "message": f"🔄 Reloading | source={log_source} | agent={agent_filter} | days={days_range} ..."
                })
                setup_chain(past_days=days_range)
                if qa_chain:
                    await websocket.send_json({"role": "bot", "message": "✅ Reload complete."})
                    chat_history = []
                else:
                    await websocket.send_json({"role": "bot", "message": "❌ Reload failed: no logs found or error initializing chain."})
                continue

            if low.startswith("/set days"):
                try:
                    parts = data.split()
                    new_days = int(parts[-1])
                    if new_days < 1 or new_days > 365:
                        await websocket.send_json({"role": "bot", "message": "⚠️ Please specify a number between 1 and 365."})
                        continue
                    days_range = new_days
                    await websocket.send_json({"role": "bot", "message": f"✅ days set to {days_range} (effective on next /reload)."})
                except Exception:
                    await websocket.send_json({"role": "bot", "message": "⚠️ Invalid format. Use: /set days <number>."})
                continue

            if low.startswith("/set agent"):
                try:
                    parts = data.split(maxsplit=2)
                    new_agent = parts[-1].strip()
                    if not new_agent:
                        await websocket.send_json({"role": "bot", "message": "⚠️ Usage: /set agent <name|all>"})
                        continue
                    agent_filter = new_agent
                    await websocket.send_json({"role": "bot", "message": f"✅ agent filter set to '{agent_filter}'."})
                except Exception:
                    await websocket.send_json({"role": "bot", "message": "⚠️ Usage: /set agent <name|all>"})
                continue

            if low.startswith("/set source"):
                try:
                    parts = data.split(maxsplit=2)
                    new_source = parts[-1].strip().lower()
                    if new_source not in ("alerts", "archives"):
                        await websocket.send_json({"role": "bot", "message": "⚠️ Usage: /set source alerts|archives"})
                        continue
                    log_source = new_source
                    await websocket.send_json({"role": "bot", "message": f"✅ log source set to '{log_source}'."})
                except Exception:
                    await websocket.send_json({"role": "bot", "message": "⚠️ Usage: /set source alerts|archives"})
                continue

            if low == "/stat":
                logs = load_logs_from_days(days_range)
                await websocket.send_json({"role": "bot", "message": get_stats(logs)})
                continue

            if low.startswith("/soc auth"):
                try:
                    parts = data.split()
                    hours = 1
                    if len(parts) >= 3:
                        hours = int(parts[2])

                    await websocket.send_json({
                        "role": "bot",
                        "message": f"🔎 Running SOC authentication analysis | agent={agent_filter} | hours={hours} ..."
                    })

                    alerts = get_latest_alerts(hours=hours, size=100, target_agent=agent_filter)

                    if not alerts:
                        await websocket.send_json({"role": "bot", "message": "No matching alerts found for the requested SOC analysis."})
                        continue

                    report_json = analyze_auth_activity_with_ai(alerts)
                    pretty_report = render_auth_report(report_json)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", pretty_report))
                    await websocket.send_json({"role": "bot", "message": pretty_report})
                except Exception as e:
                    await websocket.send_json({"role": "bot", "message": f"❌ SOC auth analysis failed: {str(e)}"})
                continue

            if is_soc_auth_question(data):
                try:
                    hours = extract_hours_from_question(data, default_hours=1)

                    await websocket.send_json({
                        "role": "bot",
                        "message": f"🔎 Analyzing authentication activity | agent={agent_filter} | hours={hours} ..."
                    })

                    alerts = get_latest_alerts(hours=hours, size=100, target_agent=agent_filter)

                    if not alerts:
                        answer = "No matching authentication-related alerts were found for that request."
                    else:
                        report_json = analyze_auth_activity_with_ai(alerts)
                        answer = render_auth_report(report_json)

                    chat_history.append(("user", data))
                    chat_history.append(("bot", answer))
                    await websocket.send_json({"role": "bot", "message": answer})
                except Exception as e:
                    await websocket.send_json({"role": "bot", "message": f"❌ Conversational SOC analysis failed: {str(e)}"})
                continue

            chat_history.append(("user", data))
            print(f"🧠 Received question: {data}")

            history_text = format_history(chat_history)
            result = qa_chain.invoke({"input": data, "chat_history": history_text})
            answer = (result.get("answer", "") or "").replace("\\n", "\n").strip()
            if not answer:
                answer = "⚠️ Sorry, I couldn't generate a response."

            chat_history.append(("bot", answer))
            await websocket.send_json({"role": "bot", "message": answer})

    except WebSocketDisconnect:
        print("⚠️ Client disconnected.")
    except Exception as e:
        print(f"❌ Error in websocket: {e}")
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
<title>Wazuh Chat Assistant</title>
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
        height: 90vh;
        width: 760px;
        max-width: 94vw;
        border: 1px solid #3595F9;
        border-radius: 8px;
        background-color: #252931;
        box-shadow: 0 0 10px #3595F9aa;
    }
    .messages {
        flex-grow: 1;
        overflow-y: auto;
        padding: 15px;
        display: flex;
        flex-direction: column;
    }
    .message {
        max-width: 82%;
        margin: 5px 0;
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
        border-bottom-left-radius: 8px;
        border-bottom-right-radius: 8px;
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
    <div class="messages" id="messages"></div>
    <div class="input-container">
        <input type="text" id="user-input" placeholder="Ask naturally, e.g. 'Which hosts show suspicious login activity?'" autocomplete="off" />
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
