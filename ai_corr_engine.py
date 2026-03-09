import requests
import json
import time
import ollama
import urllib3
from collections import defaultdict

# Disable HTTPS warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_API = "https://localhost:55000"
INDEXER_API = "https://localhost:9200"

# Wazuh Manager API credentials
WAZUH_USER = "wazuh"
WAZUH_PASS = "YOUR_WAZUH_API_PASSWORD"

# Wazuh Indexer credentials
INDEXER_USER = "admin"
INDEXER_PASS = "YOUR_INDEXER_PASSWORD"

VERIFY_TLS = False
OLLAMA_MODEL = "llama3"


# -----------------------------
# Wazuh Manager API
# -----------------------------
def get_wazuh_token():
    url = f"{WAZUH_API}/security/user/authenticate?raw=true"

    r = requests.post(
        url,
        auth=(WAZUH_USER, WAZUH_PASS),
        verify=VERIFY_TLS,
        timeout=20
    )
    r.raise_for_status()
    return r.text.strip()


def get_agents():
    token = get_wazuh_token()
    headers = {"Authorization": f"Bearer {token}"}

    r = requests.get(
        f"{WAZUH_API}/agents",
        headers=headers,
        verify=VERIFY_TLS,
        timeout=20
    )
    r.raise_for_status()

    data = r.json()
    return data["data"]["affected_items"]


# -----------------------------
# Wazuh Indexer API
# -----------------------------
def get_latest_alerts(hours=1, size=100):
    query = {
        "size": size,
        "sort": [
            {
                "timestamp": {
                    "order": "desc"
                }
            }
        ],
        "query": {
            "range": {
                "timestamp": {
                    "gte": f"now-{hours}h"
                }
            }
        }
    }

    try:
        r = requests.post(
            f"{INDEXER_API}/wazuh-alerts*/_search",
            auth=(INDEXER_USER, INDEXER_PASS),
            json=query,
            verify=VERIFY_TLS,
            timeout=30
        )

        print("Indexer status:", r.status_code)

        if not r.text.strip():
            print("Indexer returned empty response")
            return []

        if r.status_code != 200:
            print("Indexer error response:")
            print(r.text[:1000])
            return []

        data = r.json()

        if "hits" not in data or "hits" not in data["hits"]:
            print("Unexpected JSON structure:")
            print(json.dumps(data, indent=2)[:1000])
            return []

        return [h["_source"] for h in data["hits"]["hits"]]

    except Exception as e:
        print("Error querying Indexer:", str(e))
        return []


# -----------------------------
# Authentication helpers
# -----------------------------
def get_username_from_alert(alert):
    data = alert.get("data", {}) or {}

    # Common Linux / generic Wazuh fields
    for key in ["dstuser", "srcuser", "user", "username"]:
        value = data.get(key)
        if value:
            return str(value)

    # Common Windows nested fields
    win = data.get("win", {}) if isinstance(data, dict) else {}
    eventdata = win.get("eventdata", {}) if isinstance(win, dict) else {}
    for key in ["TargetUserName", "SubjectUserName"]:
        value = eventdata.get(key)
        if value:
            return str(value)

    # Fallback parsing from full_log
    full_log = alert.get("full_log", "") or ""
    markers = [
        "Invalid user ",
        "Failed password for ",
        "Accepted password for ",
        "Accepted publickey for ",
        "user="
    ]

    for marker in markers:
        if marker in full_log:
            try:
                tail = full_log.split(marker, 1)[1]
                return tail.split()[0].strip()
            except Exception:
                pass

    return "unknown-user"


def get_srcip_from_alert(alert):
    data = alert.get("data", {}) or {}

    for key in ["srcip", "src_ip", "ip"]:
        value = data.get(key)
        if value:
            return str(value)

    full_log = alert.get("full_log", "") or ""
    parts = full_log.replace(",", " ").split()
    for token in parts:
        chunks = token.split(".")
        if len(chunks) == 4 and all(c.isdigit() for c in chunks if c):
            return token

    return "unknown-ip"


def classify_auth_event(alert):
    rule = alert.get("rule", {}) or {}
    desc = (rule.get("description", "") or "").lower()
    full_log = (alert.get("full_log", "") or "").lower()

    success_keywords = [
        "accepted password",
        "accepted publickey",
        "authentication success",
        "successful login",
        "login succeeded",
        "ssh login success",
        "login success"
    ]

    failure_keywords = [
        "failed password",
        "authentication failed",
        "failed login",
        "invalid user",
        "non-existent user",
        "unknown user",
        "login failed",
        "sshd: authentication failed"
    ]

    if any(k in desc for k in success_keywords) or any(k in full_log for k in success_keywords):
        return "authorized"

    if any(k in desc for k in failure_keywords) or any(k in full_log for k in failure_keywords):
        return "unauthorized"

    return "unknown"


def is_unknown_user_attempt(alert):
    rule = alert.get("rule", {}) or {}
    desc = (rule.get("description", "") or "").lower()
    full_log = (alert.get("full_log", "") or "").lower()

    markers = [
        "invalid user",
        "non-existent user",
        "unknown user"
    ]

    return any(m in desc for m in markers) or any(m in full_log for m in markers)


# -----------------------------
# Per-host summarization
# -----------------------------
def summarize_per_host(alerts):
    host_summary = {}

    for alert in alerts:
        host = alert.get("agent", {}).get("name", "unknown-host")

        if host not in host_summary:
            host_summary[host] = {
                "affected_host": host,
                "source_ips": defaultdict(int),
                "authorized_users": defaultdict(int),
                "unauthorized_users": defaultdict(int),
                "unknown_users": defaultdict(int),
                "authorized_attempts": 0,
                "unauthorized_attempts": 0,
                "unknown_attempts": 0,
                "unknown_user_attempts": 0,
                "rule_counts": defaultdict(int),
                "alerts": []
            }

        srcip = get_srcip_from_alert(alert)
        username = get_username_from_alert(alert)
        auth_type = classify_auth_event(alert)

        rule = alert.get("rule", {}) or {}
        rule_id = str(rule.get("id", "unknown"))
        rule_desc = rule.get("description", "unknown")

        host_summary[host]["source_ips"][srcip] += 1
        host_summary[host]["rule_counts"][f"{rule_id}:{rule_desc}"] += 1
        host_summary[host]["alerts"].append(alert)

        if auth_type == "authorized":
            host_summary[host]["authorized_users"][username] += 1
            host_summary[host]["authorized_attempts"] += 1
        elif auth_type == "unauthorized":
            host_summary[host]["unauthorized_users"][username] += 1
            host_summary[host]["unauthorized_attempts"] += 1
            if is_unknown_user_attempt(alert):
                host_summary[host]["unknown_user_attempts"] += 1
        else:
            host_summary[host]["unknown_users"][username] += 1
            host_summary[host]["unknown_attempts"] += 1

    return host_summary


def infer_possible_attacks_for_host(host_data):
    attacks = []

    unauthorized_users = host_data["unauthorized_users"]
    unknown_user_attempts = host_data["unknown_user_attempts"]

    if unauthorized_users:
        top_user, top_count = max(unauthorized_users.items(), key=lambda x: x[1])

        if top_count >= 5:
            attacks.append(f'Brute-force attacks ({top_count} attempts by "{top_user}")')

    if unknown_user_attempts > 0:
        attacks.append(f"Unknown users attempting to log in ({unknown_user_attempts} attempts)")

    if not attacks and host_data["unauthorized_attempts"] > 0:
        attacks.append(f"Repeated unauthorized authentication activity ({host_data['unauthorized_attempts']} attempts)")

    if not attacks:
        attacks.append("No major attack pattern clearly identified from current alert sample")

    return attacks


def build_per_host_summary(alerts):
    host_summary = summarize_per_host(alerts)

    final = []

    for host, data in host_summary.items():
        top_source_ips = dict(
            sorted(
                data["source_ips"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
        )

        final.append({
            "affected_host": host,
            "possible_attacks": infer_possible_attacks_for_host(data),
            "top_source_ips": top_source_ips,
            "authorized_login_names": dict(
                sorted(
                    data["authorized_users"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            ),
            "unauthorized_login_names": dict(
                sorted(
                    data["unauthorized_users"].items(),
                    key=lambda x: x[1],
                    reverse=True
                )
            ),
            "authorized_attempts": data["authorized_attempts"],
            "unauthorized_attempts": data["unauthorized_attempts"],
            "unknown_user_attempts": data["unknown_user_attempts"]
        })

    return final


# -----------------------------
# Simple suspicious trigger
# -----------------------------
def detect_suspicious_hosts(alerts):
    host_summary = summarize_per_host(alerts)
    suspicious_hosts = []

    for host, data in host_summary.items():
        if data["unauthorized_attempts"] > 0 or data["unknown_user_attempts"] > 0:
            suspicious_hosts.append(host)

    return suspicious_hosts


# -----------------------------
# Send per-host summary to Ollama
# -----------------------------
def analyze_with_ai(alerts):
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

    try:
        start = time.time()
        print("Sending alerts to Ollama for analysis...")

        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )

        end = time.time()
        print(f"Ollama response received in {end - start:.2f} seconds")

        raw_content = response["message"]["content"].strip()
        print("Raw AI JSON response received")

        return raw_content

    except Exception as e:
        print("Error during Ollama analysis:", str(e))
        return json.dumps({
            "hosts": [],
            "error": str(e)
        }, indent=2)

def parse_ai_json(raw_text):
    try:
        return json.loads(raw_text)
    except Exception:
        pass

    # Try to extract the JSON object from the text
    start = raw_text.find("{")
    end = raw_text.rfind("}")

    if start != -1 and end != -1 and end > start:
        possible_json = raw_text[start:end + 1]
        try:
            return json.loads(possible_json)
        except Exception:
            pass

    return {
        "hosts": [],
        "error": "Invalid JSON returned by Ollama",
        "raw_output": raw_text
    }


# -----------------------------
# Main monitoring loop
# -----------------------------
def run_soc():
    print("AI SOC Engine Started")

    while True:
        print("Checking alerts from Wazuh Indexer...")

        alerts = get_latest_alerts(hours=1, size=100)
        print("Alerts received:", len(alerts))

        suspicious_hosts = detect_suspicious_hosts(alerts)

        if suspicious_hosts:
            print("Suspicious activity detected on hosts:", ", ".join(suspicious_hosts))

            per_host_summary = build_per_host_summary(alerts)
            print("Per-host summary preview:")
            print(json.dumps(per_host_summary, indent=2)[:2000])

            raw_report = analyze_with_ai(alerts)
            parsed_report = normalize_ai_report(parse_ai_json(raw_report))

            print("=== AI REPORT JSON START ===")
            print(json.dumps(parsed_report, indent=2))
            print("=== AI REPORT JSON END ===")

        else:
            print("No suspicious activity")

        print("Sleeping for 60 seconds...\n")
        time.sleep(60)

def normalize_ai_report(report):
    if not isinstance(report, dict):
        return {"hosts": [], "error": "Report is not a dictionary"}

    hosts = report.get("hosts", [])
    if not isinstance(hosts, list):
        return {"hosts": [], "error": "hosts is not a list"}

    normalized_hosts = []

    for host in hosts:
        if not isinstance(host, dict):
            continue

        normalized_hosts.append({
            "affected_host": host.get("affected_host", "unknown-host"),
            "possible_attacks": host.get("possible_attacks", []),
            "source_ips": host.get("source_ips", []),
            "authorized_login_names": host.get("authorized_login_names", []),
            "unauthorized_login_names": host.get("unauthorized_login_names", []),
            "severity": host.get("severity", "INFORMATIONAL"),
            "recommended_mitigation": host.get("recommended_mitigation", [])
        })

    return {"hosts": normalized_hosts}

# -----------------------------
# Start SOC engine
# -----------------------------
if __name__ == "__main__":
    run_soc()