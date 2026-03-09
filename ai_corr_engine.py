import json
import time
import ollama

from soc_utils import (
    set_config,
    get_latest_alerts,
    detect_suspicious_hosts,
    build_per_host_summary,
    parse_ai_json,
    normalize_ai_report,
)

# =========================
# Local config
# =========================

WAZUH_API = "https://localhost:55000"
INDEXER_API = "https://localhost:9200"

WAZUH_USER = "wazuh"
WAZUH_PASS = "pass"

INDEXER_USER = "admin"
INDEXER_PASS = "pass"

VERIFY_TLS = False
OLLAMA_MODEL = "llama3"

POLL_HOURS = 1
POLL_SIZE = 100
POLL_INTERVAL_SECONDS = 60


# =========================
# AI analysis
# =========================

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
        print("[3/5] Sending prompt to Ollama...", flush=True)

        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )

        end = time.time()
        print(f"Ollama response received in {end - start:.2f} seconds", flush=True)

        raw_content = response["message"]["content"].strip()
        print("Raw AI JSON response received", flush=True)

        return raw_content

    except Exception as e:
        print("Error during Ollama analysis:", str(e), flush=True)
        return json.dumps({
            "hosts": [],
            "error": str(e)
        }, indent=2)


# =========================
# Main monitoring loop
# =========================

def run_soc():
    set_config(
        wazuh_api=WAZUH_API,
        indexer_api=INDEXER_API,
        wazuh_user=WAZUH_USER,
        wazuh_pass=WAZUH_PASS,
        indexer_user=INDEXER_USER,
        indexer_pass=INDEXER_PASS,
        verify_tls=VERIFY_TLS,
    )

    print("AI SOC Engine Started", flush=True)

    while True:
        try:
            print("[1/5] Fetching alerts from Wazuh Indexer...", flush=True)
            alerts = get_latest_alerts(hours=POLL_HOURS, size=POLL_SIZE, target_agent="all")
            print("Alerts received:", len(alerts), flush=True)

            print("[2/5] Detecting suspicious hosts...", flush=True)
            suspicious_hosts = detect_suspicious_hosts(alerts)

            if suspicious_hosts:
                print("Suspicious activity detected on hosts:", ", ".join(suspicious_hosts), flush=True)

                per_host_summary = build_per_host_summary(alerts)
                print("Per-host summary preview:", flush=True)
                print(json.dumps(per_host_summary, indent=2)[:2500], flush=True)

                raw_report = analyze_with_ai(alerts)

                print("[4/5] Parsing AI response...", flush=True)
                parsed_report = normalize_ai_report(parse_ai_json(raw_report))

                print("=== AI REPORT JSON START ===", flush=True)
                print(json.dumps(parsed_report, indent=2), flush=True)
                print("=== AI REPORT JSON END ===", flush=True)

            else:
                print("No suspicious activity", flush=True)

        except KeyboardInterrupt:
            print("Interrupted by user. Exiting...", flush=True)
            break
        except Exception as e:
            print(f"Unhandled error in SOC loop: {e}", flush=True)

        print(f"[5/5] Sleeping for {POLL_INTERVAL_SECONDS} seconds...\n", flush=True)
        time.sleep(POLL_INTERVAL_SECONDS)


# =========================
# Start SOC engine
# =========================

if __name__ == "__main__":
    run_soc()
