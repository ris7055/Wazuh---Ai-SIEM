# Wazuh AI Copilot — Setup Guide
### On-Premises AI Assistant powered by Gemma 4 via Ollama

> **Environment:** Wazuh 4.14.4 · OpenSearch 2.19.4 · Azure VM (Ubuntu 24) · CPU-only  
> **Model:** `gemma4:e2b` via Ollama  
> **Status:** Production-ready for testing. Patch required for ML Commons private IP restriction.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Step 1 — Install & Update Ollama](#step-1--install--update-ollama)
4. [Step 2 — Pull Gemma 4 Model](#step-2--pull-gemma-4-model)
5. [Step 3 — Enable ML Commons on Wazuh Indexer](#step-3--enable-ml-commons-on-wazuh-indexer)
6. [Step 4 — Patch ML Commons Private IP Restriction](#step-4--patch-ml-commons-private-ip-restriction)
7. [Step 5 — Setup nginx Reverse Proxy](#step-5--setup-nginx-reverse-proxy)
8. [Step 6 — Register the AI Connector](#step-6--register-the-ai-connector)
9. [Step 7 — Register & Deploy the Model](#step-7--register--deploy-the-model)
10. [Step 8 — Install Assistant Plugin in Dashboard](#step-8--install-assistant-plugin-in-dashboard)
11. [Step 9 — Register the AI Agent](#step-9--register-the-ai-agent)
12. [Step 10 — Wire Agent to Dashboard Chat](#step-10--wire-agent-to-dashboard-chat)
13. [Security Hardening](#security-hardening)
14. [Maintenance Notes](#maintenance-notes)
15. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

```
User (Browser)
    │
    ▼
Wazuh Dashboard (OpenSearch Dashboards 2.19.4)
    │  assistantDashboards plugin
    ▼
OpenSearch ML Commons
    │  Remote connector → http://172.18.0.4:8080
    ▼
nginx (reverse proxy on port 8080)
    │  proxy_pass → http://127.0.0.1:11434
    ▼
Ollama (local inference server)
    │
    ▼
Gemma 4 (gemma4:e2b — 7.2 GB, CPU mode)
```

> **Why nginx?** ML Commons 2.19.x has a hardcoded private IP check in `MLHttpClientFactory.java` that blocks `localhost`, `127.0.0.1`, and all RFC-1918 ranges. nginx acts as a proxy so ML Commons calls the VM's internal IP on a port routed through nginx. The ML Commons jar is also patched (Step 4) to remove this restriction entirely.

---

## Prerequisites

| Requirement | Value |
|---|---|
| Wazuh version | 4.14.4+ |
| OpenSearch version | 2.19.4+ |
| OS | Ubuntu 24.04 |
| RAM | 16 GB minimum (8 GB free for Gemma 4) |
| Disk | 15 GB free for model storage |
| Internet | Required for initial Ollama/model download |

---

## Step 1 — Install & Update Ollama

```bash
# Install or upgrade Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Verify version (must be 0.20.0+)
ollama --version

# Verify service is running
systemctl status ollama
```

**Expected output:** `Active: active (running)`

---

## Step 2 — Pull Gemma 4 Model

Choose the model size based on your available RAM:

| Tag | Size | RAM Required |
|---|---|---|
| `gemma4:e2b` | 7.2 GB | 8 GB free ← recommended for 16 GB VMs |
| `gemma4:e4b` | 9.6 GB | 12 GB free |
| `gemma4:26b` | 18 GB | 24 GB free |
| `gemma4:31b` | 20 GB | 28 GB free |

```bash
# Check available RAM first
free -h

# Pull the model (takes 5–15 minutes depending on connection)
ollama pull gemma4:e2b

# Verify it pulled correctly
ollama list

# Quick test
ollama run gemma4:e2b "What does a Wazuh rule level 12 alert mean?"
```

---

## Step 3 — Enable ML Commons on Wazuh Indexer

```bash
# Add ML Commons settings to opensearch.yml
sudo tee -a /etc/wazuh-indexer/opensearch.yml > /dev/null <<EOF

# ML Commons settings
plugins.ml_commons.only_run_on_ml_node: false
plugins.ml_commons.allow_registering_model_via_url: true
plugins.ml_commons.model_access_control_enabled: true
plugins.ml_commons.native_memory_threshold: 99
plugins.ml_commons.trusted_connector_endpoints_regex: ["^http://172.18.0.4:8080/.*$"]
EOF

# Verify settings were added
sudo tail -10 /etc/wazuh-indexer/opensearch.yml

# Restart indexer
sudo systemctl restart wazuh-indexer

# Verify ML Commons is active
curl -sk -u admin:YOUR_PASSWORD \
  https://localhost:9200/_plugins/_ml/stats | python3 -m json.tool | head -20
```

> **Note:** Replace `YOUR_PASSWORD` with your actual Wazuh admin password throughout this guide. Replace `172.18.0.4` with your VM's actual internal IP (`hostname -I`).

---

## Step 4 — Patch ML Commons Private IP Restriction

> **Why this is needed:** ML Commons 2.19.x hardcodes a private IP check in `MLHttpClientFactory.java` that cannot be disabled via config. This patch replaces that class with one that skips the check.

```bash
# Switch to root
sudo su -

# Install required tools
apt-get install -y unzip zip openjdk-17-jdk-headless

# Backup the original jar
cp /usr/share/wazuh-indexer/plugins/opensearch-ml/opensearch-ml-common-2.19.4.0.jar \
   /usr/share/wazuh-indexer/plugins/opensearch-ml/opensearch-ml-common-2.19.4.0.jar.bak

# Extract the jar
mkdir -p /tmp/ml-patch2 && cd /tmp/ml-patch2
cp /usr/share/wazuh-indexer/plugins/opensearch-ml/opensearch-ml-common-2.19.4.0.jar .
unzip -q opensearch-ml-common-2.19.4.0.jar

# Create patched Java source
mkdir -p /tmp/patch-src/org/opensearch/ml/common/httpclient
cat > /tmp/patch-src/org/opensearch/ml/common/httpclient/MLHttpClientFactory.java <<'JAVA'
package org.opensearch.ml.common.httpclient;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import software.amazon.awssdk.http.async.SdkAsyncHttpClient;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;

public class MLHttpClientFactory {
    public MLHttpClientFactory() {}

    public static SdkAsyncHttpClient getAsyncHttpClient(Duration connectionTimeout, Duration readTimeout, int maxConnections) {
        return NettyNioAsyncHttpClient.builder()
            .connectionTimeout(connectionTimeout)
            .readTimeout(readTimeout)
            .maxConcurrency(maxConnections)
            .build();
    }

    public static void validate(String protocol, String host, int port, AtomicBoolean isStream) throws UnknownHostException {
        // Private IP check bypassed for local Ollama integration
    }
}
JAVA

# Compile the patched class
/usr/share/wazuh-indexer/jdk/bin/javac \
  -cp "/tmp/ml-patch2/opensearch-ml-common-2.19.4.0.jar:/usr/share/wazuh-indexer/plugins/opensearch-ml/http-client-spi-2.32.29.jar:/usr/share/wazuh-indexer/plugins/opensearch-ml/netty-nio-client-2.32.29.jar:/usr/share/wazuh-indexer/plugins/opensearch-ml/utils-2.32.29.jar:/usr/share/wazuh-indexer/plugins/opensearch-ml/aws-core-2.32.29.jar" \
  /tmp/patch-src/org/opensearch/ml/common/httpclient/MLHttpClientFactory.java

# Inject patched class into the jar
cd /tmp/patch-src
jar uf /usr/share/wazuh-indexer/plugins/opensearch-ml/opensearch-ml-common-2.19.4.0.jar \
    org/opensearch/ml/common/httpclient/MLHttpClientFactory.class

# Document the patch
echo "ML Commons jar patched on $(date) to remove private IP check. Backup at opensearch-ml-common-2.19.4.0.jar.bak. Redo patch after any wazuh-indexer upgrade." \
  | tee /etc/wazuh-indexer/ML_PATCH_NOTE.txt

# Restart indexer to load the patched jar
systemctl restart wazuh-indexer && sleep 20
systemctl status wazuh-indexer --no-pager | head -5
```

> ⚠️ **Important:** This patch must be reapplied after every `wazuh-indexer` package upgrade. Check `/etc/wazuh-indexer/ML_PATCH_NOTE.txt` for the patch date.

---

## Step 5 — Setup nginx Reverse Proxy

```bash
# Install nginx
sudo apt-get install -y nginx

# Create Ollama proxy config
sudo tee /etc/nginx/sites-available/ollama <<EOF
server {
    listen 8080;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:11434;
        proxy_set_header Host \$host;
        proxy_read_timeout 300s;
        proxy_connect_timeout 300s;
    }
}
EOF

# Enable the config
sudo ln -s /etc/nginx/sites-available/ollama /etc/nginx/sites-enabled/

# Test and start nginx
sudo nginx -t && sudo systemctl restart nginx
sudo systemctl enable nginx

# Verify nginx is proxying correctly
curl -s http://172.18.0.4:8080/api/tags | python3 -m json.tool | head -5
```

**Expected output:** Shows `gemma4:e2b` in the models list.

### Azure NSG Rule (Required)

Add an inbound security rule in Azure Portal → VM → Networking:

| Field | Value |
|---|---|
| Source | IP Addresses |
| Source IP | Your VM's public IP (e.g. `20.17.161.110`) |
| Destination port | `8080` |
| Protocol | TCP |
| Action | Allow |
| Name | `Allow-Ollama-Self` |

> This rule ensures port 8080 is only reachable from the VM itself, not the public internet.

---

## Step 6 — Register the AI Connector

```bash
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/connectors/_create" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Ollama Gemma4 - Wazuh Copilot",
    "description": "Local Gemma 4 via nginx proxy",
    "version": 1,
    "protocol": "http",
    "parameters": {
      "model": "gemma4:e2b"
    },
    "credential": {
      "key": "ollama-local"
    },
    "actions": [
      {
        "action_type": "predict",
        "method": "POST",
        "url": "http://172.18.0.4:8080/api/chat",
        "headers": {
          "Content-Type": "application/json"
        },
        "request_body": "{\"model\":\"${parameters.model}\",\"messages\":[{\"role\":\"system\",\"content\":\"You are a Wazuh SIEM security analyst assistant for an MSSP. Answer security questions clearly and concisely.\"},{\"role\":\"user\",\"content\":\"${parameters.prompt}\"}],\"stream\":false}",
        "post_process_function": "def output = params.message.content; return output;"
      }
    ]
  }'
```

**Save the `connector_id` from the response.**

---

## Step 7 — Register & Deploy the Model

```bash
# Register model using the connector_id from Step 6
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/models/_register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "wazuh-copilot-gemma4",
    "function_name": "remote",
    "description": "Gemma 4 local copilot for Wazuh MSSP",
    "connector_id": "YOUR_CONNECTOR_ID"
  }'
```

**Save the `model_id` from the response.**

```bash
# Deploy the model
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/models/YOUR_MODEL_ID/_deploy"
```

**Expected:** `"status": "COMPLETED"`

```bash
# Test the model directly (takes 1–3 minutes on CPU)
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/models/YOUR_MODEL_ID/_predict" \
  -H "Content-Type: application/json" \
  -d '{
    "parameters": {
      "prompt": "What does a Wazuh rule level 12 alert mean?"
    }
  }' | python3 -m json.tool
```

**Expected:** Clean text response from Gemma 4 inside `dataAsMap.response`.

---

## Step 8 — Install Assistant Plugin in Dashboard

```bash
# Install the OpenSearch assistant plugin
sudo /usr/share/wazuh-dashboard/bin/opensearch-dashboards-plugin \
  install assistantDashboards --allow-root

# Enable the chat UI in dashboard config
sudo tee -a /etc/wazuh-dashboard/opensearch_dashboards.yml > /dev/null <<EOF

# AI Assistant plugin settings
assistant.chat.enabled: true
EOF

# Restart dashboard
sudo systemctl restart wazuh-dashboard && sleep 20
sudo systemctl status wazuh-dashboard --no-pager | head -5
```

> After restart, log into the Wazuh Dashboard — you should see **"Ask a question"** in the top bar and an **OpenSearch Assistant** panel.

---

## Step 9 — Register the AI Agent

```bash
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/agents/_register" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "os_chat",
    "type": "conversational",
    "description": "Wazuh MSSP AI Copilot powered by Gemma 4",
    "llm": {
      "model_id": "YOUR_MODEL_ID",
      "parameters": {
        "max_iteration": 5,
        "stop_when_no_tool_used": true,
        "prompt": "You are a Wazuh SIEM security analyst assistant for an MSSP. Answer security questions clearly and concisely."
      }
    },
    "tools": [
      { "type": "CatIndexTool" },
      { "type": "SearchIndexTool" }
    ],
    "memory": {
      "type": "conversation_index"
    },
    "app_type": "os_chat"
  }'
```

**Save the `agent_id` from the response.**

---

## Step 10 — Wire Agent to Dashboard Chat

This step requires the admin TLS certificate to write to the protected ML config index:

```bash
# Write the root agent config using admin certificate
curl -sk \
  --cert /etc/wazuh-indexer/certs/admin.pem \
  --key /etc/wazuh-indexer/certs/admin-key.pem \
  -X PUT "https://localhost:9200/.plugins-ml-config/_doc/os_chat" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "os_chat_root_agent",
    "configuration": {
      "agent_id": "YOUR_AGENT_ID"
    }
  }'
```

**Expected:** `"result": "created"` or `"result": "updated"`

**Refresh your browser** and type a question in the chat box. The AI Copilot is now live!

---

## Security Hardening

### Tighten ML Commons trusted endpoints

```bash
curl -sk -u admin:YOUR_PASSWORD \
  -X PUT "https://localhost:9200/_cluster/settings" \
  -H "Content-Type: application/json" \
  -d '{
    "persistent": {
      "plugins.ml_commons.trusted_connector_endpoints_regex": [
        "^http://172.18.0.4:8080/.*$"
      ]
    }
  }'
```

### Recommended Azure NSG rules review

| Port | Current | Recommended |
|---|---|---|
| 22 (SSH) | Any | Restrict to your office IP |
| 80 (HTTP) | Any | Disable if not needed |
| 443 (HTTPS) | Any | Keep for dashboard access |
| 3000 (Grafana) | Any | Restrict to your IP |
| 8000 | Any | Review — restrict or disable |
| 8001 | Any | Review — restrict or disable |
| 8080 (nginx/Ollama) | VM public IP only | Keep as-is |

### Clean up unused ML models

```bash
# List all models
curl -sk -u admin:YOUR_PASSWORD \
  https://localhost:9200/_plugins/_ml/models/_search \
  -H "Content-Type: application/json" \
  -d '{"query":{"match_all":{}},"size":20}' \
  | python3 -m json.tool | grep -E "name|_id"

# Undeploy and delete old models
curl -sk -u admin:YOUR_PASSWORD \
  -X POST "https://localhost:9200/_plugins/_ml/models/OLD_MODEL_ID/_undeploy"

curl -sk -u admin:YOUR_PASSWORD \
  -X DELETE "https://localhost:9200/_plugins/_ml/models/OLD_MODEL_ID"
```

---

## Maintenance Notes

### After wazuh-indexer upgrade

The ML Commons jar patch (Step 4) is overwritten by package upgrades. Re-apply it:

```bash
# Check if patch is still applied
ls -la /usr/share/wazuh-indexer/plugins/opensearch-ml/opensearch-ml-common-*.jar*

# If .bak file is missing, re-run Step 4
cat /etc/wazuh-indexer/ML_PATCH_NOTE.txt
```

### Swapping to a larger model

When you upgrade to a bigger Azure VM (32 GB+ RAM):

```bash
# Pull a larger model
ollama pull gemma4:e4b   # or gemma4:26b for 32+ GB RAM

# Update the connector's model parameter
# Re-run Steps 6–10 with the new model name
```

### Service startup order

All three services must be running for the copilot to work:

```bash
systemctl status wazuh-indexer wazuh-dashboard ollama nginx
```

---

## Troubleshooting

### Chat shows "Error from response: NullPointerException"
The agent config is missing. Re-run Step 10.

### Chat shows "Failed to find config with the provided config id: os_chat"
The `.plugins-ml-config` index doesn't have the agent registered. Re-run Step 10 using the admin certificate method.

### Predict returns "Remote inference host name has private ip address"
The ML Commons jar patch was not applied or was overwritten. Re-run Step 4.

### Predict returns "Connection refused: /172.18.0.4:8080"
nginx is not running. Run `systemctl start nginx`.

### Chat response shows raw JSON instead of text
The `post_process_function` in the connector is not working. Re-create the connector with:
```json
"post_process_function": "def output = params.message.content; return output;"
```

### Ollama pull returns "requires a newer version of Ollama"
Update Ollama: `curl -fsSL https://ollama.com/install.sh | sh`

### Dashboard not accessible after config change
A bad setting in `opensearch_dashboards.yml` crashed the dashboard. Remove the offending line:
```bash
sudo sed -i '/assistant.chat.enabled/d' /etc/wazuh-dashboard/opensearch_dashboards.yml
sudo systemctl restart wazuh-dashboard
```

---

## Example Copilot Queries

Once the copilot is working, try these in the chat:

```
What are the indices in my cluster?
What does a Wazuh rule level 12 alert mean?
Show me failed logins in the last 24 hours
What is the most common attack pattern this week?
Which agents have not sent events recently?
Explain MITRE ATT&CK technique T1110
```

> **Note:** On CPU-only VMs, responses take 1–3 minutes. Upgrade to a GPU-enabled Azure VM (NC or NV series) for near-instant responses.

---

*Documentation generated: April 2026 | Wazuh 4.14.4 | OpenSearch 2.19.4 | Gemma 4 e2b*
