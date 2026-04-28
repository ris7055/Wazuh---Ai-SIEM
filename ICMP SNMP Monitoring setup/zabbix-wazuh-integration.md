# Zabbix → Wazuh Integration Documentation

**Author:** Raff  
**Date:** April 2026  
**Environment:** Azure VM (Ubuntu 24.04), Wazuh 4.14.5, Zabbix 7.0 (Docker)

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Prerequisites](#prerequisites)
3. [Phase 1 — Install Zabbix on Docker](#phase-1--install-zabbix-on-docker)
4. [Phase 2 — Configure ICMP Monitoring](#phase-2--configure-icmp-monitoring)
5. [Phase 3 — WireGuard VPN Setup](#phase-3--wireguard-vpn-setup)
6. [Phase 4 — Wazuh Custom Decoder & Rules](#phase-4--wazuh-custom-decoder--rules)
7. [Phase 5 — Socat Proxy for Docker Networking](#phase-5--socat-proxy-for-docker-networking)
8. [Phase 6 — Zabbix Media Type (Webhook)](#phase-6--zabbix-media-type-webhook)
9. [Phase 7 — Zabbix User Media & Action](#phase-7--zabbix-user-media--action)
10. [Phase 8 — Verification](#phase-8--verification)
11. [Troubleshooting](#troubleshooting)
12. [Architecture Notes](#architecture-notes)

---

## Architecture Overview

```
Client Devices (WireGuard VPN)
        │
        ▼
Zabbix Server (Docker on Wazuh VM)
  ├── ICMP Ping monitoring
  ├── SNMP monitoring (future)
  └── Trigger → Action → Webhook
        │
        ▼
Socat Proxy Container (zabbix-net)
        │
        ▼
Wazuh Manager API (port 55000)
        │
        ▼
Custom Decoder → Rule 100700-100704
        │
        ▼
OpenSearch → Wazuh Dashboard
```

---

## Prerequisites

- Azure VM running Wazuh Manager (Ubuntu 24.04 LTS)
- Wazuh 4.x installed and running
- Docker and Docker Compose installed
- Wazuh API credentials

---

## Phase 1 — Install Zabbix on Docker

### 1.1 Install Docker

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) \
  signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

sudo usermod -aG docker $USER
newgrp docker
```

### 1.2 Create Zabbix Docker Compose

```bash
mkdir -p ~/zabbix
nano ~/zabbix/docker-compose.yml
```

Paste the following:

```yaml
version: '3.8'

services:
  zabbix-db:
    image: mysql:8.0
    container_name: zabbix-db
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: zabbix
      MYSQL_USER: zabbix
      MYSQL_PASSWORD: YOUR_DB_PASSWORD
      MYSQL_ROOT_PASSWORD: YOUR_ROOT_PASSWORD
    volumes:
      - zabbix-db-data:/var/lib/mysql
    networks:
      - zabbix-net
    command: --character-set-server=utf8mb4 --collation-server=utf8mb4_bin

  zabbix-server:
    image: zabbix/zabbix-server-mysql:ubuntu-7.0-latest
    container_name: zabbix-server
    restart: unless-stopped
    environment:
      DB_SERVER_HOST: zabbix-db
      MYSQL_DATABASE: zabbix
      MYSQL_USER: zabbix
      MYSQL_PASSWORD: YOUR_DB_PASSWORD
      MYSQL_ROOT_PASSWORD: YOUR_ROOT_PASSWORD
      ZBX_STARTPINGERS: 10
      ZBX_STARTSNMPTRAPPER: 2
      ZBX_CACHESIZE: 128M
    extra_hosts:
      - "host.docker.internal:host-gateway"
    ports:
      - "10051:10051"
    depends_on:
      - zabbix-db
    networks:
      - zabbix-net

  zabbix-web:
    image: zabbix/zabbix-web-apache-mysql:ubuntu-7.0-latest
    container_name: zabbix-web
    restart: unless-stopped
    environment:
      DB_SERVER_HOST: zabbix-db
      MYSQL_DATABASE: zabbix
      MYSQL_USER: zabbix
      MYSQL_PASSWORD: YOUR_DB_PASSWORD
      PHP_TZ: Asia/Kuala_Lumpur
      ZBX_SERVER_HOST: zabbix-server
    ports:
      - "8090:8080"
    depends_on:
      - zabbix-db
      - zabbix-server
    networks:
      - zabbix-net

networks:
  zabbix-net:
    driver: bridge

volumes:
  zabbix-db-data:
```

> ⚠️ Replace `YOUR_DB_PASSWORD` and `YOUR_ROOT_PASSWORD` with strong passwords.

### 1.3 Launch Zabbix

```bash
cd ~/zabbix
docker compose up -d
docker compose ps
```

All three containers should show `Up`:
```
zabbix-db       Up
zabbix-server   Up
zabbix-web      Up (healthy)
```

### 1.4 Open Azure NSG Port

Add inbound rule in Azure Portal:
```
Port:     8090
Protocol: TCP
Source:   My IP address
Action:   Allow
Name:     Allow-Zabbix-Web
```

Also allow in UFW:
```bash
sudo ufw allow 8090/tcp
sudo ufw reload
```

### 1.5 Access Zabbix Web UI

```
http://<VM_PUBLIC_IP>:8090
Username: Admin
Password: zabbix
```

> ⚠️ Change the default password immediately after first login.

---

## Phase 2 — Configure ICMP Monitoring

### 2.1 Add Test Host (Google DNS)

```
Data collection → Hosts → Create host

Host name:    Google-DNS
Templates:    ICMP Ping
Host groups:  Virtual machines
Interface:    Agent → IP: 8.8.8.8 → Port: 10050
```

### 2.2 Verify ICMP Data

```
Monitoring → Latest data → filter by Google-DNS
```

Expected results:
```
ICMP ping            Up (1)   ✅
ICMP loss            0%       ✅
ICMP response time   Xms      ✅
```

---

## Phase 3 — WireGuard VPN Setup

> Required for monitoring client devices on remote networks.

### 3.1 Install WireGuard on Azure VM

```bash
sudo apt update
sudo apt install -y wireguard
```

### 3.2 Generate Server Keys

```bash
wg genkey | sudo tee /etc/wireguard/server_private.key | \
  wg pubkey | sudo tee /etc/wireguard/server_public.key

sudo chmod 600 /etc/wireguard/server_private.key

sudo cat /etc/wireguard/server_private.key
sudo cat /etc/wireguard/server_public.key
```

### 3.3 Generate Client Keys

```bash
wg genkey | sudo tee /etc/wireguard/client_private.key | \
  wg pubkey | sudo tee /etc/wireguard/client_public.key
```

### 3.4 Create Server Config

```bash
sudo nano /etc/wireguard/wg0.conf
```

```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIVATE_KEY>
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = <CLIENT_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
```

### 3.5 Enable IP Forwarding

```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 3.6 Start WireGuard

```bash
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
sudo ufw allow 51820/udp
sudo ufw reload
sudo wg show
```

### 3.7 Azure NSG Rule for WireGuard

```
Port:     51820
Protocol: UDP
Source:   My IP address
Action:   Allow
Name:     Allow-WireGuard
```

### 3.8 Windows Client Config

Install WireGuard from https://www.wireguard.com/install/

Create tunnel with:

```ini
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.0.0.2/24
DNS = 8.8.8.8

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = <VM_PUBLIC_IP>:51820
AllowedIPs = 10.0.0.0/24
PersistentKeepalive = 25
```

### 3.9 Enable ICMP on Windows Client

```cmd
netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow
```

---

## Phase 4 — Wazuh Custom Decoder & Rules

### 4.1 Check for Existing Zabbix Decoders

```bash
grep -ri "zabbix" /var/ossec/ruleset/ 2>/dev/null
grep -ri "zabbix" /var/ossec/etc/ 2>/dev/null
```

> Wazuh has no built-in Zabbix support — custom decoder required.

### 4.2 Add Zabbix Decoder

```bash
sudo nano /var/ossec/etc/decoders/local_decoder.xml
```

Add before the last closing tag:

```xml
<!--Zabbix Decoders-->
<decoder name="zabbix">
  <program_name>zabbix</program_name>
</decoder>

<decoder name="zabbix-alert">
  <parent>zabbix</parent>
  <regex>^(\w+) - Host: (\S+) - IP: (\S+) - Alert: (\.+) - Message: (\.+) - Severity: (\w+)</regex>
  <order>zabbix_status,zabbix_host,zabbix_ip,zabbix_alert,zabbix_message,zabbix_severity</order>
</decoder>
```

### 4.3 Add Zabbix Rules

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add at the bottom (adjust IDs to avoid conflicts with existing rules):

```xml
<!-- Zabbix Rules -->
<group name="zabbix,">

  <rule id="100700" level="3">
    <decoded_as>zabbix</decoded_as>
    <description>Zabbix alert received</description>
    <group>zabbix,</group>
  </rule>

  <rule id="100701" level="7">
    <if_sid>100700</if_sid>
    <field name="zabbix_status">PROBLEM</field>
    <description>Zabbix PROBLEM: $(zabbix_alert) on $(zabbix_host)</description>
    <group>zabbix,zabbix_problem,</group>
  </rule>

  <rule id="100702" level="3">
    <if_sid>100700</if_sid>
    <field name="zabbix_status">RESOLVED</field>
    <description>Zabbix RESOLVED: $(zabbix_alert) on $(zabbix_host)</description>
    <group>zabbix,zabbix_resolved,</group>
  </rule>

  <rule id="100703" level="10">
    <if_sid>100701</if_sid>
    <field name="zabbix_severity">High</field>
    <description>Zabbix HIGH severity: $(zabbix_alert) on $(zabbix_host) ($(zabbix_ip))</description>
    <group>zabbix,zabbix_high,</group>
  </rule>

  <rule id="100704" level="12">
    <if_sid>100701</if_sid>
    <field name="zabbix_severity">Disaster</field>
    <description>Zabbix DISASTER: $(zabbix_alert) on $(zabbix_host) ($(zabbix_ip))</description>
    <group>zabbix,zabbix_disaster,</group>
  </rule>

</group>
```

> ⚠️ Check your existing rule IDs first and adjust accordingly to avoid conflicts.

### 4.4 Test the Decoder

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste test event:
```
Jan 01 00:00:00 zabbix-server zabbix: PROBLEM - Host: TestHost - IP: 10.0.0.2 - Alert: ICMP ping failed - Message: Host is unreachable - Severity: High
```

Expected output:
```
**Phase 2: Completed decoding.
        name: 'zabbix-alert'
        zabbix_status: 'PROBLEM'
        zabbix_host: 'TestHost'
        zabbix_severity: 'High'

**Phase 3: Completed filtering (rules).
        id: '100703'
        level: '10'
        description: 'Zabbix HIGH severity: ICMP ping failed on TestHost (10.0.0.2)'
```

### 4.5 Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager | grep "Active:"
```

---

## Phase 5 — Socat Proxy for Docker Networking

> Required because the Zabbix Docker container cannot directly reach the Wazuh API on the host due to Docker network isolation.

### 5.1 Find Zabbix Docker Network

```bash
docker network inspect zabbix_zabbix-net | grep Gateway
# Note the gateway IP (e.g., 172.19.0.1)
```

### 5.2 Deploy Socat Proxy Container

```bash
docker run -d --name wazuh-proxy \
  --network zabbix_zabbix-net \
  --restart unless-stopped \
  alpine/socat \
  TCP-LISTEN:55000,fork,reuseaddr OPENSSL:172.18.0.4:55000,verify=0,commonname=""
```

> Replace `172.18.0.4` with your VM's actual eth0 IP.

### 5.3 Get Proxy Container IP

```bash
docker inspect wazuh-proxy | grep IPAddress
# Note the IP (e.g., 172.19.0.5)
```

### 5.4 Verify Connectivity

```bash
docker exec -it zabbix-server wget -v \
  --timeout=5 \
  http://172.19.0.5:55000/ 2>&1
```

Expected: `401 Unauthorized` (means connection works)

### 5.5 Generate Base64 Credentials

```bash
echo -n 'wazuh:YOUR_WAZUH_API_PASSWORD' | base64
# Save the output — needed for the webhook script
```

---

## Phase 6 — Zabbix Media Type (Webhook)

### 6.1 Create Media Type

```
Alerts → Media types → Create media type

Name: Wazuh-Direct
Type: Webhook
```

### 6.2 Add Parameters

| Name | Value |
|---|---|
| `alert_subject` | `{TRIGGER.NAME}` |
| `alert_message` | `{TRIGGER.DESCRIPTION}` |
| `zabbix_host` | `{HOST.NAME}` |
| `zabbix_ip` | `{HOST.IP}` |
| `zabbix_severity` | `{TRIGGER.SEVERITY}` |
| `zabbix_status` | `{TRIGGER.STATUS}` |
| `event_id` | `{EVENT.ID}` |
| `event_time` | `{EVENT.TIME}` |
| `event_date` | `{EVENT.DATE}` |

> Remove default parameters: URL, HTTPProxy, To, Subject, Message

### 6.3 Add Webhook Script

Click the pencil ✏️ next to Script and paste:

```javascript
var params = JSON.parse(value);

var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('Authorization: Basic YOUR_BASE64_CREDENTIALS');

// Step 1: Get Wazuh API Token
var authResponse = req.get(
    'http://PROXY_IP:55000/security/user/authenticate'
);

if (req.getStatus() != 200) {
    throw 'Auth failed: ' + req.getStatus() + ' ' + authResponse;
}

var token = JSON.parse(authResponse).data.token;

// Step 2: Format event as syslog string
var now = new Date();
var months = ['Jan','Feb','Mar','Apr','May','Jun',
              'Jul','Aug','Sep','Oct','Nov','Dec'];

function pad(n, width, z) {
    z = z || '0';
    n = String(n);
    return n.length >= width ? n : new Array(width - n.length + 1).join(z) + n;
}

var timestamp = months[now.getMonth()] + ' ' +
    pad(now.getDate(), 2, ' ') + ' ' +
    pad(now.getHours(), 2, '0') + ':' +
    pad(now.getMinutes(), 2, '0') + ':' +
    pad(now.getSeconds(), 2, '0');

var event = timestamp + ' zabbix-server zabbix: ' +
    params.zabbix_status + ' - Host: ' + params.zabbix_host +
    ' - IP: ' + params.zabbix_ip +
    ' - Alert: ' + params.alert_subject +
    ' - Message: ' + params.alert_message +
    ' - Severity: ' + params.zabbix_severity;

// Step 3: Send to Wazuh
var wazuhReq = new HttpRequest();
wazuhReq.addHeader('Content-Type: application/json');
wazuhReq.addHeader('Authorization: Bearer ' + token);

var payload = JSON.stringify({
    events: [event]
});

var response = wazuhReq.post(
    'http://PROXY_IP:55000/events',
    payload
);

if (wazuhReq.getStatus() != 200) {
    throw 'Wazuh API error: ' + wazuhReq.getStatus() + ' ' + response;
}

return response;
```

> Replace `YOUR_BASE64_CREDENTIALS` with the Base64 string from Phase 5.5
> Replace `PROXY_IP` with your socat proxy container IP (e.g., `172.19.0.5`)

### 6.4 Add Message Templates

```
Message templates tab → Add

Message type: Problem
Subject:      {TRIGGER.NAME}
Message:      {TRIGGER.DESCRIPTION}
```

```
Message type: Problem recovery
Subject:      {TRIGGER.NAME}  
Message:      {TRIGGER.DESCRIPTION}
```

### 6.5 Test the Media Type

Click **Test** at the bottom and fill in:

| Parameter | Value |
|---|---|
| `alert_message` | `Host is unreachable` |
| `alert_subject` | `ICMP ping failed` |
| `zabbix_host` | `TestHost` |
| `zabbix_ip` | `10.0.0.2` |
| `zabbix_severity` | `High` |
| `zabbix_status` | `PROBLEM` |

Expected: `Media type test successful` ✅

---

## Phase 7 — Zabbix User Media & Action

### 7.1 Add Media to Admin User

```
Users → Users → Admin → Media tab → Add

Type:           Wazuh-Direct
Send to:        wazuh
When active:    1-7,00:00-24:00
Use if severity: All checked
Enabled:        ✅
```

Click **Add** → **Update**

### 7.2 Create Trigger Action

```
Alerts → Actions → Trigger actions → Create action
```

**Action tab:**
```
Name:      Send-to-Wazuh
Condition: Trigger severity >= Warning
Enabled:   ✅
```

**Operations tab:**
```
Default operation step duration: 1m

Operation:
  Steps:              1 - 0 (infinitely)
  Step duration:      1m
  Send to users:      Admin
  Send to media type: Wazuh-Direct
```

**Recovery operations:**
```
Send to users:      Admin
Send to media type: Wazuh-Direct
```

Click **Add** → **Update**

---

## Phase 8 — Verification

### 8.1 Add Test Unreachable Host

```
Data collection → Hosts → Create host

Host name:    Test-Unreachable
IP:           192.168.255.254
Templates:    ICMP Ping
Host groups:  Virtual machines
```

### 8.2 Verify Action Log

```
Reports → Action log → Last 15 minutes
```

Expected:
```
Send-to-Wazuh | Wazuh-Direct | Sent ✅
```

### 8.3 Verify Wazuh Dashboard

```
Wazuh Dashboard → Discover
Index: wazuh-alerts-*
Search: zabbix
Time range: Last 15 minutes
```

Expected fields:
```
data.zabbix_host:     Test-Unreachable
data.zabbix_ip:       192.168.255.254
data.zabbix_status:   PROBLEM
data.zabbix_severity: High
data.zabbix_alert:    ICMP ping failed
rule.id:              100703
rule.level:           10
```

### 8.4 Verify via API

```bash
TOKEN=$(curl -k -s -X GET \
  https://localhost:55000/security/user/authenticate \
  -u wazuh:YOUR_PASSWORD \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])")

curl -k -X POST https://localhost:55000/events \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"events": ["Jan 01 00:00:00 zabbix-server zabbix: PROBLEM - Host: TestHost - IP: 10.0.0.2 - Alert: ICMP ping failed - Message: Host is unreachable - Severity: High"]}'
```

---

## Troubleshooting

### Zabbix Web UI Not Accessible

```bash
# Check containers
docker compose ps

# Check UFW
sudo ufw status | grep 8090

# Check Azure NSG — ensure port 8090 is allowed for your IP
```

### Wazuh API Not Reachable from Zabbix Container

```bash
# Verify socat proxy is running
docker ps | grep wazuh-proxy

# Test connectivity
docker exec -it zabbix-server wget -v \
  --timeout=5 \
  http://<PROXY_IP>:55000/ 2>&1
# Should return 401 Unauthorized
```

### Decoder Not Matching

```bash
# Test with logtest
sudo /var/ossec/bin/wazuh-logtest

# Check decoder file syntax
sudo xmllint --noout /var/ossec/etc/decoders/local_decoder.xml
```

### Action Log Shows "Failed"

Common causes:
1. Message template not defined → Add in Media type → Message templates tab
2. Proxy container not running → `docker ps | grep wazuh-proxy`
3. Base64 credentials wrong → Regenerate with `echo -n 'user:pass' | base64`

### WireGuard Tunnel Not Working

```bash
# Check if UFW is blocking
sudo ufw allow 51820/udp
sudo ufw reload

# Verify tunnel is up
sudo wg show
```

---

## Architecture Notes

### Key IPs (adjust for your environment)

| Component | IP |
|---|---|
| Wazuh VM eth0 | `172.18.0.4` |
| Zabbix Docker network gateway | `172.19.0.1` |
| Zabbix server container | `172.19.0.3` |
| Socat proxy container | `172.19.0.5` |
| WireGuard server (Azure VM) | `10.0.0.1` |
| WireGuard client (laptop) | `10.0.0.2` |

### Why Socat Proxy?

Docker containers on a custom bridge network cannot directly reach host services due to network isolation and iptables rules. The socat proxy container sits on the same Docker network as Zabbix and forwards requests to the Wazuh API on the host, bridging this gap cleanly.

### Rule ID Allocation

| Rule ID | Description |
|---|---|
| 100700 | Base Zabbix alert (level 3) |
| 100701 | Zabbix PROBLEM (level 7) |
| 100702 | Zabbix RESOLVED (level 3) |
| 100703 | Zabbix HIGH severity (level 10) |
| 100704 | Zabbix DISASTER severity (level 12) |

### Zabbix Token Expiry

Wazuh API tokens expire every 15 minutes. The webhook script fetches a fresh token on every execution — no manual token management needed.

---

## References

- [Zabbix 7.0 Documentation](https://www.zabbix.com/documentation/7.0/)
- [Wazuh API Documentation](https://documentation.wazuh.com/current/user-manual/api/reference.html)
- [WireGuard Documentation](https://www.wireguard.com/)
- [Docker Documentation](https://docs.docker.com/)
