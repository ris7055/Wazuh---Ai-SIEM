# Phase 1 — Windows Endpoint Telemetry Setup
> **Wazuh MSSP — Threat Hunting Readiness**  
> Last Updated: April 2026  
> Applies to: Wazuh v4.14.x | Windows 10/11 Endpoints

---

## Overview

This document covers the complete setup of Windows endpoint telemetry for Threat Hunting using Wazuh. It enables full visibility into process activity, file changes, registry modifications, and network connections on any Windows agent.

### What This Achieves

| Telemetry Source | Data Collected |
|---|---|
| **Sysmon** | Process creation, file creation, registry changes, DNS queries |
| **Windows Firewall Logs** | All inbound/outbound connections + dropped packets (with IPs) |
| **Windows Event Logs** | Authentication events, logon/logoff, privilege use |

---

## Prerequisites

- Wazuh agent already installed and connected on the Windows endpoint
- PowerShell running as **Administrator**
- SSH access to Wazuh server (Azure VM)
- Wazuh Manager v4.x running

---

## Part A — Sysmon Setup
> Provides deep endpoint visibility: process, file, registry, and network events

### Step 1 — Download Sysmon

```powershell
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "C:\Sysmon.zip"
Expand-Archive -Path "C:\Sysmon.zip" -DestinationPath "C:\Sysmon"
```

### Step 2 — Download SwiftOnSecurity Config

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "C:\Sysmon\sysmonconfig.xml" -UseBasicParsing
```

Verify the config downloaded correctly:

```powershell
Get-Content C:\Sysmon\sysmonconfig.xml | Select-Object -First 5
```

Expected output: XML content starting with `<!--` (SwiftOnSecurity config header).

### Step 3 — Install Sysmon

```powershell
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Verify Sysmon is running:

```powershell
Get-Service Sysmon64
```

Expected: `Status: Running`

### Step 4 — Check for Existing Sysmon Config in Wazuh Agent

```powershell
Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "sysmon" -CaseSensitive:$false
```

- **No output** → Safe to proceed to Step 5
- **Output returned** → Sysmon already configured, skip Step 5

### Step 5 — Add Sysmon to Wazuh Agent Config

Open the agent config file:

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Add this block **just before** the closing `</ossec_config>` tag:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### Step 6 — Restart Wazuh Agent

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

Expected: `Status: Running`

### Step 7 — Verify Sysmon Logs in OpenSearch

In **Wazuh Dashboard → Dev Tools**, run:

```json
GET wazuh-alerts-*/_count
{
  "query": {
    "bool": {
      "must": [
        { "match": { "agent.name": "YOUR-AGENT-NAME" }},
        { "match": { "data.win.system.channel": "Microsoft-Windows-Sysmon/Operational" }}
      ]
    }
  }
}
```

✅ `count > 0` = Sysmon logs are flowing

### Key Sysmon Event IDs Reference

| Event ID | Description | Threat Hunting Value |
|---|---|---|
| `1` | Process Creation | Malware execution, suspicious spawning |
| `3` | Network Connection | C2 beaconing, lateral movement |
| `7` | Image/DLL Loaded | DLL hijacking, injection |
| `8` | CreateRemoteThread | Process injection |
| `11` | File Created | Malware dropping files |
| `12/13` | Registry Events | Persistence mechanisms |
| `22` | DNS Query | C2 domain lookup |

---

## Part B — Windows Firewall Logging Setup
> Captures all inbound/outbound connections and dropped packets with full IP details

### Step 1 — Enable Firewall Logging (All Profiles)

```powershell
# Domain Profile
netsh advfirewall set domainprofile logging droppedconnections enable
netsh advfirewall set domainprofile logging allowedconnections enable

# Private Profile
netsh advfirewall set privateprofile logging droppedconnections enable
netsh advfirewall set privateprofile logging allowedconnections enable

# Public Profile
netsh advfirewall set publicprofile logging droppedconnections enable
netsh advfirewall set publicprofile logging allowedconnections enable
```

### Step 2 — Set Log File Path and Size

```powershell
netsh advfirewall set allprofiles logging filename "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
netsh advfirewall set allprofiles logging maxfilesize 32767
```

### Step 3 — Verify Logging is Enabled

```powershell
netsh advfirewall show allprofiles logging
```

Expected output for all three profiles:
```
LogAllowedConnections    Enable
LogDroppedConnections    Enable
FileName                 C:\Windows\System32\LogFiles\Firewall\pfirewall.log
MaxFileSize              32767
```

### Step 4 — Add Firewall Log to Wazuh Agent Config

```powershell
notepad "C:\Program Files (x86)\ossec-agent\ossec.conf"
```

Add this block **just before** the closing `</ossec_config>` tag:

```xml
<localfile>
  <location>C:\Windows\System32\LogFiles\Firewall\pfirewall.log</location>
  <log_format>syslog</log_format>
</localfile>
```

### Step 5 — Restart Wazuh Agent

```powershell
Restart-Service WazuhSvc
Get-Service WazuhSvc
```

### Step 6 — Verify Log File is Being Written

```powershell
Get-Content "C:\Windows\System32\LogFiles\Firewall\pfirewall.log" | Select-Object -First 20
```

Expected: Lines in this format:
```
2026-04-15 12:14:57 DROP TCP 192.168.0.59 109.61.38.38 55496 80 0 - 0 0 0 - - - SEND 4900
2026-04-15 12:14:44 ALLOW UDP 192.168.0.59 1.1.1.1 60698 53 0 - - - - - - - SEND 17312
```

### Step 7 — Verify Logs Reaching Wazuh Manager

On the **Wazuh server**:

```bash
grep -i "pfirewall\|192.168.x.x" /var/ossec/logs/archives/archives.log | tail -20
```

✅ Lines showing `pfirewall.log` = logs are reaching the manager

---

## Part C — Wazuh Server Configuration
> Add custom decoder and rules for Windows Firewall log parsing

### Step 1 — Add Windows Firewall Decoder

```bash
sudo nano /var/ossec/etc/decoders/local_decoder.xml
```

Add this decoder block at the end of the file (before the closing tag if any):

```xml
<decoder name="windows-firewall-allow">
  <parent>windows-date-format</parent>
  <type>firewall</type>
  <prematch offset="after_parent">^ALLOW</prematch>
  <regex offset="after_parent">^(\w+) (\w+) </regex>
  <regex>(\S+) (\S+) (\d+) (\d+) </regex>
  <order>action,protocol,srcip,dstip,srcport,dstport</order>
</decoder>
```

> **Note:** The DROP decoder is already built into Wazuh as `windows-firewall` under `/var/ossec/ruleset/decoders/0380-windows_decoders.xml`. Only the ALLOW decoder needs to be added manually.

### Step 2 — Add Windows Firewall Alert Rules

```bash
sudo nano /var/ossec/etc/rules/local_rules.xml
```

Add these rules inside the file (use rule IDs that don't conflict with existing rules):

```xml
<rule id="100300" level="5">
  <if_sid>4100</if_sid>
  <match>ALLOW</match>
  <description>Windows Firewall: Connection allowed</description>
  <group>windows,firewall,windows_firewall,connection_allowed,</group>
</rule>

<rule id="100301" level="10">
  <if_sid>4101</if_sid>
  <match>DROP</match>
  <description>Windows Firewall: Connection dropped</description>
  <group>windows,firewall,windows_firewall,connection_drop,</group>
</rule>
```

> ⚠️ **Important:** Check existing rule IDs in `local_rules.xml` before adding. If 100300/100301 are taken, use different IDs (e.g. 100310/100311).

### Step 3 — Restart Wazuh Manager

```bash
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager | grep -i "active\|error"
```

Expected: `Active: active (running)`

### Step 4 — Test Decoder with Wazuh Logtest

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste ALLOW test line:
```
2026-04-15 12:29:55 ALLOW UDP 192.168.0.59 142.251.151.119 61391 443 0 - - - - - - - SEND 17312
```

Paste DROP test line:
```
2026-04-15 12:14:57 DROP TCP 192.168.0.59 109.61.38.38 55496 80 0 - 0 0 0 - - - SEND 4900
```

Expected Phase 2 output:
```
name: 'windows-firewall' or 'windows-firewall-allow'
srcip: '192.168.0.59'    ✅
dstip: 'x.x.x.x'        ✅
action: 'ALLOW'/'DROP'   ✅
protocol: 'TCP'/'UDP'    ✅
```

Expected Phase 3 output:
```
ALLOW → Rule 100300 - Windows Firewall: Connection allowed   ✅
DROP  → Rule 100301 - Windows Firewall: Connection dropped   ✅
```

Press `Ctrl+C` to exit logtest.

---

## Part D — OpenSearch Verification Queries

Run these in **Wazuh Dashboard → Dev Tools** to confirm everything is working:

### Verify Sysmon Events

```json
GET wazuh-alerts-*/_count
{
  "query": {
    "bool": {
      "must": [
        { "match": { "agent.name": "YOUR-AGENT-NAME" }},
        { "match": { "data.win.system.channel": "Microsoft-Windows-Sysmon/Operational" }}
      ]
    }
  }
}
```

### Verify Firewall DROP Events

```json
GET wazuh-alerts-*/_count
{
  "query": {
    "bool": {
      "must": [
        { "match": { "agent.name": "YOUR-AGENT-NAME" }},
        { "match": { "rule.id": "100301" }}
      ]
    }
  }
}
```

### Verify Firewall ALLOW Events

```json
GET wazuh-alerts-*/_count
{
  "query": {
    "bool": {
      "must": [
        { "match": { "agent.name": "YOUR-AGENT-NAME" }},
        { "match": { "rule.id": "100300" }}
      ]
    }
  }
}
```

### Check All Event IDs Flowing from Agent

```json
GET wazuh-alerts-*/_search
{
  "size": 0,
  "query": {
    "match": { "agent.name": "YOUR-AGENT-NAME" }
  },
  "aggs": {
    "event_ids": {
      "terms": {
        "field": "data.win.system.eventID",
        "size": 50
      }
    }
  }
}
```

---


## Part E — Final Verification Checklist

| Check | Command | Expected Result |
|---|---|---|
| Sysmon service running | `Get-Service Sysmon64` | `Running` |
| Wazuh agent running | `Get-Service WazuhSvc` | `Running` |
| Sysmon in ossec.conf | `Select-String ... -Pattern "sysmon"` | Match found |
| Firewall log in ossec.conf | `Select-String ... -Pattern "pfirewall"` | Match found |
| Firewall logging enabled | `netsh advfirewall show allprofiles logging` | All `Enable` |
| Sysmon events in OpenSearch | Dev Tools count query | `count > 0` |
| Firewall DROP events in OpenSearch | Dev Tools count query | `count > 0` |
| IP fields extracted | Full document query | `data.srcip` and `data.dstip` populated |

---

## Troubleshooting

### Sysmon config fails to load
```powershell
# Verify config file exists and is valid
dir C:\Sysmon\sysmonconfig.xml
Get-Content C:\Sysmon\sysmonconfig.xml | Select-Object -First 5
```

### Wazuh agent not reading pfirewall.log
```powershell
# Check agent log for file reading confirmation
Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" | Select-String -Pattern "pfirewall|firewall" | Select-Object -Last 20
```

### Decoder syntax error on restart
```bash
# Test decoder syntax before restarting
sudo /var/ossec/bin/wazuh-analysisd -t 2>&1 | tail -20
```

### No alerts in OpenSearch despite logs flowing
```bash
# Check archives to confirm logs reaching manager
grep -i "pfirewall" /var/ossec/logs/archives/archives.log | tail -20

# Check what rules are firing
grep -A 3 "AGENT-NAME.*pfirewall" /var/ossec/logs/alerts/alerts.log | grep "Rule:" | sort | uniq -c
```

---

## Notes

- Rule IDs `100300` and `100301` are reserved for Windows Firewall in this setup. Adjust if conflicts exist.
- The SwiftOnSecurity Sysmon config intentionally limits network Event ID 3 to suspicious paths only — this is by design for high-fidelity detections.
- Windows Firewall logging is **passive** — it does not change any firewall rules or expose new attack surface.
- Always run `wazuh-logtest` after any decoder or rule changes before restarting the manager.
- Repeat Parts A and B for each new Windows endpoint. Parts C decoder/rules only need to be configured once on the Wazuh server.

---
