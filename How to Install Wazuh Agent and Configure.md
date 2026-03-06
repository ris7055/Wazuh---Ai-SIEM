## Important Concept:
Wazuh works like this:

`Linux Server (Agent)  →  Wazuh Manager (on Azure VM)  →  Wazuh Dashboard`

So for Ubuntu machine must install a Wazuh Agent.

## How to Connect Ubuntu Logs to Wazuh-Server: (Azure VM)

### Step 1 — Open Required Azure Ports

Check the Azure VM first - Goto:
`Azure Portal → VM → Networking → Inbound Rules`

Make sure these ports are allowed:

| Port      | Purpose                       |
| --------- | ----------------------------- |
| 1514 TCP  | Agent → Manager communication |
| 1515 TCP  | Agent registration            |
| 55000 TCP | (Optional) Wazuh API          |  

⚠️ For testing, you can allow from “Any”\
🔒 For production, restrict to your Ubuntu server IP.

2️⃣ Configure Azure Network Security Group (NSG)

### Open Azure Portal → Virtual Machine → Networking → Network Security Group

Add inbound rule for Agent → Manager communication:

| Field	    | Value                         |
| --------- | ----------------------------- |
| Source    | Any |
| Source Port  | *            |
| Destination	  | Any         | 
| Destination Port	  | 1514        | 
| Protocol	  | TCP          | 
| Action	  | Allow          | 
| Priority	  | 310          | 
| Name	  | Allow-Wazuh-Agent  | 

Add inbound rule for Agent registration:

| Field	    | Value                         |
| --------- | ----------------------------- |
| Source    | Any |
| Source Port  | *            |
| Destination	  | Any         | 
| Destination Port	  | 1515        | 
| Protocol	  | TCP          | 
| Action	  | Allow          | 
| Priority	  | 320          | 
| Name	  | Allow-Wazuh-Agent  | 

**This allows agents to send logs to the manager.**

Verify Wazuh Manager Listening Port

Login to the Azure VM terminal.

Run:

`sudo ss -tulnp | grep 1514`

Expected result:

tcp LISTEN 0 128 0.0.0.0:1514 \
**This confirms the manager is ready to receive agent logs.**


## Steps to Install Wazuh Agent on Ubuntu Server

## Step1: On the Ubuntu machine (not Azure VM)

`curl -sO https://packages.wazuh.com/4.x/wazuh-agent_4.x.x-1_amd64.deb`

(Replace version with latest shown in dashboard “Add Agent” section.)

Or easier:

`Go to Wazuh Dashboard → Agents → Add Agent`

Select:\
OS: Linux\
Server IP: Your Azure public IP\
It will generate the exact install command for you.

### Step 2 — Register the Agent
On Ubuntu machine:

`sudo nano /var/ossec/etc/ossec.conf`

Find:\
`<client>
  <server>
    <address>MANAGER_IP</address>
  </server>
</client>
`

Replace with:

`<address>YOUR_AZURE_VM_PUBLIC_IP</address>`\
Save and exit.

### Step 3 — Start Agent

`sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent`

Check status:

`sudo systemctl status wazuh-agent`

On Wazuh server:

`sudo /var/ossec/bin/manage_agents`\
Add agent manually if it doesn't auto-register.

Step 4 — Confirm It Appears in Dashboard

Go to:\
Dashboard → Agents

There should appear:
```
Agent Name
OS: Linux
Status: Active
```
## Steps to Install Wazuh Agent on Windows:

### Step1: Download Wazuh agent from:

https://packages.wazuh.com/4.x/windows/

Example file:

`wazuh-agent-4.x.x.msi`

Install normally.

Default path:

`C:\Program Files (x86)\ossec-agent`

### Step2: Configure Agent Authentication (Windows PowerShell ver 7)

Open PowerShell as Administrator

Run:

`& "C:\Program Files (x86)\ossec-agent\agent-auth.exe" -m <wazuh-server-ip>`

Example output:
```
INFO: Started
INFO: Requesting key from server
INFO: Valid key received
```
This registers the Windows agent with the Wazuh manager.

### Step3: Configure Agent Connection

Edit the configuration file:

'C:\Program Files (x86)\ossec-agent\ossec.conf'

Find this section:
```
<server>
  <address>20.17.161.110</address>
  <port>1514</port>
  <protocol>tcp</protocol>
</server>
```
**Important Note:** \
protocol = tcp \
This must match the Wazuh manager.

### Step4:Restart Wazuh Agent

In PowerShell:

`Restart-Service Wazuh`

Verify Agent Logs

Check logs:

`Get-Content "C:\Program Files (x86)\ossec-agent\ossec.log" -Tail 20`

Expected messages:
```
Connected to server
Sending keepalive
File integrity monitoring started
```
Verify Connection on Wazuh Manager

On Azure VM run:
`sudo /var/ossec/bin/agent_control -l`

Check agents with names: example
`sudo grep "Lenovo-W11" /var/ossec/logs/alerts/alerts.log`

Expected output:
`ID: 001, Name: Lenovo-W11, IP: xxx.xxx.xxx.xxx, Active`

By default, Wazuh agent monitors:
```
* /var/log/auth.log
* /var/log/syslog
* /var/log/messages
* SSH login attempts
* sudo usage
* privilege escalation
* file integrity changes
```
### If want to add custom Log:

Example:\
Suppose your logs are stored at:

`/home/app/logs/app.log`

Edit:

`sudo nano /var/ossec/etc/ossec.conf`

Add inside <localfile>:\
`
<localfile>
  <log_format>syslog</log_format>
  <location>/home/app/logs/app.log</location>
</localfile>
`
Restart agent:

`sudo systemctl restart wazuh-agent`
