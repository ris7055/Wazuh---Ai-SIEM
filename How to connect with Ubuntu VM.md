## Important Concept:
Wazuh works like this:

`Linux Server (Agent)  →  Wazuh Manager (on Azure VM)  →  Wazuh Dashboard`

So for Ubuntu machine must install a Wazuh Agent.

## How to Connect Ubuntu Logs to Wazuh:

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


### Step 2 — Install Wazuh Agent on Ubuntu Server
On the Ubuntu machine (not Azure VM):

`curl -sO https://packages.wazuh.com/4.x/wazuh-agent_4.x.x-1_amd64.deb`

(Replace version with latest shown in dashboard “Add Agent” section.)

Or easier:

`Go to Wazuh Dashboard → Agents → Add Agent`

Select:\
OS: Linux\
Server IP: Your Azure public IP\
It will generate the exact install command for you.

### Step 3 — Register the Agent
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

### Step 4 — Start Agent

`sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent`

Check status:

`sudo systemctl status wazuh-agent
Step 5 — Approve Agent (If Needed)`

On Wazuh server:

`sudo /var/ossec/bin/manage_agents`\
Add agent manually if it doesn't auto-register.

Step 6 — Confirm It Appears in Dashboard

Go to:\
Dashboard → Agents

There should appear:
```
Agent Name
OS: Linux
Status: Active
```

By default, Wazuh monitors:

* /var/log/auth.log
* /var/log/syslog
* /var/log/messages
* SSH login attempts
* sudo usage
* privilege escalation
* file integrity changes

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
