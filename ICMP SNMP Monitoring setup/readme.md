
### Testing Pipeline implemented:

```
Zabbix detects unreachable host (every 1 min)
        ↓ AUTOMATIC
Send-to-Wazuh action fires
        ↓ AUTOMATIC  
Wazuh-Direct webhook → socat proxy → Wazuh API
        ↓ AUTOMATIC
Custom decoder + rule 100703 fires
        ↓ AUTOMATIC
Preview logs in Opensearch or Wazuh Dashboard
```

### Recommended Pipeline
```

Zabbix deployed in seperate VM
        ↓ AUTOMATIC
Install Wazuh-Agent on zabbix server
        ↓ (collect logs from a directory)
Send-to-Wazuh action fires
        ↓ AUTOMATIC  
Custom decoder + rule 100703 fires
        ↓ AUTOMATIC
Preview logs in Opensearch or Wazuh Dashboard
```
