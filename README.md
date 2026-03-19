## AI-POWERED SOC AUTOMATION BY INTEGRATING WAZUH WITH N8N
<img width="896" height="650" alt="image" src="https://github.com/user-attachments/assets/3a964639-85f5-467c-a6dd-cc09696bac7d" /> 


<br/>The Workflow: <br/>
<br/><img width="1703" height="426" alt="image" src="https://github.com/user-attachments/assets/2607f37c-f024-43be-b3da-7e1d02b9cddf" /><br/>

#### Introduction

This project presents an automated AI-SOC reporting workflow built by integrating Wazuh, n8n, VirusTotal enrichment,
and an AI agent. The workflow is designed to collect security alerts from the Wazuh Indexer, process and enrich the alert data,
generate AI-driven summaries, and finally deliver the results through email in a structured report format. Its main purpose is to
reduce manual effort in SOC operations, improve threat visibility, and support faster incident reporting with the help of automation
and artificial intelligence.

#### Brief Overview

- Scheduled execution: The workflow starts automatically at a defined time using the Schedule Trigger node.
- Alert collection from Wazuh: Security events are retrieved from the Wazuh Indexer through an HTTP request.
- Data preparation: The raw alert data is cleaned and organized using JavaScript processing nodes such as Prepare Rows.js and Split Rows.js.
- Threat intelligence enrichment: Each relevant indicator is checked against VirusTotal using an HTTP request to gather additional threat context.
- Data merging and formatting: The enriched and original alert data are combined and reformatted for further analysis.
- AI-based SOC analysis: The processed dataset is passed to the AI-SOC Agent, which uses the Google Gemini Chat Model to generate a concise security summary and insights.
- Report generation: The summarized content is transformed into an HTML-based report format.
- Email delivery: The final SOC report is automatically sent to the intended recipient through the Send an Email node.
- Operational benefit: This workflow helps automate repetitive SOC reporting tasks, making incident monitoring and communication more efficient.

#### Prerequisite
- Azure account and Ubuntu VM
- Wazuh installation setup
- n8n installation setup
- Wazuh API / Indexer access
- VirusTotal API key
- AI agent / LLM access
- Email SMTP configuration
- Internet and network access
- Required dependencies and permissions

#### Workflow Orchestration
- Cloud infrastructure deployment on Microsoft Azure
- Secure server and network configuration
- Wazuh SIEM setup for alert collection
- n8n workflow orchestration
- Alert retrieval and processing
- Threat enrichment and AI-based analysis
- Automated SOC report generation
- Email-based report dissemination
- Workflow validation and maintenance

#### Architecture
```
Cloud Layer
└── Microsoft Azure
    └── Azure VM (Ubuntu)

  Security Monitoring Layer
  └── Wazuh
      ├── Manager
      ├── Indexer
      ├── Dashboard
      └── Agents / Monitored Endpoints

  Automation and AI Layer
  └── n8n
      ├── Scheduled Workflow Trigger
      ├── Alert Collection from Wazuh
      ├── Data Processing
      ├── Threat Intelligence Enrichment
      ├── AI-Based Alert Analysis
      └── SOC Report Preparation

  Output Layer
  └── Reporting
      ├── HTML / Structured Report
      └── Email Delivery to SOC Team
```  
#### Why It Is Necessary to Use n8n with Wazuh

Using n8n with Wazuh is necessary because Wazuh mainly focuses on security monitoring, 
log collection, detection, and alert generation, while n8n provides the automation and orchestration layer needed to turn 
those alerts into actionable workflows. On its own, Wazuh can detect suspicious activities and display them in the dashboard, 
but many SOC processes still require manual work such as extracting alert details, enriching indicators, generating summaries, 
formatting reports, and sending notifications. By integrating n8n, these repetitive tasks can be automated in a structured workflow, 
allowing Wazuh alerts to be processed, enriched, analyzed by AI agents, and delivered as readable SOC reports without requiring constant 
manual intervention.

#### Benefits for SOC Analysts
- Reduces manual workload by automating repetitive alert-handling tasks
- Saves investigation time through faster data collection and processing
- Improves alert visibility by transforming raw logs into structured information
- Supports quicker triage with automated enrichment and AI-generated summaries
- Enhances reporting efficiency by generating ready-to-share SOC reports automatically
- Minimizes human error during manual copy-paste, formatting, and data handling
- Provides better context by combining Wazuh alerts with external threat intelligence
- Helps analysts focus on critical incidents instead of spending time on repetitive operational steps
- Enables consistent workflows for daily, weekly, or scheduled security reporting
- Strengthens decision-making through summarized and easier-to-understand security insights

### Step-by-step Implementation 
Step 1: Configure Scheduled Trigger
- Added a Schedule Trigger node in n8n.
- Defined the execution time and frequency based on reporting needs.
- Set the workflow to run automatically at fixed intervals.
- Connected the trigger to the next node to begin alert retrieval.

Key Role: \
To automatically initiate the Wazuh AI-SOC reporting workflow on a scheduled basis without manual intervention.


<img width="1856" height="739" alt="image" src="https://github.com/user-attachments/assets/fedc3317-7a90-4b24-9fe2-421b8bc38d63" /> 

 Step 2: Configure Wazuh Indexer HTTP Request
- Added an HTTP Request node in n8n to connect with the Wazuh Indexer.
- Set the request method to POST for querying alert data. Mode: Fixed
- Configured the Wazuh Indexer search URL to retrieve security events from the alert index. Mode: Fixed
- Applied Basic Authentication credentials to allow secure access to the indexer. Mode: Fixed
- Enabled the request body option to send the alert query in JSON format. Mode: Expression.
- The body content type : Json (fixed) and Specify body: using Json(fixed)
- Executed the node to verify successful connection and alert retrieval from Wazuh.

Key Role: \
To fetch security alerts and event data from the Wazuh Indexer so they can be processed in the next stages of the AI-SOC workflow.

<img width="1854" height="749" alt="image" src="https://github.com/user-attachments/assets/172298cb-e943-433f-9dab-3439ec499505" />

<details>
  <summary><strong>View JSON Body Input</strong></summary>

```json

{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-7d/d",
              "lte": "now"
            }
          }
        },
        {
          "exists": {
            "field": "data.srcip"
          }
        }
      ]
    }
  },
  "aggs": {
    "top_source_ips": {
      "terms": {
        "field": "data.srcip",
        "size": 10,
        "order": {
          "max_severity": "desc"
        }
      },
      "aggs": {
        "max_severity": {
          "max": {
            "field": "rule.level"
          }
        },
        "first_seen": {
          "min": {
            "field": "@timestamp"
          }
        },
        "top_rule": {
          "terms": {
            "field": "rule.description.keyword",
            "size": 1
          }
        },
        "top_agent": {
          "terms": {
            "field": "agent.name.keyword",
            "size": 1
          }
        },
        "sample_log": {
          "top_hits": {
            "size": 1,
            "_source": {
              "includes": [
                "@timestamp",
                "rule.level",
                "rule.description",
                "agent.name",
                "data.srcip",
                "data.dstip",
                "full_log"
              ]
            },
            "sort": [
              {
                "rule.level": {
                  "order": "desc"
                }
              }
            ]
          }
        }
      }
    }
  }
}
    
```
</details>

