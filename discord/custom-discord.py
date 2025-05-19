#!/usr/bin/env python3

import sys
import requests
import json

# Read configuration
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# Read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# Basic info
rule = alert_json.get("rule", {})
alert_level = rule.get("level", 0)
agent_ = alert_json.get("agent", {}).get("name", "agentless")
#agent_ip = alert_json.get("agent", {}).get("ip")
#agent_ip = agent.get("ip") or alert_json.get("agent", {}).get("ip", "N/A")
agent_ip = alert_json.get("agent", {}).get("ip") or "NA"
#failed_username = alert_json.get("data", {}).get("eventdata", {}).get("targetUserName") or "NA"
failed_username = alert_json.get("data", {}).get("win", {}).get("eventdata", {}).get("targetUserName", "NA")


# Color coding
if alert_level < 5:
    color = 5763719
elif 5 <= alert_level <= 7:
    color = 16705372
else:
    color = 15548997

# Start building fields
fields = [
    {"name": "Rule ID", "value": str(rule.get("id", "N/A")), "inline": True},
    {"name": "Level", "value": str(alert_level), "inline": True},
    {"name": "Agent Name", "value": agent_, "inline": True},
    {"name": "Agent IP", "value": agent_ip, "inline": False},
    {"name": "Failed Username", "value": failed_username, "inline": False},
    {"name": "Description", "value": rule.get("description", "N/A"), "inline": False},
    {"name": "Timestamp", "value": alert_json.get("timestamp", "N/A"), "inline": False}
]

# Dynamically add key fields from data
data = alert_json.get("data", {})
key_fields = ["srcip", "srcport", "dstip", "dstport", "srccountry", "dstcountry",
              "action", "app", "url", "user", "protocol", "eventtype", "msg","dstuser","status","mitre.tactic"]

for key in key_fields:
    if key in data:
        fields.append({
            "name": key.replace("_", " ").title(),
            "value": str(data[key]),
            "inline": True if len(str(data[key])) < 50 else False
        })

# Add full_log (truncated for Discord limits)
full_log = alert_json.get("full_log", "")
if full_log:
    fields.append({
        "name": "Full Log",
        "value": f"{full_log}",
        "inline": False
    })

# Build payload
payload = json.dumps({
    "content": "",
    "embeds": [
        {
            "title": f"Wazuh Alert - Rule {rule.get('id', 'N/A')}",
            "color": color,
            "fields": fields
        }
    ]
})

# Send to Discord
requests.post(hook_url, data=payload, headers={"content-type": "application/json"})
sys.exit(0)
