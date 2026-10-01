#!/usr/bin/env python3
import sys
import json
import requests
import docker

# Configuration
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3:latest"

try:
    docker_client = docker.from_env()
except Exception:
    docker_client = None

def isolate_container(container_name):
    """SOAR Integration: Disconnect container from network"""
    if not docker_client:
        return "Docker disconnected"
    try:
        container = docker_client.containers.get(container_name)
        networks = container.attrs['NetworkSettings']['Networks']
        for net_name in networks.keys():
            network = docker_client.networks.get(net_name)
            network.disconnect(container)
        return f"SUCCESS: {container_name} completely isolated."
    except Exception as e:
        return f"FAILED: {str(e)}"

def query_ai_copilot(wazuh_alert):
    """Generating an AI Playbook based on a Wazuh alert"""
    # Extracting key data from Wazuh JSON
    alert_id = wazuh_alert.get("id", "N/A")
    rule_desc = wazuh_alert.get("rule", {}).get("description", "Unknown Attack")
    rule_id = wazuh_alert.get("rule", {}).get("id", "Unknown")
    agent_name = wazuh_alert.get("agent", {}).get("name", "Unknown-Agent")
    
    # Extract request payload if available
    request_payload = wazuh_alert.get("data", {}).get("request", "No details")

    system_prompt = f"""
    You are an L3 Cyber Security Incident Response Expert monitoring a Wazuh SIEM platform.
    Analyze this real-time Wazuh Alert and output a strict JSON triage playbook matching this exact structure:
    {{
      "incident_id": "INC-WAZ-{alert_id}",
      "compliance_impact": "ISO27001 Control A.12.6.1 Vulnerability Management / NIST SP 800-53",
      "threat_analysis": "Explain what the attacker is doing based on: {rule_desc}",
      "nist_playbook": {{
        "containment": "Actionable step to stop blast radius",
        "eradication": "How to patch",
        "recovery": "How to restore"
      }},
      "recommended_action": "ISOLATE_CONTAINER" or "MONITOR"
    }}

    Wazuh Alert Metadata: Rule ID: {rule_id}, Desc: {rule_desc}, Agent: {agent_name}
    Raw Telemetry Payload: {request_payload}
    """

    payload = {"model": MODEL_NAME, "prompt": system_prompt, "stream": False, "format": "json"}
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=90)
        return json.loads(response.json()["response"])
    except Exception as e:
        return {"error": f"AI Copilot Offline: {str(e)}"}

if __name__ == "__main__":
    # Wazuh sends the alert by passing a file path as an argument.
    if len(sys.argv) < 2:
        sys.exit(1)
        
    alert_file_path = sys.argv[1]
    
    with open(alert_file_path, 'r') as f:
        wazuh_alert_json = json.load(f)
        
    # AI Engine trigger
    ai_playbook = query_ai_copilot(wazuh_alert_json)
    
    # Log the output for Wazuh Manager logs
    print(f"🤖 [AI COPILOT TRIAGE]: {json.dumps(ai_playbook, indent=2)}")
    
    # Action (SOAR Mitigation)
    if ai_playbook.get("recommended_action") == "ISOLATE_CONTAINER":
        #In the real world, we capture the target container from the logs; here, we are simulating that.
        status = isolate_container("enterprise_web_node")
        print(f"🛡️ [SOAR ACTION]: {status}")
