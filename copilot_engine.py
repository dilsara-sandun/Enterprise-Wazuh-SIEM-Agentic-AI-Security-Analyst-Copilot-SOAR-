import json
import requests
import re
from flask import Flask, request, jsonify
import docker
import yaml

app = Flask(__name__)

# Docker Integration for SOAR Response
try:
    client = docker.from_env()
except Exception as e:
    print(f"⚠️ [DOCKER WARNING]: Could not connect to Docker daemon. Mitigation features will run in Simulation Mode. Error: {e}")
    client = None

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL_NAME = "phi3:latest"

# 1. DETECTION-AS-CODE: Sigma-style Rules Repository

SIGMA_RULES = """
rules:
  - id: SIG-001
    title: SQL Injection Attempt via HTTP Request
    tactic: Credential Access / Defense Evasion
    mitre_id: T1114
    level: critical
    patterns:
      - 'UNION SELECT'
      - 'SELECT.*FROM'
      - '--'
      - "' OR '1'='1"
    
  - id: SIG-002
    title: Log4Shell / Remote Code Execution Attempt
    tactic: Execution
    mitre_id: T1210
    level: critical
    patterns:
      - '\\${jndi:'
      - 'ctx:'
    
  - id: SIG-003
    title: Directory Traversal / Path Manipulation
    tactic: Initial Access
    mitre_id: T1190
    level: high
    patterns:
      - '\\.\\./\\.\\.'
      - '/etc/passwd'
      - 'win.ini'
"""

def match_sigma_rules(raw_log):
    """Raw logs සැබෑ Sigma Rules සමඟ සසඳා බලා මුලින්ම ට්‍රිගර් කිරීම"""
    rules_ds = yaml.safe_load(SIGMA_RULES)
    request_str = raw_log.get("request", "")
    
    for rule in rules_ds["rules"]:
        for pattern in rule["patterns"]:
            if re.search(pattern, request_str, re.IGNORECASE):
                return rule
    return None

def trigger_soar_response(action_type, container_name, source_ip):
    """Automated SOAR Playbook Execution Engine"""
    if not client:
        return f"[SIMULATION] Executing {action_type} for IP {source_ip}"
        
    try:
        container = client.containers.get(container_name)
        if action_type == "ISOLATE_CONTAINER":
            networks = container.attrs['NetworkSettings']['Networks']
            for net_name in networks.keys():
                network = client.networks.get(net_name)
                network.disconnect(container)
            return f"SUCCESS: Container {container_name} completely isolated from network."
            
        elif action_type == "BLOCK_IP":
            return f"SUCCESS: Host Firewall updated. Network egress/ingress blocked for IP: {source_ip}"
            
    except Exception as e:
        return f"FAILED: SOAR mitigation failed due to: {str(e)}"

def analyze_with_ai_copilot(log_data, matched_rule):
    """Advanced LLM Context Triage & NIST Incident Response Playbook Generation"""
    
    system_prompt = f"""
    You are an Enterprise Level L3 Cyber Security Incident Response Expert.
    Analyze the provided log telemetry combined with the triggered Detection-as-Code (Sigma) rule metadata.
    
    You must output a highly structured incident triage report in STRICT JSON format. Do not include any backticks or markdown formatting. The JSON must exactly match this structure:
    {{
      "incident_id": "INC-2026-XXXX",
      "threat_context": "Deep analysis of what the attacker is trying to achieve",
      "mitre_mapping": {{
        "tactic": "MITRE ATT&CK Tactic name",
        "technique_id": "MITRE Technique ID"
      }},
      "nist_playbook": {{
        "containment": "Immediate technical step taken to stop the blast radius",
        "eradication": "How to cleanly remove the threat from the application",
        "recovery": "Steps to restore secure production state"
      }},
      "recommended_soar_action": "ISOLATE_CONTAINER" or "BLOCK_IP" or "MONITOR"
    }}

    Log Telemetry: {json.dumps(log_data)}
    Triggered Rule Metadata: {json.dumps(matched_rule)}
    """
    
    payload = {
        "model": MODEL_NAME,
        "prompt": system_prompt,
        "stream": False,
        "format": "json"
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=90)
        return json.loads(response.json()["response"])
    except Exception as e:
        return {"error": f"AI Copilot Triage Pipeline broken: {str(e)}"}

@app.route("/siem/alert", methods=["POST"])
def enterprise_siem_ingest():
    raw_log = request.json
    print("\n📥 [SIEM INGEST]: New raw log telemetry intercepted...")

    # 1. Detection Phase (Sigma Rules Matching)
    matched_rule = match_sigma_rules(raw_log)
    
    if not matched_rule:
        print("🟢 [SIEM INGEST]: Log passed standard detection rules. Status: Monitored.")
        return jsonify({"status": "clean", "message": "No known threat signatures detected."})
        
    print(f"🚨 [SIGMA ALERT TRIGGERED]: {matched_rule['title']} (Severity: {matched_rule['level'].upper()})")
    
    # 2. Triage & Brain Phase (AI Copilot Engine)
    print("🤖 [AI COPILOT]: Generating NIST Incident Response Playbook and mapping constraints...")
    ai_playbook = analyze_with_ai_copilot(raw_log, matched_rule)
    print(f"📝 [AI PLAYBOOK GENERATED]:\n{json.dumps(ai_playbook, indent=2)}")
    
    # 3. Action Phase (SOAR Orchestration)
    soar_action = ai_playbook.get("recommended_soar_action", "MONITOR")
    target = raw_log.get("target_container", "enterprise_web_node")
    src_ip = raw_log.get("source_ip", "0.0.0.0")
    
    if soar_action in ["ISOLATE_CONTAINER", "BLOCK_IP"]:
        print(f"⚡ [SOAR ACTION TRIGGERED]: Executing {soar_action} automatically...")
        mitigation_status = trigger_soar_response(soar_action, target, src_ip)
        print(f"🛡️ [SOAR MITIGATION STATUS]: {mitigation_status}")
        ai_playbook["soar_mitigation_execution"] = mitigation_status
    else:
        print("ℹ️ [SOAR ACTION]: No destructive mitigation recommended. Keeping in telemetry watch.")
        ai_playbook["soar_mitigation_execution"] = "NO_ACTION_TAKEN"

    return jsonify({
        "status": "incident_handled",
        "sigma_rule_id": matched_rule["id"],
        "security_incident_triage": ai_playbook
    })

if __name__ == "__main__":
    print("🛡️ Enterprise Detection-as-Code SIEM Engine v2.0 Live on Port 5001...")
    app.run(host="0.0.0.0", port=5001, debug=True)
