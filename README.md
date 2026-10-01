# Enterprise Wazuh SIEM & Agentic AI Security Analyst Copilot (SOAR)

An enterprise-grade Security Operations Center (SOC) engineering project that integrates an open-source SIEM (**Wazuh**) with a localized, resource-optimized Large Language Model (**Ollama Phi-3**) via a custom Python automation daemon. This implementation enables real-time **Detection-as-Code (Sigma rules criteria)**, contextual threat enrichment, **NIST SP 800-61 aligned incident response playbook automation**, and automated **SOAR infrastructure mitigation** without any external cloud API dependency or sensitive data exfiltration.

---

## 🏛️ System Architecture Workflow

[ Target Web Server (Docker) ]
│  (SQLi / RCE Cyber Attack Telemetry)
▼
[ Wazuh SIEM Manager (Detection-as-Code Engine) ]
│  (Triggers Level 10 Alert JSON)
▼
[ Custom Python Integration Daemon ]
│  (Structured Pipeline Ingestion)
▼
[ Local AI Copilot (Ollama Phi-3 3B LLM) ] ──► Generates NIST SP 800-61 Playbooks
│                                 & Maps to ISO 27001 Controls
▼ (If Recommended Action == ISOLATE_CONTAINER)
[ SOAR Mitigation Engine (Docker API) ] ────► Dynamic Network Segment Isolation

---

## 🔥 Key Technical Capabilities

- **Detection-as-Code Integration:** Leverages enterprise signature alerting logic managed natively through Wazuh's decoders and rule-sets (e.g., Rule 31103 for Web Application SQL Injection attempts).
- **Localized Threat Intel & Triage:** Bypasses costly cloud API keys by routing live internal SIEM JSON alert streams to a resource-friendly, local 2.2GB **Phi-3 (3B)** model, mitigating data privacy leakage in highly regulated financial environments.
- **Automated NIST SP 800-61 Playbooks:** Contextually transforms raw log telemetry into a strict JSON-formatted incident triage matrix encompassing programmatic steps for *Containment*, *Eradication*, and *Recovery*.
- **Closed-Loop SOAR Orchestration:** The Python daemon parses the model's structured payload and interfaces with the underlying Docker socket to immediately disconnect compromised containers from virtual networks, preventing threat lateral movement.
- **Compliance Mapping:** Programmatically maps incoming log indicators to specific institutional security baselines such as **ISO 27001 Control A.12.6.1** (Technical Vulnerability Management) and **NIST SP 800-53 SI-10** (Information Input Validation).

---

## 🛠️ Project Repository Structure

```text
├── custom-ai-copilot.py    # Core SIEM Integration, AI Prompt Pipeline & SOAR Engine
├── docker-compose.yml      # Multi-container sandboxed target enterprise server architecture
├── .gitignore              # Technical exclusions keeping repos free from binary blobs & logs
└── README.md               # Advanced deployment architecture manual
```

---

## 🚀 Live Pipeline Triage Output (Verified Proof-of-Concept)

When a web alert payload indicating a critical signature hit (`UNION SELECT`) is evaluated, the pipeline processes the triage matrix natively within the container environment:

```json
🤖 [AI COPILOT TRIAGE]: {
  "incident_id": "INC-WAZ-1625139400.92341",
  "compliance_impact": "ISO27001 Control A.12.6.1 Vulnerability Management / NIST SP 800-53 SI-10 Information Input Validation",
  "threat_analysis": "The attacker is attempting an SQL Injection attack by appending a 'UNION SELECT' payload to access application database credentials from the users table.",
  "nist_playbook": {
    "containment": "Isolate the compromised node from the application network layer immediately.",
    "eradication": "Implement parameterized queries or input validation regex filters on the web application side to safely reject UNION patterns.",
    "recovery": "Audit backend database user tables for modification logs and safely restore container ingress traffic."
  },
  "recommended_action": "ISOLATE_CONTAINER"
}
🛡️ [SOAR ACTION]: SUCCESS: enterprise_web_node completely isolated.
```

---

## 📊 Deployment & Integration Blueprint

### 1. Register Daemon with Wazuh Core
The Python script is compiled into the host integration directory of the Wazuh Manager deployment container path:
```bash
docker cp custom-ai-copilot.py single-node-wazuh.manager-1:/var/ossec/integrations/
docker exec -it single-node-wazuh.manager-1 chmod +x /var/ossec/integrations/custom-ai-copilot.py
```

### 2. Configure Dynamic Ingestion Pipeline
Appended the following routing telemetry configurations inside the global configuration manifest `/var/ossec/etc/ossec.conf`:
```xml
<integration>
  <name>custom-ai-copilot.py</name>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

---

## 💼 UK Professional CV / Resume Bullet Points

*Add this directly to your professional profile or experience catalog:*

- **Cybersecurity Architecture & DevSecOps:** Designed and engineered a fully virtualized Enterprise Security Operations Center (SOC) lab utilizing **Wazuh SIEM** and **Docker Desktop**, establishing secure containerized logging planes.
- **Agentic AI & LLM Engineering:** Built an asynchronous integration daemon in Python that channels critical JSON alert telemetry to a localized **Ollama Phi-3 (3B)** model, mitigating alert fatigue through context-aware triage automation.
- **SOAR Infrastructure Automation:** Integrated localized LLM decisions with container-runtime control APIs, establishing closed-loop incident handling capabilities that automatically execute **NIST SP 800-61 containment protocols** (dynamic network micro-segmentation/isolation) upon active exploitation indicators.
- **Compliance & Risk Advisory:** Implemented automated ingestion templates translating technical threat payloads directly into institutional governance requirements spanning **ISO 27001 Control Frameworks** and **NIST SP 800-53 baselines**.