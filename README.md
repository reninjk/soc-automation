# ⚙️ SOC Automation

> Python and Bash automation scripts for alert triage, IOC enrichment, case management, and incident response workflows.

## 📁 Repository Structure

```
soc-automation/
├── alert-triage/
│   ├── auto_triage.py          # Auto-classify incoming alerts by severity
│   └── alert_dedup.py          # Deduplicate repeated alerts within time window
├── ioc-enrichment/
│   ├── enrich_ioc.py           # Enrich IPs/domains/hashes via threat intel APIs
│   └── virustotal_lookup.py    # VirusTotal API wrapper
├── case-management/
│   ├── create_ticket.py        # Auto-create IR tickets from SIEM alerts
│   └── escalate_case.py        # Escalation workflow automation
├── response-actions/
│   ├── isolate_host.py         # Trigger host isolation via EDR API
│   ├── block_ioc.py            # Push IOC blocks to firewall/proxy
│   └── reset_password.py       # Force account password reset via AD
├── reporting/
│   ├── weekly_metrics.py       # Generate weekly SOC metrics report
│   └── mttr_calculator.py      # Calculate MTTD/MTTR from ticket data
├── utils/
│   ├── config.py               # Centralized config management
│   ├── logger.py               # Structured logging helper
│   └── api_client.py           # Generic REST API client with retry logic
├── requirements.txt
└── .github/
    └── workflows/
        └── test-scripts.yml
```

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/reninjk/soc-automation.git
cd soc-automation

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env
# Edit .env with your API keys and endpoints
```

## 🔧 Environment Variables

```env
# SIEM
SIEM_URL=https://your-siem.example.com
SIEM_API_KEY=your_api_key

# Threat Intelligence
VT_API_KEY=your_virustotal_key
MISP_URL=https://your-misp.example.com
MISP_API_KEY=your_misp_key

# EDR
EDR_URL=https://your-edr.example.com
EDR_API_KEY=your_edr_key

# Case Management
TICKETING_URL=https://your-ticketing.example.com
TICKETING_API_KEY=your_ticket_key

# Notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx
```

## 📋 Script Reference

| Script | Purpose | Trigger |
|--------|---------|---------|
| `auto_triage.py` | Classify alert severity, assign to analyst | SIEM webhook |
| `enrich_ioc.py` | Multi-source IOC enrichment | New IOC observed |
| `create_ticket.py` | Open IR ticket with context | P1/P2 alert |
| `isolate_host.py` | Isolate host via EDR | P1 malware alert |
| `block_ioc.py` | Block IP/domain at firewall | Confirmed malicious |
| `weekly_metrics.py` | SOC KPI report | Every Monday 08:00 |

## 🧪 Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Lint
flake8 . --max-line-length=120
```

## 🔗 Related Repositories

- [soc-detection-rules](../soc-detection-rules) — Detection rules that trigger these automations
- [soc-incident-response](../soc-incident-response) — IR playbooks executed by these scripts
- [soc-compliance-reporting](../soc-compliance-reporting) — Metrics reports generated here

---
*Maintained by the SOC Manager | All scripts require peer review before production deployment*
