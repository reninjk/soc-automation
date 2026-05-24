#!/usr/bin/env python3
"""
Automated Alert Triage Script
Receives alerts from SIEM webhook, classifies severity, deduplicates,
and routes to the correct analyst queue or auto-closes false positives.

Usage:
    # Run as webhook listener
    python auto_triage.py --port 8080

    # Triage a single alert from file
    python auto_triage.py --alert-file alert.json
"""

import argparse
import json
import logging
import os
import re
from datetime import datetime, timedelta
from typing import Optional

from utils.logger import setup_logger

logger = setup_logger(__name__)

# ─── Severity Classification Rules ────────────────────────────────────────────
SEVERITY_RULES = [
    # (pattern_in_alert_name, min_severity_score, assigned_severity)
    (r'ransomware|file.encrypt|shadow.copy.delet', 0,  'P1'),
    (r'data.exfil|large.upload|unusual.transfer',  0,  'P1'),
    (r'c2.commun|beaconing|known.malware',         0,  'P1'),
    (r'account.comprom|credential.dump|pass.spray', 0, 'P2'),
    (r'lateral.move|rdp.brute|psexec',             0,  'P2'),
    (r'malware.detect|trojan|backdoor',            50, 'P2'),
    (r'phishing|malicious.link|suspicious.attach', 0,  'P3'),
    (r'brute.force|failed.login',                  0,  'P3'),
    (r'policy.violation|usb.usage|shadow.it',      0,  'P4'),
]

# ─── False Positive Suppressions ──────────────────────────────────────────────
FP_SUPPRESSIONS = [
    {'rule': r'brute.force', 'condition': lambda a: a.get('source_ip') in KNOWN_SCANNERS},
    {'rule': r'large.upload', 'condition': lambda a: a.get('dest_ip') in KNOWN_BACKUP_SERVERS},
    {'rule': r'failed.login', 'condition': lambda a: int(a.get('count', 0)) < 5},
]

# These would be loaded from config in production
KNOWN_SCANNERS = set(os.getenv('KNOWN_SCANNER_IPS', '').split(','))
KNOWN_BACKUP_SERVERS = set(os.getenv('KNOWN_BACKUP_IPS', '').split(','))


# ─── Core Triage Logic ────────────────────────────────────────────────────────
def classify_severity(alert: dict) -> str:
    """Classify alert severity based on rule matching."""
    alert_name = alert.get('name', '').lower()
    alert_score = alert.get('risk_score', 0)

    for pattern, min_score, severity in SEVERITY_RULES:
        if re.search(pattern, alert_name) and alert_score >= min_score:
            return severity

    # Default based on risk score
    if alert_score >= 90:   return 'P1'
    if alert_score >= 70:   return 'P2'
    if alert_score >= 40:   return 'P3'
    return 'P4'


def check_suppression(alert: dict) -> Optional[str]:
    """Check if alert matches a known false positive pattern."""
    alert_name = alert.get('name', '').lower()
    for rule in FP_SUPPRESSIONS:
        if re.search(rule['rule'], alert_name):
            try:
                if rule['condition'](alert):
                    return f"Suppressed: matched rule '{rule['rule']}'"
            except Exception:
                pass
    return None


def deduplicate(alert: dict, recent_alerts: list) -> bool:
    """Check if a duplicate alert fired within the dedup window (15 min)."""
    window = datetime.utcnow() - timedelta(minutes=15)
    for prev in recent_alerts:
        if (prev['name'] == alert['name'] and
                prev['source_ip'] == alert.get('source_ip') and
                prev['timestamp'] > window.isoformat()):
            return True
    return False


def triage_alert(alert: dict, recent_alerts: list = None) -> dict:
    """Main triage function — classify, suppress, deduplicate."""
    recent_alerts = recent_alerts or []
    result = {
        'alert_id': alert.get('id', 'unknown'),
        'name': alert.get('name', ''),
        'timestamp': datetime.utcnow().isoformat(),
        'action': None,
        'severity': None,
        'reason': '',
    }

    # 1. Check suppression
    suppression_reason = check_suppression(alert)
    if suppression_reason:
        result['action'] = 'AUTO_CLOSE'
        result['reason'] = suppression_reason
        logger.info(f"Alert {result['alert_id']} auto-closed: {suppression_reason}")
        return result

    # 2. Check deduplication
    if deduplicate(alert, recent_alerts):
        result['action'] = 'DEDUPLICATE'
        result['reason'] = 'Duplicate alert within 15-minute window'
        logger.info(f"Alert {result['alert_id']} deduplicated")
        return result

    # 3. Classify severity
    result['severity'] = classify_severity(alert)

    # 4. Route to queue
    if result['severity'] == 'P1':
        result['action'] = 'ESCALATE_IMMEDIATELY'
        result['reason'] = f"Critical severity — auto-escalating to SOC Manager"
    elif result['severity'] == 'P2':
        result['action'] = 'ASSIGN_L2'
        result['reason'] = f"High severity — assigned to L2 analyst queue"
    else:
        result['action'] = 'ASSIGN_L1'
        result['reason'] = f"Severity {result['severity']} — assigned to L1 queue"

    logger.info(f"Alert {result['alert_id']} triaged: {result['severity']} → {result['action']}")
    return result


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description='Auto-triage SOC alerts')
    parser.add_argument('--alert-file', help='JSON file containing alert to triage')
    args = parser.parse_args()

    if args.alert_file:
        with open(args.alert_file) as f:
            alert = json.load(f)
        result = triage_alert(alert)
        print(json.dumps(result, indent=2))
    else:
        logger.error("Provide --alert-file to test triage")


if __name__ == '__main__':
    main()
