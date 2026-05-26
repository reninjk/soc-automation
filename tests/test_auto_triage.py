"""
Unit tests for alert-triage/auto_triage.py
Run: pytest tests/test_auto_triage.py -v
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'alert-triage'))

from auto_triage import (
    classify_severity,
    check_suppression,
    deduplicate,
    triage_alert,
)


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def p1_ransomware_alert():
    return {
        "id": "alert-001",
        "title": "Ransomware file encryption detected on DESKTOP-ABC",
        "host": "DESKTOP-ABC",
        "user": "john.doe",
        "source_ip": "192.168.1.50",
        "timestamp": "2026-01-15T10:00:00Z",
        "rule": "ransomware-file-encryption",
    }

@pytest.fixture
def p2_brute_force_alert():
    return {
        "id": "alert-002",
        "title": "Brute force login attempt from 185.220.101.5",
        "host": "DC-01",
        "user": "administrator",
        "source_ip": "185.220.101.5",
        "timestamp": "2026-01-15T10:05:00Z",
        "rule": "brute-force-login",
    }

@pytest.fixture
def p3_phishing_alert():
    return {
        "id": "alert-003",
        "title": "Phishing email detected from external sender",
        "host": "MAIL-GW",
        "user": "jane.smith",
        "source_ip": "203.0.113.1",
        "timestamp": "2026-01-15T10:10:00Z",
        "rule": "phishing-email",
    }

@pytest.fixture
def known_fp_alert():
    return {
        "id": "alert-004",
        "title": "Vulnerability scanner activity from Nessus",
        "host": "VULN-SCANNER",
        "user": "svc-nessus",
        "source_ip": "10.0.0.50",
        "timestamp": "2026-01-15T10:15:00Z",
        "rule": "network-scan",
    }


# ─── Severity Classification Tests ───────────────────────────────────────────

class TestClassifySeverity:

    def test_ransomware_classifies_as_p1(self, p1_ransomware_alert):
        assert classify_severity(p1_ransomware_alert) == "P1"

    def test_brute_force_classifies_as_p2(self, p2_brute_force_alert):
        assert classify_severity(p2_brute_force_alert) == "P2"

    def test_phishing_classifies_as_p3(self, p3_phishing_alert):
        assert classify_severity(p3_phishing_alert) == "P3"

    def test_unknown_alert_defaults_to_p3(self):
        alert = {"id": "x", "title": "some generic alert", "rule": "unknown"}
        result = classify_severity(alert)
        assert result in ("P3", "P4")

    def test_data_exfiltration_classifies_as_p1(self):
        alert = {
            "id": "alert-005",
            "title": "Large data exfiltration to external IP detected",
            "host": "WORKSTATION-01",
            "user": "user1",
            "rule": "data-exfiltration",
        }
        assert classify_severity(alert) == "P1"

    def test_severity_is_string(self, p1_ransomware_alert):
        result = classify_severity(p1_ransomware_alert)
        assert isinstance(result, str)
        assert result.startswith("P")


# ─── Suppression Tests ───────────────────────────────────────────────────────

class TestCheckSuppression:

    def test_known_fp_is_suppressed(self, known_fp_alert):
        result = check_suppression(known_fp_alert)
        assert result is not None  # Should return suppression reason

    def test_real_threat_not_suppressed(self, p1_ransomware_alert):
        result = check_suppression(p1_ransomware_alert)
        assert result is None

    def test_suppression_returns_string_reason(self, known_fp_alert):
        result = check_suppression(known_fp_alert)
        if result is not None:
            assert isinstance(result, str)
            assert len(result) > 0


# ─── Deduplication Tests ─────────────────────────────────────────────────────

class TestDeduplicate:

    def test_first_occurrence_not_duplicate(self, p1_ransomware_alert):
        assert deduplicate(p1_ransomware_alert, []) is False

    def test_identical_alert_within_window_is_duplicate(self, p1_ransomware_alert):
        recent = [p1_ransomware_alert.copy()]
        # Same host + rule = duplicate
        result = deduplicate(p1_ransomware_alert, recent)
        assert result is True

    def test_different_host_not_duplicate(self, p1_ransomware_alert):
        other = p1_ransomware_alert.copy()
        other["host"] = "DIFFERENT-HOST"
        other["id"] = "alert-999"
        assert deduplicate(other, [p1_ransomware_alert]) is False

    def test_empty_recent_list(self, p2_brute_force_alert):
        assert deduplicate(p2_brute_force_alert, []) is False


# ─── Full Triage Pipeline Tests ───────────────────────────────────────────────

class TestTriageAlert:

    def test_triage_returns_dict(self, p1_ransomware_alert):
        result = triage_alert(p1_ransomware_alert, [])
        assert isinstance(result, dict)

    def test_triage_includes_severity(self, p1_ransomware_alert):
        result = triage_alert(p1_ransomware_alert, [])
        assert "severity" in result

    def test_triage_includes_action(self, p1_ransomware_alert):
        result = triage_alert(p1_ransomware_alert, [])
        assert "action" in result

    def test_p1_routes_to_escalate(self, p1_ransomware_alert):
        result = triage_alert(p1_ransomware_alert, [])
        assert result.get("severity") == "P1"
        assert "escalate" in result.get("action", "").lower()

    def test_suppressed_alert_action_is_suppress(self, known_fp_alert):
        result = triage_alert(known_fp_alert, [])
        assert result.get("action", "").lower() in ("suppress", "suppressed")

    def test_duplicate_alert_is_deduped(self, p2_brute_force_alert):
        recent = [p2_brute_force_alert.copy()]
        result = triage_alert(p2_brute_force_alert, recent)
        assert "dedup" in result.get("action", "").lower()

    def test_triage_preserves_alert_id(self, p3_phishing_alert):
        result = triage_alert(p3_phishing_alert, [])
        assert result.get("id") == p3_phishing_alert["id"]
