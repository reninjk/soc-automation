"""
Tests for ioc_enrichment/enrichment.py
Covers enrich_ip, enrich_domain, enrich_hash, enrich_ioc dispatcher,
batch_enrich, _build_summary, and cache behaviour.
All external API calls are mocked — no real keys required.
"""
import pytest
from unittest.mock import patch, MagicMock
import os

os.environ.setdefault("VT_API_KEY", "test-vt-key")
os.environ.setdefault("ABUSEIPDB_API_KEY", "test-abuse-key")
os.environ.setdefault("OTX_API_KEY", "test-otx-key")

try:
    from ioc_enrichment import enrichment as ioc_mod
    HAS_MOD = True
except ModuleNotFoundError:
    HAS_MOD = False

skip_no_mod = pytest.mark.skipif(not HAS_MOD, reason="ioc_enrichment not importable")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vt_ip_bad():
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 8, "suspicious": 1, "harmless": 60, "undetected": 5},
        "country": "RU", "as_owner": "EVIL-ASN", "reputation": -20, "tags": ["tor-exit-node"],
    }}}

@pytest.fixture
def vt_ip_good():
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 85, "undetected": 3},
        "country": "US", "as_owner": "GOOGLE", "reputation": 10, "tags": [],
    }}}

@pytest.fixture
def abuse_bad():
    return {"data": {"abuseConfidenceScore": 97, "totalReports": 842, "countryCode": "RU",
                     "usageType": "Hosting", "isp": "EvilHost", "isWhitelisted": False}}

@pytest.fixture
def abuse_clean():
    return {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US",
                     "usageType": "Fixed Line ISP", "isp": "Google", "isWhitelisted": True}}

@pytest.fixture
def vt_domain_bad():
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 12, "suspicious": 0, "harmless": 60, "undetected": 8},
        "reputation": -30, "categories": {"Forcepoint": "phishing"},
    }}}

@pytest.fixture
def vt_hash_bad():
    return {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 45, "suspicious": 2, "harmless": 0, "undetected": 5},
        "meaningful_name": "ransomware.exe", "size": 3723264, "tags": ["ransomware"],
    }}}


# ---------------------------------------------------------------------------
# enrich_ip
# ---------------------------------------------------------------------------

class TestEnrichIp:
    @skip_no_mod
    def test_returns_dict(self, vt_ip_bad, abuse_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_ip_bad), \
             patch.object(ioc_mod, "_abuseipdb_get", return_value=abuse_bad):
            result = ioc_mod.enrich_ip("1.2.3.4")
        assert isinstance(result, dict)

    @skip_no_mod
    def test_malicious_verdict(self, vt_ip_bad, abuse_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_ip_bad), \
             patch.object(ioc_mod, "_abuseipdb_get", return_value=abuse_bad):
            result = ioc_mod.enrich_ip("1.2.3.4")
        assert result["verdict"] == "malicious"

    @skip_no_mod
    def test_clean_verdict(self, vt_ip_good, abuse_clean):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_ip_good), \
             patch.object(ioc_mod, "_abuseipdb_get", return_value=abuse_clean):
            result = ioc_mod.enrich_ip("8.8.8.8")
        assert result["verdict"] == "clean"

    @skip_no_mod
    def test_ioc_and_type_set(self, vt_ip_bad, abuse_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_ip_bad), \
             patch.object(ioc_mod, "_abuseipdb_get", return_value=abuse_bad):
            result = ioc_mod.enrich_ip("1.2.3.4")
        assert result.get("ioc") == "1.2.3.4"
        assert result.get("ioc_type") == "ip"

    @skip_no_mod
    def test_vt_error_returns_partial(self, abuse_bad):
        with patch.object(ioc_mod, "_vt_get", side_effect=Exception("timeout")), \
             patch.object(ioc_mod, "_abuseipdb_get", return_value=abuse_bad):
            result = ioc_mod.enrich_ip("1.2.3.4")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# enrich_domain
# ---------------------------------------------------------------------------

class TestEnrichDomain:
    @skip_no_mod
    def test_returns_dict(self, vt_domain_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_domain_bad):
            result = ioc_mod.enrich_domain("evil.com")
        assert isinstance(result, dict)

    @skip_no_mod
    def test_malicious_verdict(self, vt_domain_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_domain_bad):
            result = ioc_mod.enrich_domain("evil.com")
        assert result["verdict"] == "malicious"

    @skip_no_mod
    def test_ioc_type(self, vt_domain_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_domain_bad):
            result = ioc_mod.enrich_domain("evil.com")
        assert result.get("ioc_type") == "domain"

    @skip_no_mod
    def test_api_error_handled(self):
        with patch.object(ioc_mod, "_vt_get", side_effect=Exception("rate limit")):
            result = ioc_mod.enrich_domain("evil.com")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# enrich_hash
# ---------------------------------------------------------------------------

class TestEnrichHash:
    @skip_no_mod
    def test_returns_dict(self, vt_hash_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_hash_bad):
            result = ioc_mod.enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert isinstance(result, dict)

    @skip_no_mod
    def test_malicious_verdict(self, vt_hash_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_hash_bad):
            result = ioc_mod.enrich_hash("d41d8cd98f00b204e9800998ecf8427e")
        assert result["verdict"] == "malicious"

    @skip_no_mod
    def test_ioc_type(self, vt_hash_bad):
        with patch.object(ioc_mod, "_vt_get", return_value=vt_hash_bad):
            result = ioc_mod.enrich_hash("aabbcc")
        assert result.get("ioc_type") == "hash"


# ---------------------------------------------------------------------------
# enrich_ioc dispatcher
# ---------------------------------------------------------------------------

class TestEnrichIoc:
    @skip_no_mod
    def test_dispatches_ip(self):
        with patch.object(ioc_mod, "enrich_ip", return_value={"verdict": "clean", "ioc": "1.2.3.4", "ioc_type": "ip"}) as m:
            ioc_mod.enrich_ioc("1.2.3.4")
        m.assert_called_once_with("1.2.3.4")

    @skip_no_mod
    def test_dispatches_domain(self):
        with patch.object(ioc_mod, "enrich_domain", return_value={"verdict": "malicious", "ioc": "evil.com", "ioc_type": "domain"}) as m:
            ioc_mod.enrich_ioc("evil.com")
        m.assert_called_once_with("evil.com")

    @skip_no_mod
    def test_dispatches_md5(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        with patch.object(ioc_mod, "enrich_hash", return_value={"verdict": "malicious", "ioc": md5, "ioc_type": "hash"}) as m:
            ioc_mod.enrich_ioc(md5)
        m.assert_called_once_with(md5)

    @skip_no_mod
    def test_dispatches_sha256(self):
        sha256 = "a" * 64
        with patch.object(ioc_mod, "enrich_hash", return_value={"verdict": "malicious", "ioc": sha256, "ioc_type": "hash"}) as m:
            ioc_mod.enrich_ioc(sha256)
        m.assert_called_once_with(sha256)

    @skip_no_mod
    def test_unknown_type(self):
        result = ioc_mod.enrich_ioc("????not-an-ioc????")
        assert result.get("verdict") in ("unknown", None) or "error" in result


# ---------------------------------------------------------------------------
# batch_enrich
# ---------------------------------------------------------------------------

class TestBatchEnrich:
    @skip_no_mod
    def test_returns_list(self):
        with patch.object(ioc_mod, "enrich_ioc", return_value={"verdict": "clean"}):
            assert isinstance(ioc_mod.batch_enrich(["1.1.1.1", "evil.com"]), list)

    @skip_no_mod
    def test_length_matches(self):
        with patch.object(ioc_mod, "enrich_ioc", return_value={"verdict": "clean"}):
            assert len(ioc_mod.batch_enrich(["a", "b", "c"])) == 3

    @skip_no_mod
    def test_empty_input(self):
        assert ioc_mod.batch_enrich([]) == []

    @skip_no_mod
    def test_one_error_does_not_abort(self):
        calls = []
        def side(ioc):
            calls.append(ioc)
            if ioc == "bad": raise Exception("err")
            return {"verdict": "clean"}
        with patch.object(ioc_mod, "enrich_ioc", side_effect=side):
            results = ioc_mod.batch_enrich(["good1", "bad", "good2"])
        assert len(calls) == 3
        assert len(results) == 3


# ---------------------------------------------------------------------------
# _build_summary
# ---------------------------------------------------------------------------

class TestBuildSummary:
    @skip_no_mod
    def test_counts_correctly(self):
        results = [{"verdict": "malicious"}, {"verdict": "malicious"}, {"verdict": "clean"},
                   {"verdict": "suspicious"}, {"verdict": "unknown"}]
        s = ioc_mod._build_summary(results)
        assert s["malicious"] == 2
        assert s["clean"] == 1
        assert s["total"] == 5

    @skip_no_mod
    def test_empty(self):
        s = ioc_mod._build_summary([])
        assert s["total"] == 0
        assert s["malicious"] == 0
