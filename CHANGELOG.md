# Changelog

All notable changes to **soc-automation** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Planned
- Webhook listener mode for `auto_triage.py` (HTTP server)
- SOAR integration stub for case-management auto-ticketing
- Expanded unit tests for `reporting/weekly_metrics.py`

---

## [1.3.0] — 2026-10-25

### Added
- `utils/` package — shared `setup_logger` (JSON + text) and `APIClient` (retries, rate limiting)
- `.gitignore` — prevents accidental commit of `.env` and build artefacts
- `CHANGELOG.md` — this file

### Fixed
- `auto_triage.py` and `enrich_ioc.py` broken imports resolved by adding `utils/` module

---

## [1.2.0] — 2026-08-14

### Added
- CodeQL security scanning workflow (`.github/workflows/codeql.yml`)
- Dependabot configuration for pip + GitHub Actions (weekly)
- shields.io badges (License · Last Commit · Issues · CI · CodeQL) in README

### Changed
- `.env.example` — replaced vendor-specific variable names with generic category names (SIEM_, EDR_, FIREWALL_) to avoid tool-stack disclosure

---

## [1.1.0] — 2026-08-01

### Added
- `.github/ISSUE_TEMPLATE/bug_report.md` and `feature_request.md`
- `.github/pull_request_template.md`
- MIT `LICENSE`
- `SECURITY.md` — responsible disclosure policy
- `CONTRIBUTING.md` — contribution guidelines

---

## [1.0.0] — 2026-05-24

### Added
- `alert-triage/auto_triage.py` — severity classification, false-positive suppression, deduplication
- `ioc-enrichment/enrich_ioc.py` — VirusTotal + AbuseIPDB enrichment with aggregated verdict
- `reporting/weekly_metrics.py` — SOC KPI metrics report generator
- `dashboard/soc-dashboard.html` — static HTML SOC metrics dashboard
- `tests/test_auto_triage.py` and `test_enrich_ioc.py` — pytest unit test suite
- `requirements.txt` — pinned Python dependencies
- `index.html` — repository landing page
- CI workflow (`.github/workflows/ci.yml`) — lint, test, structure validation
- Nightly health check workflow
- Weekly SOC digest workflow
- `.env.example` — environment variable template

---

## Version Scheme

`MAJOR.MINOR.PATCH`
- **MAJOR** — breaking changes to script interfaces or output formats
- **MINOR** — new scripts, new modules, new workflow features
- **PATCH** — bug fixes, doc updates, dependency bumps
