# Security Policy

## Repository Overview

This repository contains **Python automation scripts** for SOC operations — alert triage, IOC enrichment, and metrics reporting. These scripts interact with production security tools and must be handled carefully.

## Credential & Secrets Policy

This is the most security-sensitive repository in the SOC GitHub org. Strict rules apply:

**Never commit:**
- API keys, tokens, or passwords of any kind
- SIEM connection strings or credentials
- TI platform API keys
- Ticketing system tokens
- Any value from your `.env` file
- Hardcoded IP addresses, hostnames, or internal URLs

**Always use:**
- `.env` file for all secrets (confirmed in `.gitignore`)
- `.env.example` for documenting required variables (placeholder values only)
- Environment variables or a secrets manager in CI/CD pipelines

If you accidentally commit a secret: **rotate it immediately**, then contact the SOC Manager. Do not wait.

## Dependency Security

- Dependencies are pinned in `requirements.txt` — do not use floating versions (e.g., `requests>=2.0`)
- Review `pip audit` output before merging any dependency changes
- No new dependencies without SOC Manager approval
- Prefer well-maintained libraries with active security advisories

## Code Security Standards

All automation scripts must follow these practices:

- No `shell=True` in `subprocess` calls
- Input validation on all externally supplied data (IOC values, API responses)
- Timeouts on all HTTP requests (default: 10s)
- Errors logged via `structlog` — never print credentials to logs
- Tests must cover error/exception paths, not just happy paths
- No `eval()` or `exec()` on untrusted data

## Reporting Security Issues

If you discover a vulnerability in these scripts or a process gap:

1. Do **not** open a public GitHub issue
2. Email the SOC Manager directly (internal directory)
3. Include: affected script, nature of the issue, potential impact
4. Acknowledgement within 2 business days; critical issues addressed within 24 hours

## Supported Versions

Only the current `main` branch is maintained. Scripts are reviewed:
- When a new integration is added
- After any security incident involving automation tooling
- Quarterly as part of the SOC tooling review

## Compliance

Automation scripts in this repository support:
- ISO 27001:2022 Annex A 8.19 — Installation of software on operational systems
- CIS Controls v8 — Control 16: Application Software Security
- NIST CSF 2.0 — Protect: Identity Management and Access Control (PR.AA)
