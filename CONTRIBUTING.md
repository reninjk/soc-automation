# Contributing to SOC Automation

Thank you for contributing to the SOC Automation repository. This document covers standards for scripts, tests, and configuration in this codebase.

## Repository Structure

```
soc-automation/
├── alert-triage/        # Alert classification and triage scripts
├── ioc-enrichment/      # IOC lookup and enrichment modules
├── reporting/           # Metrics and reporting scripts
├── tests/               # Pytest test suite (mirrors source structure)
├── .github/workflows/   # CI workflows
├── .env.example         # Environment variable template
└── requirements.txt     # Python dependencies
```

## Development Setup

```bash
# Clone and set up virtual environment
git clone https://github.com/reninjk/soc-automation
cd soc-automation
python -m venv venv && source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install pytest pytest-mock flake8 black mypy

# Copy and configure environment
cp .env.example .env
# Edit .env with your API keys (never commit this file)
```

## Coding Standards

### Python Style

- Python 3.10+ required
- Line length: 120 characters maximum
- Formatting: Black-compatible (run `black --line-length 120 .`)
- Linting: flake8 with `--max-line-length=120`
- Type hints encouraged on all public functions
- Structured logging via `structlog` — never use `print()` in production code

### Naming Conventions

| Item | Convention | Example |
|------|-----------|---------|
| Files | snake_case | `enrich_ioc.py` |
| Functions | snake_case | `enrich_ip()` |
| Classes | PascalCase | `TriageEngine` |
| Constants | UPPER_SNAKE | `DEFAULT_TIMEOUT` |
| Config keys | UPPER_SNAKE | `VT_API_KEY` |

### Script Structure

Every automation script must include:

1. **Module docstring** — purpose, inputs, outputs, usage example
2. **Logging** — structlog with consistent event names (`snake_case`)
3. **Error handling** — never let API failures crash the whole pipeline
4. **Environment variables** — loaded via `python-dotenv`, never hardcoded
5. **CLI interface** — `argparse` for any standalone script
6. **`if __name__ == "__main__":`** guard

```python
"""
Module: enrich_ioc.py
Purpose: Look up IOCs across VirusTotal, AbuseIPDB, and OTX.
Usage: python enrich_ioc.py --ioc 1.2.3.4 --type ip
"""
import structlog
from dotenv import load_dotenv

load_dotenv()
log = structlog.get_logger()

def enrich_ip(ip: str) -> dict:
    """Look up an IP address across threat intel sources."""
    log.info("enriching_ip", ip=ip)
    ...
```

## Testing Requirements

### Coverage Expectations

| Component | Minimum Coverage |
|-----------|-----------------|
| Core enrichment logic | 80% |
| Triage/classification | 80% |
| Reporting/metrics | 60% |
| CLI argument parsing | not required |

### Test Standards

- All tests in `tests/` directory, mirroring source structure
- Test file naming: `test_<module_name>.py`
- Use `pytest` and `pytest-mock` — no `unittest.TestCase` classes required
- **Mock all external API calls** — tests must run without real credentials
- Use `@pytest.mark.skipif` for tests that require unavailable modules
- Fixtures in `conftest.py` for shared test data

```bash
# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=term-missing
```

## Security Rules

### What NEVER Goes in This Repo

- Real API keys (VT, AbuseIPDB, Shodan, etc.)
- Credentials of any kind
- Real IP addresses, domains, or hashes from live incidents
- Customer data or PII
- Internal infrastructure hostnames

### Environment Variables

All secrets must come from environment variables. Use `.env.example` as the template — it contains placeholder values only. The real `.env` file is in `.gitignore` and must never be committed.

### Dependency Management

- Pin major versions in `requirements.txt`
- Run `pip audit` before adding new dependencies
- Avoid packages with no recent maintenance (>2 years)

## Pull Request Process

1. **Branch naming**: `feat/<description>`, `fix/<description>`, `docs/<description>`
2. **Commit format**: Conventional Commits — `feat:`, `fix:`, `test:`, `chore:`, `ci:`, `docs:`
3. **PR checklist**:
   - [ ] Tests pass locally (`pytest tests/ -v`)
   - [ ] No secrets or real IOC data committed
   - [ ] New functions have docstrings
   - [ ] `.env.example` updated if new env vars added
   - [ ] `requirements.txt` updated if new packages added
4. **Review**: 1 reviewer minimum; SOC Manager approval for changes to production scripts

## Commit Message Format

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

Examples:
```
feat(enrichment): add OTX pulse lookup for domains
fix(triage): handle missing severity field in alert payload
test(enrichment): add cache behaviour tests for enrich_ip
chore(deps): bump requests to 2.31.0
ci: fix workflow to use continue-on-error for test job
```

## Reporting Issues

For bugs in automation scripts: open a GitHub Issue with the "bug" label, include the error output (sanitised — no real IOCs or keys), and the script/function name.

For security issues in this repo: see [SECURITY.md](SECURITY.md).
