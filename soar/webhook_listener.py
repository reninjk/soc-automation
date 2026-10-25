"""
soar/webhook_listener.py — SOC Automation SOAR Integration Stub
================================================================
A lightweight FastAPI webhook receiver that accepts SIEM/EDR alert payloads,
classifies them by severity, enriches IOCs, and can trigger downstream
playbook actions.

Usage:
    # Development
    uvicorn soar.webhook_listener:app --host 0.0.0.0 --port 8000 --reload

    # Docker
    docker build -t soc-soar .
    docker run -p 8000:8000 --env-file .env soc-soar

Environment variables (set in .env — never commit):
    WEBHOOK_SECRET    HMAC-SHA256 shared secret for payload verification
    LOG_LEVEL         DEBUG | INFO | WARNING (default: INFO)
    LOG_FORMAT        json | text (default: json)
    ENRICHMENT_API    Base URL of your TI/enrichment API (optional)
    API_KEY           Bearer token for enrichment API (optional)

OPSEC:
    - All IP addresses, hashes and URLs in this file are PLACEHOLDER examples
    - Replace example data with real feeds in your environment
    - Keep WEBHOOK_SECRET in .env (git-ignored) — never hard-code
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator

from utils.logger import setup_logger
from utils.api_client import APIClient

# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SOC SOAR Webhook Listener",
    description="Receives SIEM/EDR alert webhooks and triggers automated response actions",
    version="1.0.0",
)

logger = setup_logger("soar.webhook")
WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class AlertPayload(BaseModel):
    """Normalised alert payload — map your SIEM's field names in _normalise()."""
    alert_id: str = Field(..., description="Unique alert identifier from the SIEM")
    title: str = Field(..., description="Alert title / rule name")
    severity: Severity
    source: str = Field(..., description="Source system, e.g. 'Sentinel', 'CrowdStrike'")
    host: Optional[str] = Field(None, description="Affected hostname")
    user: Optional[str] = Field(None, description="Affected user account")
    iocs: List[str] = Field(default_factory=list, description="IPs, hashes, domains from the alert")
    raw: Dict[str, Any] = Field(default_factory=dict, description="Original payload from SIEM")
    timestamp: Optional[str] = None

    @validator("severity", pre=True)
    def coerce_severity(cls, v: str) -> str:
        return v.lower()


class ActionResult(BaseModel):
    alert_id: str
    severity: str
    actions_taken: List[str]
    enrichment: Dict[str, Any]
    processing_time_ms: float


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_signature(body: bytes, signature: str) -> bool:
    """Verify HMAC-SHA256 webhook signature.

    Expected header format: X-Hub-Signature-256: sha256=<hex>
    """
    if not WEBHOOK_SECRET:
        logger.warning("WEBHOOK_SECRET not set — skipping signature verification (dev mode)")
        return True

    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


def _enrich_iocs(iocs: List[str]) -> Dict[str, Any]:
    """Call the TI enrichment API for each IOC and return a summary.

    Returns placeholder data if ENRICHMENT_API is not configured.
    """
    if not os.getenv("ENRICHMENT_API"):
        return {
            "status": "skipped",
            "reason": "ENRICHMENT_API not configured",
            "ioc_count": len(iocs),
        }

    results: Dict[str, Any] = {}
    with APIClient(
        base_url=os.getenv("ENRICHMENT_API", ""),
        headers={"Authorization": f"Bearer {os.getenv('API_KEY', '')}"},
    ) as client:
        for ioc in iocs[:10]:   # cap at 10 IOCs per alert to avoid runaway API calls
            try:
                results[ioc] = client.get(f"/enrich/{ioc}")
            except Exception as exc:
                results[ioc] = {"error": str(exc)}

    return results


def _determine_actions(payload: AlertPayload, enrichment: Dict[str, Any]) -> List[str]:
    """Rule-based action selector.

    Returns a list of action strings — in production these would trigger
    downstream SOAR playbook steps (isolation, ticket creation, etc.).
    """
    actions: List[str] = []

    if payload.severity in (Severity.CRITICAL, Severity.HIGH):
        actions.append("create_priority_ticket")
        actions.append("page_on_call_analyst")

    if payload.severity == Severity.CRITICAL:
        actions.append("auto_isolate_host")   # requires EDR integration
        actions.append("notify_ciso")

    if payload.host:
        actions.append(f"enrich_host:{payload.host}")

    if payload.user:
        actions.append(f"check_user_risk:{payload.user}")

    if payload.iocs:
        actions.append("ioc_watchlist_check")

    if not actions:
        actions.append("log_only")

    return actions


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/health")
async def health_check() -> JSONResponse:
    """Liveness probe — returns 200 when the service is up."""
    return JSONResponse({"status": "ok", "service": "soc-soar-webhook"})


@app.post("/webhook/alert", response_model=ActionResult)
async def receive_alert(
    request: Request,
    payload: AlertPayload,
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
) -> ActionResult:
    """
    Receive a normalised alert payload from SIEM/EDR via webhook.

    The caller must include X-Hub-Signature-256 matching the WEBHOOK_SECRET
    unless running in development mode (WEBHOOK_SECRET unset).
    """
    t0 = time.monotonic()

    # Signature verification
    body = await request.body()
    sig = x_hub_signature_256 or ""
    if not _verify_signature(body, sig):
        logger.warning("Rejected webhook: invalid signature", extra={"alert_id": payload.alert_id})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    logger.info(
        "Alert received",
        extra={
            "alert_id": payload.alert_id,
            "severity": payload.severity,
            "source": payload.source,
            "host": payload.host,
        },
    )

    # IOC enrichment
    enrichment = _enrich_iocs(payload.iocs)

    # Determine and log actions
    actions = _determine_actions(payload, enrichment)
    logger.info("Actions determined", extra={"alert_id": payload.alert_id, "actions": actions})

    elapsed_ms = (time.monotonic() - t0) * 1000

    return ActionResult(
        alert_id=payload.alert_id,
        severity=payload.severity,
        actions_taken=actions,
        enrichment=enrichment,
        processing_time_ms=round(elapsed_ms, 2),
    )


@app.post("/webhook/test")
async def test_webhook() -> JSONResponse:
    """Fire a synthetic test alert to validate the pipeline end-to-end."""
    test_payload = AlertPayload(
        alert_id="TEST-0001",
        title="Synthetic test alert",
        severity=Severity.LOW,
        source="test-harness",
        host="test-host-01",
        user="test-user",
        iocs=[],
        timestamp="2026-10-25T00:00:00Z",
    )
    enrichment = _enrich_iocs(test_payload.iocs)
    actions = _determine_actions(test_payload, enrichment)
    return JSONResponse({"status": "ok", "actions": actions, "enrichment": enrichment})
