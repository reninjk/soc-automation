#!/usr/bin/env python3
"""
Generic API client for SOC Automation scripts.
Handles retries, rate limiting, and consistent error handling
across all third-party API integrations.
"""

import os
import time
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import setup_logger

logger = setup_logger(__name__)


class APIClientError(Exception):
    """Raised when an API request fails after all retries."""
    pass


class APIClient:
    """
    Reusable HTTP client with retry logic and rate limiting.

    Reads rate-limit delay from API_RATE_LIMIT_DELAY env var (default: 1s).
    Automatically retries on 429, 500, 502, 503, 504 with exponential back-off.

    Example:
        client = APIClient(base_url="https://api.example.com", headers={"x-api-key": key})
        data = client.get("/v1/resource", params={"id": "123"})
    """

    DEFAULT_TIMEOUT = 15
    RETRY_TOTAL = 3
    RETRY_STATUS_FORCELIST = (429, 500, 502, 503, 504)

    def __init__(
        self,
        base_url: str = "",
        headers: Optional[Dict[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.rate_limit_delay = float(os.getenv("API_RATE_LIMIT_DELAY", "1"))

        self.session = requests.Session()
        self.session.headers.update(headers or {})
        self.session.headers.setdefault("Accept", "application/json")
        self.session.headers.setdefault("Content-Type", "application/json")

        # Retry adapter: back-off 0.5s, 1s, 2s
        retry = Retry(
            total=self.RETRY_TOTAL,
            backoff_factor=0.5,
            status_forcelist=self.RETRY_STATUS_FORCELIST,
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json: Optional[Dict] = None,
        **kwargs: Any,
    ) -> Dict:
        url = f"{self.base_url}{endpoint}" if endpoint.startswith("/") else endpoint
        logger.debug(f"{method} {url} params={params}")

        try:
            resp = self.session.request(
                method,
                url,
                params=params,
                json=json,
                timeout=self.timeout,
                **kwargs,
            )
        except requests.exceptions.ConnectionError as e:
            raise APIClientError(f"Connection failed to {url}: {e}") from e
        except requests.exceptions.Timeout as e:
            raise APIClientError(f"Request timed out ({self.timeout}s): {url}") from e

        if not resp.ok:
            logger.warning(
                f"API returned {resp.status_code} for {method} {url}: {resp.text[:200]}"
            )
            resp.raise_for_status()

        # Honour rate limit between calls
        time.sleep(self.rate_limit_delay)

        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    def get(self, endpoint: str, params: Optional[Dict] = None, **kwargs: Any) -> Dict:
        """Send a GET request."""
        return self._request("GET", endpoint, params=params, **kwargs)

    def post(self, endpoint: str, json: Optional[Dict] = None, **kwargs: Any) -> Dict:
        """Send a POST request."""
        return self._request("POST", endpoint, json=json, **kwargs)

    def close(self) -> None:
        """Close the underlying session."""
        self.session.close()

    def __enter__(self) -> "APIClient":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
