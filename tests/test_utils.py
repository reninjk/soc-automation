"""
Unit tests for soc-automation utils/ package.

Tests are intentionally self-contained and do not require a live SIEM/API
connection. All external HTTP calls are mocked via unittest.mock.
"""
import json
import logging
import os
import unittest
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# logger tests
# ---------------------------------------------------------------------------

class TestSetupLogger(unittest.TestCase):
    """Tests for utils.logger.setup_logger."""

    def setUp(self):
        # Reset log level env var before each test
        os.environ.pop("LOG_LEVEL", None)
        os.environ.pop("LOG_FORMAT", None)

    def _import_setup_logger(self):
        # Import here so env vars set in setUp take effect
        from utils.logger import setup_logger
        return setup_logger

    def test_returns_logger_instance(self):
        setup_logger = self._import_setup_logger()
        logger = setup_logger("test_returns")
        self.assertIsInstance(logger, logging.Logger)

    def test_logger_name(self):
        setup_logger = self._import_setup_logger()
        logger = setup_logger("my_component")
        self.assertEqual(logger.name, "my_component")

    def test_default_level_is_info(self):
        setup_logger = self._import_setup_logger()
        logger = setup_logger("test_level")
        self.assertEqual(logger.level, logging.INFO)

    def test_env_log_level_override(self):
        os.environ["LOG_LEVEL"] = "DEBUG"
        setup_logger = self._import_setup_logger()
        logger = setup_logger("test_debug")
        self.assertEqual(logger.level, logging.DEBUG)

    def test_no_duplicate_handlers_on_repeated_call(self):
        setup_logger = self._import_setup_logger()
        logger1 = setup_logger("dedup")
        logger2 = setup_logger("dedup")
        self.assertIs(logger1, logger2)
        self.assertEqual(len(logger2.handlers), 1)

    def test_json_format_produces_valid_json(self):
        os.environ["LOG_FORMAT"] = "json"
        from utils.logger import JSONFormatter
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="hello world", args=(), exc_info=None
        )
        output = formatter.format(record)
        data = json.loads(output)
        self.assertIn("timestamp", data)
        self.assertIn("level", data)
        self.assertEqual(data["message"], "hello world")


# ---------------------------------------------------------------------------
# APIClient tests
# ---------------------------------------------------------------------------

class TestAPIClient(unittest.TestCase):
    """Tests for utils.api_client.APIClient."""

    def _make_client(self, base_url="https://api.example.com"):
        from utils.api_client import APIClient
        return APIClient(base_url=base_url)

    def test_instantiation(self):
        client = self._make_client()
        self.assertIsNotNone(client)

    def test_context_manager(self):
        from utils.api_client import APIClient
        with APIClient(base_url="https://api.example.com") as client:
            self.assertIsNotNone(client)

    @patch("utils.api_client.requests.Session.get")
    def test_get_returns_json(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        client = self._make_client()
        result = client.get("/health")
        self.assertEqual(result, {"status": "ok"})

    @patch("utils.api_client.requests.Session.post")
    def test_post_sends_json(self, mock_post):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "abc123"}
        mock_response.raise_for_status = MagicMock()
        mock_post.return_value = mock_response

        client = self._make_client()
        result = client.post("/alerts", json={"title": "test alert"})
        self.assertEqual(result["id"], "abc123")
        mock_post.assert_called_once()

    @patch("utils.api_client.requests.Session.get")
    def test_get_raises_on_4xx(self, mock_get):
        from utils.api_client import APIClientError
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.raise_for_status.side_effect = Exception("404 Not Found")
        mock_get.return_value = mock_response

        client = self._make_client()
        with self.assertRaises((APIClientError, Exception)):
            client.get("/nonexistent")

    def test_custom_headers_stored(self):
        from utils.api_client import APIClient
        headers = {"X-API-Key": "test-key-placeholder"}
        client = APIClient(base_url="https://api.example.com", headers=headers)
        # Verify session has the custom header
        self.assertIn("X-API-Key", client.session.headers)
        client.close()

    def test_close_closes_session(self):
        from utils.api_client import APIClient
        client = APIClient(base_url="https://api.example.com")
        client.session.close = MagicMock()
        client.close()
        client.session.close.assert_called_once()


# ---------------------------------------------------------------------------
# Integration smoke test (no network)
# ---------------------------------------------------------------------------

class TestUtilsPackageImport(unittest.TestCase):
    """Verify the utils package __init__ exports are correct."""

    def test_package_exports_setup_logger(self):
        from utils import setup_logger
        self.assertTrue(callable(setup_logger))

    def test_package_exports_api_client(self):
        from utils import APIClient
        self.assertTrue(callable(APIClient))


if __name__ == "__main__":
    unittest.main()
