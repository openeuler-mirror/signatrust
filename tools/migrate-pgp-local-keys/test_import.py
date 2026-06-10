"""Tests for import.py - KeyImport class."""

import importlib
import os
import sys
import unittest
from unittest import mock

# Ensure the module under test is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
_import_mod = importlib.import_module("import")
KeyImport = _import_mod.KeyImport


class TestKeyImport(unittest.TestCase):
    """Tests for the KeyImport class."""

    def setUp(self):
        """Set up a KeyImport instance with test parameters."""
        self.worker = KeyImport(
            signatrust_url="https://example.com",
            token="test-token",
            name="test-key",
            email="test@example.com",
            private_key="/tmp/test_private.pem",
            public_key="/tmp/test_public.pem",
            passphrase=None,
        )

    def test_default_ssl_verify_is_enabled(self):
        """SSL verification should be enabled by default."""
        self.assertTrue(self.worker.ssl_verify)

    def test_ssl_verify_disabled_via_env(self):
        """SSL verification can be disabled via SIGNATRUST_SSL_VERIFY=0."""
        with mock.patch.dict(os.environ, {"SIGNATRUST_SSL_VERIFY": "0"}):
            worker = KeyImport(
                signatrust_url="https://example.com",
                token="test-token",
                name="test-key",
                email="test@example.com",
                private_key="/tmp/test_private.pem",
                public_key="/tmp/test_public.pem",
                passphrase=None,
            )
            self.assertFalse(worker.ssl_verify)

    def test_ssl_verify_enabled_via_env(self):
        """SSL verification should be enabled when SIGNATRUST_SSL_VERIFY=1."""
        with mock.patch.dict(os.environ, {"SIGNATRUST_SSL_VERIFY": "1"}):
            worker = KeyImport(
                signatrust_url="https://example.com",
                token="test-token",
                name="test-key",
                email="test@example.com",
                private_key="/tmp/test_private.pem",
                public_key="/tmp/test_public.pem",
                passphrase=None,
            )
            self.assertTrue(worker.ssl_verify)

    def test_headers_set_correctly(self):
        """Headers should contain Authorization and Content-Type."""
        self.assertEqual(self.worker.headers["Authorization"], "test-token")
        self.assertEqual(self.worker.headers["Content-Type"], "application/json")

    def test_signatrust_url_strips_trailing_slash(self):
        """The signatrust_url should have trailing slash stripped."""
        worker = KeyImport(
            signatrust_url="https://example.com/",
            token="test-token",
            name="test-key",
            email="test@example.com",
            private_key="/tmp/test_private.pem",
            public_key="/tmp/test_public.pem",
            passphrase=None,
        )
        self.assertEqual(worker.signatrust_url, "https://example.com")

    @mock.patch("import.requests.head")
    def test_check_name_exists_uses_timeout(self, mock_head):
        """_check_name_exists should pass timeout to requests.head."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response

        self.worker._check_name_exists("test-key")

        call_kwargs = mock_head.call_args[1]
        self.assertIn("timeout", call_kwargs)
        self.assertEqual(call_kwargs["timeout"], 30)

    @mock.patch("import.requests.get")
    def test_check_key_enabled_passes_timeout(self, mock_get):
        """_check_key_enabled should pass timeout to requests.get."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"key_state": "enabled"}
        mock_get.return_value = mock_response

        self.worker._check_key_enabled("test-key")

        call_kwargs = mock_get.call_args[1]
        self.assertIn("timeout", call_kwargs)
        self.assertEqual(call_kwargs["timeout"], 30)

    @mock.patch("import.requests.post")
    def test_enable_key_passes_timeout(self, mock_post):
        """_enable_key should pass timeout to requests.post."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        self.worker._enable_key("test-key")

        call_kwargs = mock_post.call_args[1]
        self.assertIn("timeout", call_kwargs)
        self.assertEqual(call_kwargs["timeout"], 30)

    @mock.patch("import.requests.post")
    def test_create_key_passes_timeout(self, mock_post):
        """_create_key should pass timeout to requests.post."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"name": "test-key"}
        mock_post.return_value = mock_response

        attribute = {"name": "test-key", "attributes": {}}
        self.worker._create_key(attribute)

        call_kwargs = mock_post.call_args[1]
        self.assertIn("timeout", call_kwargs)
        self.assertEqual(call_kwargs["timeout"], 30)

    @mock.patch("import.requests.head")
    def test_check_name_exists_passes_ssl_verify(self, mock_head):
        """_check_name_exists should pass verify=self.ssl_verify to requests."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 200
        mock_head.return_value = mock_response

        self.worker._check_name_exists("test-key")

        call_kwargs = mock_head.call_args[1]
        self.assertIn("verify", call_kwargs)
        self.assertTrue(call_kwargs["verify"])

    @mock.patch("import.requests.head")
    def test_check_name_exists_status_409_returns_false(self, mock_head):
        """_check_name_exists should return False when key already exists (409)."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 409
        mock_head.return_value = mock_response

        result = self.worker._check_name_exists("test-key")
        self.assertFalse(result)

    @mock.patch("import.requests.head")
    def test_check_name_exists_unexpected_status_raises(self, mock_head):
        """_check_name_exists should raise on unexpected status code."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 500
        mock_response.content = b"server error"
        mock_head.return_value = mock_response

        with self.assertRaises(Exception) as ctx:
            self.worker._check_name_exists("test-key")
        self.assertIn("failed to determine key duplication", str(ctx.exception))

    @mock.patch("import.requests.get")
    def test_check_key_enabled_unexpected_status_raises(self, mock_get):
        """_check_key_enabled should raise on unexpected status code."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 500
        mock_response.content = b"server error"
        mock_get.return_value = mock_response

        with self.assertRaises(Exception) as ctx:
            self.worker._check_key_enabled("test-key")
        self.assertIn("failed to get key", str(ctx.exception))

    @mock.patch("import.requests.post")
    def test_enable_key_unexpected_status_raises(self, mock_post):
        """_enable_key should raise on unexpected status code."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 500
        mock_response.content = b"server error"
        mock_post.return_value = mock_response

        with self.assertRaises(Exception) as ctx:
            self.worker._enable_key("test-key")
        self.assertIn("failed to enable key", str(ctx.exception))

    @mock.patch("import.requests.post")
    def test_create_key_unexpected_status_raises(self, mock_post):
        """_create_key should raise on unexpected status code."""
        mock_response = mock.MagicMock()
        mock_response.status_code = 500
        mock_response.content = b"server error"
        mock_post.return_value = mock_response

        with self.assertRaises(Exception) as ctx:
            self.worker._create_key({"name": "test", "attributes": {}})
        self.assertIn("failed to create key", str(ctx.exception))

    def test_ssl_verify_with_ssl_verify_env_unset(self):
        """SSL verify should default to True when env var is not set."""
        with mock.patch.dict(os.environ, {}, clear=True):
            worker = KeyImport(
                signatrust_url="https://example.com",
                token="test-token",
                name="test-key",
                email="test@example.com",
                private_key="/tmp/test_private.pem",
                public_key="/tmp/test_public.pem",
                passphrase=None,
            )
            self.assertTrue(worker.ssl_verify)


if __name__ == "__main__":
    unittest.main()
