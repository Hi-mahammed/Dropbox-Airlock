"""Tests for the Dropbox Airlock module — handler layer.

Tests the orchestration layer with mock helpers (no real API calls).
Validates error handling, tuple return contract, and safety proof attachment.
"""

import importlib
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent.parent


def make_vault(token="dbx_test_token"):
    return {"vault": {"get": lambda f: token if f == "DROPBOX_API_KEY" else None}}


def make_empty():
    return {}


@pytest.fixture(autouse=True)
def _reset_handler_helpers():
    """Clear __rc_helpers__ between tests so state never leaks."""
    yield
    for mod in list(sys.modules.values()):
        if hasattr(mod, "__rc_helpers__"):
            setattr(mod, "__rc_helpers__", {})


@pytest.fixture
def handler():
    """Import the Dropbox handler with clean sys.path isolation."""
    for key in ("handler", "dropbox_core"):
        sys.modules.pop(key, None)
    sys.path.insert(0, str(MODULE_DIR))
    sys.path.insert(0, str(MODULE_DIR / "handlers"))
    return importlib.import_module("handler")


class TestHandlerContract:
    """Every handler must return a (result_dict, None) tuple."""

    def test_list_folder_returns_tuple(self, handler):
        handler.__rc_helpers__ = make_empty()
        result, err = handler.dropbox_list_folder({"path": "/test"}, {})
        assert isinstance(result, dict)
        assert err is None
        assert "ok" in result
        assert "safety_proof" in result

    def test_search_returns_tuple(self, handler):
        handler.__rc_helpers__ = make_empty()
        result, err = handler.dropbox_search({"query": "x"}, {})
        assert isinstance(result, dict)
        assert err is None

    def test_move_returns_tuple(self, handler):
        handler.__rc_helpers__ = make_empty()
        result, err = handler.dropbox_move({"from_path": "/a", "to_path": "/b"}, {})
        assert isinstance(result, dict)
        assert err is None


class TestAuthMissing:
    """All handlers must return a structured auth error when no token is set."""

    @pytest.mark.parametrize("handler_name,inputs", [
        ("dropbox_list_folder", {"path": "/test"}),
        ("dropbox_get_metadata", {"path": "/test"}),
        ("dropbox_search", {"query": "test"}),
        ("dropbox_list_revisions", {"path": "/test"}),
        ("dropbox_create_folder", {"path": "/new"}),
        ("dropbox_move", {"from_path": "/a", "to_path": "/b"}),
        ("dropbox_copy", {"from_path": "/a", "to_path": "/b"}),
        ("dropbox_delete", {"path": "/old"}),
        ("dropbox_upload", {"path": "/x.txt", "content": "x"}),
        ("dropbox_create_shared_link", {"path": "/pub"}),
    ])
    def test_auth_missing(self, handler, handler_name, inputs):
        handler.__rc_helpers__ = make_empty()
        fn = getattr(handler, handler_name)
        result, err = fn(inputs, {"receipt_id": "rc"})
        assert result["ok"] is False
        assert result["code"] == "auth_missing"
        assert "safety_proof" in result
        assert err is None


class TestDomainValidationErrors:
    """Handlers must catch DomainError and return structured error with proof."""

    def test_get_metadata_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_get_metadata({"path": "/"}, {})
        assert result["ok"] is False
        assert "safety_proof" in result

    def test_create_folder_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_create_folder({"path": "/"}, {})
        assert result["ok"] is False

    def test_move_root_from_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_move({"from_path": "/", "to_path": "/b"}, {})
        assert result["ok"] is False

    def test_move_root_to_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_move({"from_path": "/a", "to_path": "/"}, {})
        assert result["ok"] is False

    def test_delete_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_delete({"path": "/"}, {})
        assert result["ok"] is False

    def test_upload_empty_content_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_upload({"path": "/x.txt", "content": ""}, {})
        assert result["ok"] is False

    def test_upload_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_upload({"path": "/", "content": "x"}, {})
        assert result["ok"] is False

    def test_search_empty_query_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_search({"query": ""}, {})
        assert result["ok"] is False

    def test_shared_link_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_create_shared_link({"path": "/"}, {})
        assert result["ok"] is False

    def test_list_revisions_root_raises(self, handler):
        handler.__rc_helpers__ = make_vault()
        result, err = handler.dropbox_list_revisions({"path": "/"}, {})
        assert result["ok"] is False


class TestSafetyProofOnAllHandlers:
    """Every handler result — success or error — must carry a safety_proof."""

    @pytest.mark.parametrize("handler_name,inputs", [
        ("dropbox_list_folder", {"path": "/Projects"}),
        ("dropbox_get_metadata", {"path": "/file.txt"}),
        ("dropbox_search", {"query": "report"}),
        ("dropbox_list_revisions", {"path": "/file.txt"}),
        ("dropbox_create_folder", {"path": "/New"}),
        ("dropbox_move", {"from_path": "/a", "to_path": "/b"}),
        ("dropbox_copy", {"from_path": "/a", "to_path": "/b"}),
        ("dropbox_delete", {"path": "/old"}),
        ("dropbox_upload", {"path": "/x.txt", "content": "hello"}),
        ("dropbox_create_shared_link", {"path": "/pub"}),
    ])
    def test_error_path_has_proof(self, handler, handler_name, inputs):
        handler.__rc_helpers__ = make_empty()
        fn = getattr(handler, handler_name)
        result, err = fn(inputs, {"receipt_id": "rc_test"})
        assert "safety_proof" in result, f"{handler_name} missing safety_proof"
        assert err is None


class TestVaultResolution:
    """Test that the transport resolves tokens from various helper shapes."""

    def test_vault_get_dict(self, handler):
        handler.__rc_helpers__ = {"vault": {"get": lambda f: "tok_abc" if f == "DROPBOX_API_KEY" else None}}
        result, err = handler.dropbox_search({"query": "x"}, {})
        assert result["code"] != "auth_missing"

    def test_vault_get_callable(self, handler):
        handler.__rc_helpers__ = {"vault_get": lambda f: "tok_xyz" if f == "DROPBOX_API_KEY" else None}
        result, err = handler.dropbox_search({"query": "x"}, {})
        assert result["code"] != "auth_missing"

    def test_secret_callable(self, handler):
        handler.__rc_helpers__ = {"secret": lambda f: "tok_sec" if f == "DROPBOX_API_KEY" else None}
        result, err = handler.dropbox_search({"query": "x"}, {})
        assert result["code"] != "auth_missing"

    def test_env_dict(self, handler):
        handler.__rc_helpers__ = {"env": {"DROPBOX_API_KEY": "tok_env"}}
        result, err = handler.dropbox_search({"query": "x"}, {})
        assert result["code"] != "auth_missing"
