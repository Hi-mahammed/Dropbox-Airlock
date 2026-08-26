"""Tests for the Dropbox Airlock module — transport token resolution.

Validates token resolution and transport construction without network calls.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dropbox_core.transport import DropboxTransport, TransportError, _resolve_token


class TestDropboxTokenResolution:
    def test_vault_dict_with_get(self):
        helpers = {"vault": {"get": lambda f: "dbx_abc" if f == "DROPBOX_API_KEY" else None}}
        assert _resolve_token(helpers) == "dbx_abc"

    def test_vault_callable(self):
        helpers = {"vault": lambda f: "dbx_fn" if f == "DROPBOX_API_KEY" else None}
        assert _resolve_token(helpers) == "dbx_fn"

    def test_vault_get_callable(self):
        helpers = {"vault_get": lambda f: "dbx_vg" if f == "DROPBOX_API_KEY" else None}
        assert _resolve_token(helpers) == "dbx_vg"

    def test_secret_callable(self):
        helpers = {"secret": lambda f: "dbx_sec" if f == "DROPBOX_API_KEY" else None}
        assert _resolve_token(helpers) == "dbx_sec"

    def test_env_dict(self):
        helpers = {"env": {"DROPBOX_API_KEY": "dbx_env"}}
        assert _resolve_token(helpers) == "dbx_env"

    def test_empty_returns_none(self):
        assert _resolve_token({}) is None

    def test_wrong_field_returns_none(self):
        helpers = {"vault": {"get": lambda f: "tok" if f == "WRONG" else None}}
        assert _resolve_token(helpers) is None


class TestDropboxTransportConstruction:
    def test_no_token_raises(self):
        with pytest.raises(TransportError) as exc_info:
            DropboxTransport({})
        assert exc_info.value.code == "auth_missing"

    def test_with_token_succeeds(self):
        helpers = {"vault": {"get": lambda f: "tok" if f == "DROPBOX_API_KEY" else None}}
        transport = DropboxTransport(helpers)
        assert transport._token == "tok"
