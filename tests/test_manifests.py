"""Tests validating the Dropbox module.json manifest structure.

Ensures the v2 manifest is correct, all commands have required fields,
function names match command ids, and contest tag is present.
"""

import json
import sys
from pathlib import Path

import pytest

MODULE_DIR = Path(__file__).resolve().parent.parent

REQUIRED_COMMAND_FIELDS = {
    "id", "title", "provider", "risk", "mode", "side_effects",
    "requires", "preview", "receipt_required", "input_schema", "output_schema",
}

VALID_MODES = {"read", "write_requires_approval"}
VALID_RISKS = {"low", "high"}


@pytest.fixture(scope="module")
def manifest():
    with open(MODULE_DIR / "module.json") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def handler():
    for key in ("handler", "dropbox_core"):
        sys.modules.pop(key, None)
    sys.path.insert(0, str(MODULE_DIR))
    sys.path.insert(0, str(MODULE_DIR / "handlers"))
    import importlib
    return importlib.import_module("handler")


class TestManifestStructure:
    def test_manifest_version(self, manifest):
        assert manifest["manifest_version"] == 2

    def test_id(self, manifest):
        assert manifest["id"] == "dropbox"

    def test_name(self, manifest):
        assert manifest["name"] == "Dropbox Airlock"

    def test_provider(self, manifest):
        assert manifest["provider"] == "dropbox"

    def test_contest_tag(self, manifest):
        assert "contest:2026Q3" in manifest["description"]

    def test_license_free(self, manifest):
        assert manifest["license_required"] is False

    def test_auth(self, manifest):
        auth = manifest["auth"]
        assert auth["type"] == "api_key"
        assert auth["vault_provider"] == "dropbox"
        assert auth["field"] == "DROPBOX_API_KEY"

    def test_requires_network(self, manifest):
        network = manifest["requires"]["network"]
        assert "api.dropboxapi.com" in network
        assert "content.dropboxapi.com" in network

    def test_requires_no_subprocess(self, manifest):
        assert manifest["requires"]["subprocess"] is False

    def test_requires_no_filesystem_writes(self, manifest):
        assert manifest["requires"]["filesystem_writes"] == []


class TestCommands:
    def test_command_count(self, manifest):
        assert len(manifest["commands"]) == 10

    def test_all_fields_present(self, manifest):
        for cmd in manifest["commands"]:
            missing = REQUIRED_COMMAND_FIELDS - set(cmd.keys())
            assert not missing, f"{cmd['id']} missing: {missing}"

    def test_valid_modes(self, manifest):
        for cmd in manifest["commands"]:
            assert cmd["mode"] in VALID_MODES, f"{cmd['id']} bad mode"

    def test_valid_risks(self, manifest):
        for cmd in manifest["commands"]:
            assert cmd["risk"] in VALID_RISKS, f"{cmd['id']} bad risk"

    def test_side_effects_match_mode(self, manifest):
        for cmd in manifest["commands"]:
            if cmd["mode"] == "read":
                assert cmd["side_effects"] == "none"
            else:
                assert cmd["side_effects"] == "external"

    def test_all_have_input_schema(self, manifest):
        for cmd in manifest["commands"]:
            assert isinstance(cmd["input_schema"], dict)
            assert len(cmd["input_schema"]) > 0

    def test_all_have_output_schema(self, manifest):
        for cmd in manifest["commands"]:
            assert isinstance(cmd["output_schema"], dict)
            assert "safety_proof" in cmd["output_schema"]
            assert "http_status" in cmd["output_schema"]

    def test_all_require_key(self, manifest):
        for cmd in manifest["commands"]:
            assert "DROPBOX_API_KEY" in cmd["requires"]

    def test_preview_and_receipt(self, manifest):
        for cmd in manifest["commands"]:
            assert cmd["preview"] is True
            assert cmd["receipt_required"] is True

    def test_function_names_match(self, manifest, handler):
        for cmd in manifest["commands"]:
            func_name = cmd["id"].replace(".", "_")
            assert hasattr(handler, func_name), f"Missing {func_name}"
            assert callable(getattr(handler, func_name))
