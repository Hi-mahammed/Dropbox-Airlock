"""Tests validating module.json manifests for both modules.

Ensures the v2 manifest structure is correct, all commands have required
fields, function names match command ids, and contest tag is present.
"""

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REQUIRED_COMMAND_FIELDS = {
    "id", "title", "provider", "risk", "mode", "side_effects",
    "requires", "preview", "receipt_required", "input_schema", "output_schema",
}

REQUIRED_MANIFEST_FIELDS = {
    "manifest_version", "id", "name", "version", "provider",
    "description", "auth", "requires", "commands", "license_required",
}

REQUIRED_AUTH_FIELDS = {"type", "vault_provider", "field"}

VALID_MODES = {"read", "write_requires_approval"}
VALID_RISKS = {"low", "high"}
VALID_SIDE_EFFECTS = {"none", "external"}


def load_manifest(module_dir):
    with open(module_dir / "module.json") as f:
        return json.load(f)


def get_handler(module_dir):
    handler_path = module_dir / "handlers"
    sys.path.insert(0, str(module_dir))
    sys.path.insert(0, str(handler_path))
    mod_name = f"handler_{module_dir.name.replace('-', '_')}"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import importlib
    mod = importlib.import_module("handler")
    return mod


# -- manifest structure --------------------------------------------------


class TestDropboxManifest:
    manifest = load_manifest(PROJECT_ROOT)

    def test_manifest_version(self):
        assert self.manifest["manifest_version"] == 2

    def test_id(self):
        assert self.manifest["id"] == "dropbox"

    def test_name(self):
        assert self.manifest["name"] == "Dropbox Airlock"

    def test_contest_tag(self):
        assert "contest:2026Q3" in self.manifest["description"]

    def test_license_free(self):
        assert self.manifest["license_required"] is False

    def test_auth_fields(self):
        auth = self.manifest["auth"]
        for field in REQUIRED_AUTH_FIELDS:
            assert field in auth, f"auth missing {field}"
        assert auth["vault_provider"] == "dropbox"
        assert auth["field"] == "DROPBOX_API_KEY"

    def test_requires_network(self):
        network = self.manifest["requires"]["network"]
        assert "api.dropboxapi.com" in network
        assert "content.dropboxapi.com" in network

    def test_requires_no_subprocess(self):
        assert self.manifest["requires"]["subprocess"] is False

    def test_command_count(self):
        assert len(self.manifest["commands"]) == 10

    def test_all_command_fields_present(self):
        for cmd in self.manifest["commands"]:
            missing = REQUIRED_COMMAND_FIELDS - set(cmd.keys())
            assert not missing, f"Command {cmd['id']} missing fields: {missing}"

    def test_valid_modes(self):
        for cmd in self.manifest["commands"]:
            assert cmd["mode"] in VALID_MODES, f"{cmd['id']} has invalid mode"

    def test_valid_risks(self):
        for cmd in self.manifest["commands"]:
            assert cmd["risk"] in VALID_RISKS, f"{cmd['id']} has invalid risk"

    def test_side_effects_match_mode(self):
        for cmd in self.manifest["commands"]:
            if cmd["mode"] == "read":
                assert cmd["side_effects"] == "none"
            elif cmd["mode"] == "write_requires_approval":
                assert cmd["side_effects"] == "external"

    def test_all_commands_have_input_schema(self):
        for cmd in self.manifest["commands"]:
            assert isinstance(cmd["input_schema"], dict)
            assert len(cmd["input_schema"]) > 0

    def test_all_commands_have_output_schema(self):
        for cmd in self.manifest["commands"]:
            assert isinstance(cmd["output_schema"], dict)
            assert "safety_proof" in cmd["output_schema"]
            assert "http_status" in cmd["output_schema"]

    def test_all_commands_require_key(self):
        for cmd in self.manifest["commands"]:
            assert "DROPBOX_API_KEY" in cmd["requires"]

    def test_preview_and_receipt_required(self):
        for cmd in self.manifest["commands"]:
            assert cmd["preview"] is True
            assert cmd["receipt_required"] is True

    def test_function_names_match(self):
        handler = get_handler(PROJECT_ROOT / "dropbox")
        for cmd in self.manifest["commands"]:
            func_name = cmd["id"].replace(".", "_")
            assert hasattr(handler, func_name), f"Missing function {func_name}"
            assert callable(getattr(handler, func_name))
