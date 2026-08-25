"""Transport layer for Dropbox Airlock.

The single network chokepoint. Reads the API token from RailCall's
runtime helpers (vault), never from user input. All outbound requests
go to api.dropboxapi.com (RPC/JSON endpoints) or content.dropboxapi.com
(file content upload endpoints) only.

Dropbox API v2 uses two distinct calling styles:
  - RPC style: arguments in the request body as JSON, no Dropbox-API-Arg header.
  - Upload style: arguments in Dropbox-API-Arg header, content in the body.
  - Download style: arguments in Dropbox-API-Arg header, file content in response.

Helpers shape (injected by RailCall runtime via ``__rc_helpers__``):

    {
        "vault": {  # callable or dict
            "get": callable(field) -> str | None
        }
    }

or simpler form::

    {"vault_get": callable(field) -> str | None}
"""

import json
import urllib.error
import urllib.request

_RPC_BASE = "https://api.dropboxapi.com"
_CONTENT_BASE = "https://content.dropboxapi.com"


class TransportError(Exception):
    """Structured error raised when the Dropbox API or network fails."""

    def __init__(self, code, message, status):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status

    def to_dict(self):
        return {
            "ok": False,
            "code": self.code,
            "message": self.message,
            "http_status": self.status,
        }


def _resolve_token(helpers):
    """Pull the Dropbox API key from RailCall vault helpers.

    Tries multiple shapes so the module is resilient across runtime versions.
    """
    vault = helpers.get("vault")
    if vault is not None:
        if callable(vault):
            token = vault("DROPBOX_API_KEY")
            if token:
                return token
        elif isinstance(vault, dict):
            vault_get = vault.get("get")
            if callable(vault_get):
                token = vault_get("DROPBOX_API_KEY")
                if token:
                    return token
            token = vault.get("DROPBOX_API_KEY")
            if token:
                return token

    vault_get = helpers.get("vault_get")
    if callable(vault_get):
        token = vault_get("DROPBOX_API_KEY")
        if token:
            return token

    secret = helpers.get("secret")
    if callable(secret):
        token = secret("DROPBOX_API_KEY")
        if token:
            return token

    env = helpers.get("env")
    if isinstance(env, dict):
        token = env.get("DROPBOX_API_KEY")
        if token:
            return token

    return None


class DropboxTransport:
    """Fixed-origin HTTP transport for the Dropbox API v2."""

    def __init__(self, helpers):
        token = _resolve_token(helpers)
        if not token:
            raise TransportError(
                "auth_missing",
                "Dropbox API key is not configured. Add it in Studio's Integrations tab.",
                None,
            )
        self._token = token

    def _rpc_request(self, method, path, body=None):
        """RPC-style call: JSON arguments in the body.

        Returns (http_status, parsed_json).
        """
        url = f"{_RPC_BASE}{path}"
        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Content-Type", "application/json")

        return self._execute(req)

    def _upload_request(self, path, api_arg_json, content_bytes):
        """Upload-style call: arguments in Dropbox-API-Arg header, content in body.

        Returns (http_status, parsed_json).
        """
        url = f"{_CONTENT_BASE}{path}"
        req = urllib.request.Request(url, data=content_bytes, method="POST")
        req.add_header("Authorization", f"Bearer {self._token}")
        req.add_header("Dropbox-API-Arg", api_arg_json)
        req.add_header("Content-Type", "application/octet-stream")

        return self._execute(req)

    def _execute(self, req):
        """Execute an urllib request and return (status, parsed_json)."""
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = resp.read().decode("utf-8")
                parsed = json.loads(payload) if payload else {}
                return resp.status, parsed
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            try:
                err_json = json.loads(err_body)
                summary = err_json.get("error_summary", "")
                message = err_json.get("error", {}).get(".tag", "") if isinstance(err_json.get("error"), dict) else summary
                if not message:
                    message = summary or err_body
                code = summary or "http_error"
            except (json.JSONDecodeError, ValueError):
                message = err_body
                code = "http_error"
            raise TransportError(code, message, e.code)
        except urllib.error.URLError as e:
            raise TransportError("network_error", str(e.reason), None)

    # -- high-level methods ---

    def rpc(self, method, path, body=None):
        """RPC-style API call (most endpoints)."""
        return self._rpc_request(method, path, body)

    def upload(self, path, api_arg_json, content_bytes):
        """Content upload API call."""
        return self._upload_request(path, api_arg_json, content_bytes)
