"""Thin RailCall orchestration layer for Dropbox Airlock.

Pure validation and mutation planning live in ``dropbox_core.domain``.
Vault and HTTP I/O live in ``dropbox_core.transport``. These handlers
connect the two layers and attach a deterministic SHA-256 event chain
to every successful result; RailCall then seals that chain inside its
signed receipt.

Each top-level function name matches a command id from module.json with
dots replaced by underscores (``dropbox.list_folder`` -> ``dropbox_list_folder``).
Every function takes ``(inputs, stamp)`` and returns ``(result, error)``
where error is ``None`` on success.
"""

from dropbox_core.domain import (
    DomainError,
    entry_view,
    plan_copy,
    plan_create_folder,
    plan_create_shared_link,
    plan_delete,
    plan_get_metadata,
    plan_list_folder,
    plan_list_revisions,
    plan_move,
    plan_search,
    plan_upload,
    revision_view,
    search_match_view,
)
from dropbox_core.proof import build_safety_proof
from dropbox_core.transport import DropboxTransport, TransportError


def _helpers():
    """Return the RailCall runtime helpers dict injected via __rc_helpers__."""
    helpers = globals().get("__rc_helpers__")
    if not isinstance(helpers, dict):
        raise TransportError(
            "runtime_error",
            "RailCall runtime helpers are unavailable",
            None,
        )
    return helpers


def _transport():
    return DropboxTransport(_helpers())


def _error(command_id, inputs, stamp, err):
    """Build a uniform error result with a minimal safety proof."""
    code = getattr(err, "code", "domain_error")
    message = getattr(err, "message", str(err))
    status = getattr(err, "status", None)
    proof = build_safety_proof(
        command_id, inputs, stamp,
        [("intent_validated", {"error": code, "message": message})],
    )
    return {
        "ok": False,
        "code": code,
        "message": message,
        "http_status": status,
        "safety_proof": proof,
    }, None


def _finish(command_id, inputs, stamp, result, events):
    """Attach the SHA-256 event chain proof and return (result, None)."""
    result["safety_proof"] = build_safety_proof(command_id, inputs, stamp, events)
    result["ok"] = True
    return result, None


# -- read commands --------------------------------------------------------

def dropbox_list_folder(inputs, stamp):
    """List contents of a Dropbox folder."""
    command_id = "dropbox.list_folder"
    try:
        body = plan_list_folder(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/list_folder", body=body)
        entries = [entry_view(e) for e in payload.get("entries") or []]
        return _finish(
            command_id, inputs, stamp,
            {
                "http_status": status,
                "entries": entries,
                "has_more": payload.get("has_more", False),
                "cursor": payload.get("cursor"),
            },
            [
                ("intent_validated", body),
                ("state_observed", {"entries": entries, "has_more": payload.get("has_more", False)}),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_get_metadata(inputs, stamp):
    """Retrieve metadata for a file or folder."""
    command_id = "dropbox.get_metadata"
    try:
        body = plan_get_metadata(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/get_metadata", body=body)
        view = entry_view(payload)
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "metadata": view},
            [
                ("intent_validated", body),
                ("state_observed", view),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_search(inputs, stamp):
    """Search for files and folders by name or content."""
    command_id = "dropbox.search"
    try:
        body = plan_search(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/search_v2", body=body)
        matches = [search_match_view(m) for m in payload.get("matches") or []]
        return _finish(
            command_id, inputs, stamp,
            {
                "http_status": status,
                "matches": matches,
                "has_more": payload.get("has_more", False),
            },
            [
                ("intent_validated", body),
                ("state_observed", {"matches": matches, "count": len(matches)}),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_list_revisions(inputs, stamp):
    """List file revisions for rollback and audit."""
    command_id = "dropbox.list_revisions"
    try:
        body = plan_list_revisions(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/list_revisions", body=body)
        revs = [revision_view(r) for r in payload.get("entries") or []]
        return _finish(
            command_id, inputs, stamp,
            {
                "http_status": status,
                "revisions": revs,
                "is_deleted": payload.get("is_deleted", False),
            },
            [
                ("intent_validated", body),
                ("state_observed", {"revisions": revs, "count": len(revs)}),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


# -- write commands -------------------------------------------------------

def dropbox_create_folder(inputs, stamp):
    """Create a new folder in Dropbox."""
    command_id = "dropbox.create_folder"
    try:
        body = plan_create_folder(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/create_folder_v2", body=body)
        metadata = entry_view(payload.get("metadata") or {})
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "folder": metadata},
            [
                ("intent_validated", body),
                ("mutation_verified", metadata),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_move(inputs, stamp):
    """Move a file or folder to a new path."""
    command_id = "dropbox.move"
    try:
        body = plan_move(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/move_v2", body=body)
        view = entry_view(payload.get("metadata") or {})
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "metadata": view},
            [
                ("intent_validated", body),
                ("mutation_verified", view),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_copy(inputs, stamp):
    """Copy a file or folder to a new path."""
    command_id = "dropbox.copy"
    try:
        body = plan_copy(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/copy_v2", body=body)
        view = entry_view(payload.get("metadata") or {})
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "metadata": view},
            [
                ("intent_validated", body),
                ("mutation_verified", view),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_delete(inputs, stamp):
    """Delete a file or folder."""
    command_id = "dropbox.delete"
    try:
        body = plan_delete(inputs)
        transport = _transport()
        status, payload = transport.rpc("POST", "/2/files/delete_v2", body=body)
        view = entry_view(payload.get("metadata") or {})
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "metadata": view},
            [
                ("intent_validated", body),
                ("mutation_verified", view),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_upload(inputs, stamp):
    """Upload text content as a new file."""
    command_id = "dropbox.upload"
    try:
        api_arg_json, content_bytes = plan_upload(inputs)
        transport = _transport()
        status, payload = transport.upload(
            "/2/files/upload", api_arg_json, content_bytes
        )
        view = entry_view(payload)
        return _finish(
            command_id, inputs, stamp,
            {"http_status": status, "metadata": view},
            [
                ("intent_validated", {"path": payload.get("path_display"), "size": len(content_bytes)}),
                ("mutation_verified", view),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)


def dropbox_create_shared_link(inputs, stamp):
    """Create a shared link for a file or folder."""
    command_id = "dropbox.create_shared_link"
    try:
        body = plan_create_shared_link(inputs)
        transport = _transport()
        status, payload = transport.rpc(
            "POST", "/2/sharing/create_shared_link_with_settings", body=body
        )
        return _finish(
            command_id, inputs, stamp,
            {
                "http_status": status,
                "url": payload.get("url"),
                "metadata": entry_view(payload),
            },
            [
                ("intent_validated", body),
                ("mutation_verified", {"url": payload.get("url")}),
            ],
        )
    except (DomainError, TransportError) as e:
        return _error(command_id, inputs, stamp, e)
