"""Pure domain layer for Dropbox Airlock.

No I/O, no vault, no network — only input validation, path
canonicalisation, and mutation planning. This isolation is what lets
the transport layer be the single network chokepoint and keeps planners
testable offline.
"""

_PATH_RE = __import__("re").compile(r"^(/.+)|$")

_VALID_WRITE_MODES = {"add", "overwrite", "update"}
_VALID_BOOL_STRINGS = {"true", "false"}


class DomainError(ValueError):
    """Raised when an input violates a domain invariant."""

    def __init__(self, field, message):
        super().__init__(f"{field}: {message}")
        self.field = field
        self.message = message


def dropbox_path(value, field):
    """Validate and return a Dropbox path.

    Dropbox paths must start with '/' (except the root, which is empty
    string). We normalise the root to '' and strip trailing slashes.
    """
    if value is None or not isinstance(value, str):
        raise DomainError(field, "is required and must be a string")
    cleaned = value.strip()
    if cleaned == "" or cleaned == "/":
        return ""
    if not cleaned.startswith("/"):
        cleaned = "/" + cleaned
    if cleaned.endswith("/") and len(cleaned) > 1:
        cleaned = cleaned.rstrip("/")
    return cleaned


def nonempty(value, field):
    """Validate that a string input is present and non-empty."""
    if value is None or not isinstance(value, str) or not value.strip():
        raise DomainError(field, "is required and must be a non-empty string")
    return value.strip()


def boolean_string(value, field, default=False):
    """Parse a boolean-like string ('true'/'false') or return default."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
        raise DomainError(field, "must be 'true' or 'false'")
    return default


def positive_int(value, field, default=None, maximum=None):
    """Clamp and validate a positive integer parameter."""
    if value is None:
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise DomainError(field, "must be a number")
    if n < 1:
        raise DomainError(field, "must be at least 1")
    if maximum is not None and n > maximum:
        n = maximum
    return n


def write_mode(value):
    """Validate the upload mode parameter."""
    if value is None:
        return "add"
    if value not in _VALID_WRITE_MODES:
        raise DomainError(
            "mode",
            f"must be one of {sorted(_VALID_WRITE_MODES)} or omitted",
        )
    return value


def plan_list_folder(inputs):
    """Build the Dropbox /files/list_folder request body."""
    path = dropbox_path(inputs.get("path"), "path")
    recursive = boolean_string(inputs.get("recursive"), "recursive", default=False)
    limit = positive_int(inputs.get("limit"), "limit", default=None, maximum=1000)
    body = {"path": path, "recursive": recursive}
    if limit is not None:
        body["limit"] = limit
    return body


def plan_get_metadata(inputs):
    """Build the Dropbox /files/get_metadata request body."""
    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "root path is not supported for metadata")
    return {
        "path": path,
        "include_media_info": False,
        "include_deleted": False,
        "include_has_explicit_shared_members": False,
    }


def plan_search(inputs):
    """Build the Dropbox /files/search_v2 request body."""
    query = nonempty(inputs.get("query"), "query")
    path = dropbox_path(inputs.get("path"), "path")
    max_results = positive_int(
        inputs.get("max_results"), "max_results", default=20, maximum=1000
    )
    body = {"query": query, "max_results": max_results}
    if path:
        body["options"] = {"path": path, "filename_only": False}
    return body


def plan_create_folder(inputs):
    """Build the Dropbox /files/create_folder_v2 request body."""
    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "cannot create the root folder")
    autorename = boolean_string(inputs.get("autorename"), "autorename", default=False)
    return {"path": path, "autorename": autorename}


def plan_move(inputs):
    """Build the Dropbox /files/move_v2 request body."""
    from_path = dropbox_path(inputs.get("from_path"), "from_path")
    to_path = dropbox_path(inputs.get("to_path"), "to_path")
    if from_path == "":
        raise DomainError("from_path", "cannot move the root folder")
    if to_path == "":
        raise DomainError("to_path", "cannot move into the root folder")
    autorename = boolean_string(inputs.get("autorename"), "autorename", default=False)
    return {
        "from_path": from_path,
        "to_path": to_path,
        "autorename": autorename,
        "allow_ownership_transfer": False,
    }


def plan_copy(inputs):
    """Build the Dropbox /files/copy_v2 request body."""
    from_path = dropbox_path(inputs.get("from_path"), "from_path")
    to_path = dropbox_path(inputs.get("to_path"), "to_path")
    if from_path == "":
        raise DomainError("from_path", "cannot copy the root folder")
    if to_path == "":
        raise DomainError("to_path", "cannot copy into the root folder")
    autorename = boolean_string(inputs.get("autorename"), "autorename", default=False)
    return {
        "from_path": from_path,
        "to_path": to_path,
        "autorename": autorename,
        "allow_ownership_transfer": False,
    }


def plan_delete(inputs):
    """Build the Dropbox /files/delete_v2 request body."""
    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "cannot delete the root folder")
    return {"path": path}


def plan_upload(inputs):
    """Build the Dropbox /files/upload request parameters.

    Returns (api_arg_json, content_bytes) — content goes in the body,
    api_arg goes in the Dropbox-API-Arg header.
    """
    import json

    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "cannot upload to the root folder")
    content = nonempty(inputs.get("content"), "content")
    mode = write_mode(inputs.get("mode"))
    autorename = boolean_string(inputs.get("autorename"), "autorename", default=True)

    api_arg = {
        "path": path,
        "mode": mode,
        "autorename": autorename,
        "mute": True,
    }
    return json.dumps(api_arg), content.encode("utf-8")


def plan_create_shared_link(inputs):
    """Build the Dropbox /sharing/create_shared_link_with_settings request body."""
    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "cannot share the root folder")
    return {"path": path}


def plan_list_revisions(inputs):
    """Build the Dropbox /files/list_revisions request body."""
    path = dropbox_path(inputs.get("path"), "path")
    if path == "":
        raise DomainError("path", "root path is not supported for revisions")
    limit = positive_int(inputs.get("limit"), "limit", default=10, maximum=100)
    return {"path": path, "limit": limit}


def entry_view(entry):
    """Compact a Dropbox metadata entry to receipt-relevant fields."""
    tag = entry.get(".tag")
    result = {
        "name": entry.get("name"),
        "path_lower": entry.get("path_lower"),
        "path_display": entry.get("path_display"),
        "type": tag,
    }
    if tag == "file":
        result["id"] = entry.get("id")
        result["size"] = entry.get("size")
        result["content_hash"] = entry.get("content_hash")
        result["server_modified"] = entry.get("server_modified")
    elif tag == "folder":
        result["id"] = entry.get("id")
    if entry.get("sharing_info"):
        result["sharing_info"] = entry["sharing_info"]
    return result


def search_match_view(match):
    """Compact a search match to receipt-relevant fields."""
    metadata = match.get("metadata") or {}
    return {
        "metadata": entry_view(metadata),
        "match_type": (match.get("match_type") or {}).get(".tag"),
    }


def revision_view(rev):
    """Compact a file revision to receipt-relevant fields."""
    return {
        "name": rev.get("name"),
        "id": rev.get("id"),
        "server_modified": rev.get("server_modified"),
        "size": rev.get("size"),
        "content_hash": rev.get("content_hash"),
    }
