"""Tests for the Dropbox Airlock module — domain layer.

Validates pure input validation, path canonicalisation, and mutation planning.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dropbox_core.domain import (
    DomainError,
    boolean_string,
    dropbox_path,
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
    positive_int,
    revision_view,
    search_match_view,
    write_mode,
)


# -- dropbox_path --------------------------------------------------------

class TestDropboxPath:
    def test_root_empty_string(self):
        assert dropbox_path("", "path") == ""

    def test_root_slash(self):
        assert dropbox_path("/", "path") == ""

    def test_normal_path(self):
        assert dropbox_path("/Projects", "path") == "/Projects"

    def test_adds_leading_slash(self):
        assert dropbox_path("Projects", "path") == "/Projects"

    def test_strips_trailing_slash(self):
        assert dropbox_path("/a/b/", "path") == "/a/b"

    def test_nested_path(self):
        assert dropbox_path("/Projects/App/Source", "path") == "/Projects/App/Source"

    def test_none_required_raises(self):
        with pytest.raises(DomainError, match="required"):
            dropbox_path(None, "path")

    def test_none_optional_returns_empty(self):
        assert dropbox_path(None, "path", required=False) == ""

    def test_non_string_raises(self):
        with pytest.raises(DomainError, match="must be a string"):
            dropbox_path(123, "path")

    def test_strips_whitespace(self):
        assert dropbox_path("  /Projects  ", "path") == "/Projects"


# -- boolean_string ------------------------------------------------------

class TestBooleanString:
    def test_true(self):
        assert boolean_string("true", "test") is True

    def test_false(self):
        assert boolean_string("false", "test") is False

    def test_none_uses_default(self):
        assert boolean_string(None, "test", default=True) is True

    def test_actual_bool_passthrough(self):
        assert boolean_string(True, "test") is True
        assert boolean_string(False, "test") is False

    def test_invalid_raises(self):
        with pytest.raises(DomainError, match="test"):
            boolean_string("yes", "test")

    def test_case_insensitive(self):
        assert boolean_string("TRUE", "test") is True
        assert boolean_string("False", "test") is False


# -- positive_int --------------------------------------------------------

class TestPositiveInt:
    def test_none_uses_default(self):
        assert positive_int(None, "test", default=10) == 10

    def test_custom_value(self):
        assert positive_int(5, "test") == 5

    def test_clamps_to_max(self):
        assert positive_int(150, "test", maximum=100) == 100

    def test_below_one_raises(self):
        with pytest.raises(DomainError, match="test"):
            positive_int(0, "test")

    def test_non_number_raises(self):
        with pytest.raises(DomainError, match="test"):
            positive_int("abc", "test")

    def test_string_number(self):
        assert positive_int("5", "test") == 5


# -- write_mode ----------------------------------------------------------

class TestWriteMode:
    def test_none_defaults_to_add(self):
        assert write_mode(None) == "add"

    def test_overwrite(self):
        assert write_mode("overwrite") == "overwrite"

    def test_update(self):
        assert write_mode("update") == "update"

    def test_invalid_raises(self):
        with pytest.raises(DomainError, match="mode"):
            write_mode("invalid")


# -- plan_list_folder ----------------------------------------------------

class TestPlanListFolder:
    def test_basic(self):
        body = plan_list_folder({"path": "/Projects"})
        assert body["path"] == "/Projects"
        assert body["recursive"] is False

    def test_recursive_true(self):
        body = plan_list_folder({"path": "/Projects", "recursive": "true"})
        assert body["recursive"] is True

    def test_with_limit(self):
        body = plan_list_folder({"path": "/", "limit": 50})
        assert body["limit"] == 50

    def test_limit_clamped(self):
        body = plan_list_folder({"path": "/", "limit": 5000})
        assert body["limit"] == 1000


# -- plan_get_metadata ---------------------------------------------------

class TestPlanGetMetadata:
    def test_basic(self):
        body = plan_get_metadata({"path": "/Projects/file.txt"})
        assert body["path"] == "/Projects/file.txt"

    def test_root_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_get_metadata({"path": "/"})


# -- plan_search ---------------------------------------------------------

class TestPlanSearch:
    def test_basic(self):
        body = plan_search({"query": "invoice"})
        assert body["query"] == "invoice"
        assert body["max_results"] == 20

    def test_with_path(self):
        body = plan_search({"query": "report", "path": "/Projects"})
        assert body["options"]["path"] == "/Projects"

    def test_without_path(self):
        body = plan_search({"query": "x"})
        assert "options" not in body

    def test_custom_max_results(self):
        body = plan_search({"query": "x", "max_results": 50})
        assert body["max_results"] == 50

    def test_empty_query_raises(self):
        with pytest.raises(DomainError, match="query"):
            plan_search({"query": ""})


# -- plan_create_folder --------------------------------------------------

class TestPlanCreateFolder:
    def test_basic(self):
        body = plan_create_folder({"path": "/New Folder"})
        assert body["path"] == "/New Folder"
        assert body["autorename"] is False

    def test_autorename(self):
        body = plan_create_folder({"path": "/X", "autorename": "true"})
        assert body["autorename"] is True

    def test_root_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_create_folder({"path": "/"})


# -- plan_move / plan_copy -----------------------------------------------

class TestPlanMove:
    def test_basic(self):
        body = plan_move({"from_path": "/a.txt", "to_path": "/b.txt"})
        assert body["from_path"] == "/a.txt"
        assert body["to_path"] == "/b.txt"

    def test_root_from_raises(self):
        with pytest.raises(DomainError, match="from_path"):
            plan_move({"from_path": "/", "to_path": "/b"})

    def test_root_to_raises(self):
        with pytest.raises(DomainError, match="to_path"):
            plan_move({"from_path": "/a", "to_path": "/"})


class TestPlanCopy:
    def test_basic(self):
        body = plan_copy({"from_path": "/a.txt", "to_path": "/copy.txt"})
        assert body["from_path"] == "/a.txt"
        assert body["to_path"] == "/copy.txt"

    def test_root_from_raises(self):
        with pytest.raises(DomainError, match="from_path"):
            plan_copy({"from_path": "/", "to_path": "/b"})


# -- plan_delete ---------------------------------------------------------

class TestPlanDelete:
    def test_basic(self):
        body = plan_delete({"path": "/old.txt"})
        assert body["path"] == "/old.txt"

    def test_root_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_delete({"path": "/"})


# -- plan_upload ---------------------------------------------------------

class TestPlanUpload:
    def test_basic(self):
        import json
        api_arg_json, content_bytes = plan_upload({
            "path": "/test.txt",
            "content": "hello world",
        })
        api_arg = json.loads(api_arg_json)
        assert api_arg["path"] == "/test.txt"
        assert api_arg["mode"] == "add"
        assert content_bytes == b"hello world"

    def test_overwrite_mode(self):
        import json
        api_arg_json, _ = plan_upload({
            "path": "/test.txt",
            "content": "x",
            "mode": "overwrite",
        })
        assert json.loads(api_arg_json)["mode"] == "overwrite"

    def test_empty_content_raises(self):
        with pytest.raises(DomainError, match="content"):
            plan_upload({"path": "/x.txt", "content": ""})

    def test_root_path_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_upload({"path": "/", "content": "x"})


# -- plan_create_shared_link ---------------------------------------------

class TestPlanCreateSharedLink:
    def test_basic(self):
        body = plan_create_shared_link({"path": "/Public/doc.pdf"})
        assert body["path"] == "/Public/doc.pdf"

    def test_root_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_create_shared_link({"path": "/"})


# -- plan_list_revisions -------------------------------------------------

class TestPlanListRevisions:
    def test_basic(self):
        body = plan_list_revisions({"path": "/file.txt"})
        assert body["path"] == "/file.txt"
        assert body["limit"] == 10

    def test_custom_limit(self):
        body = plan_list_revisions({"path": "/file.txt", "limit": 50})
        assert body["limit"] == 50

    def test_root_raises(self):
        with pytest.raises(DomainError, match="root"):
            plan_list_revisions({"path": "/"})


# -- view helpers --------------------------------------------------------

class TestEntryView:
    def test_file_entry(self):
        entry = {
            ".tag": "file",
            "name": "report.pdf",
            "path_lower": "/reports/report.pdf",
            "path_display": "/Reports/report.pdf",
            "id": "id:abc",
            "size": 1024,
            "content_hash": "hash123",
            "server_modified": "2024-01-01T00:00:00Z",
        }
        view = entry_view(entry)
        assert view["type"] == "file"
        assert view["name"] == "report.pdf"
        assert view["size"] == 1024
        assert view["content_hash"] == "hash123"

    def test_folder_entry(self):
        entry = {".tag": "folder", "name": "Projects", "path_display": "/Projects", "id": "id:xyz"}
        view = entry_view(entry)
        assert view["type"] == "folder"
        assert view["name"] == "Projects"
        assert "size" not in view

    def test_with_sharing_info(self):
        entry = {".tag": "file", "name": "x.txt", "sharing_info": {"read_only": True}}
        view = entry_view(entry)
        assert view["sharing_info"] == {"read_only": True}


class TestSearchMatchView:
    def test_basic(self):
        match = {
            "metadata": {".tag": "file", "name": "report.pdf", "path_display": "/report.pdf"},
            "match_type": {".tag": "filename"},
        }
        view = search_match_view(match)
        assert view["match_type"] == "filename"
        assert view["metadata"]["name"] == "report.pdf"


class TestRevisionView:
    def test_basic(self):
        rev = {"name": "file.txt", "id": "id:1", "server_modified": "2024-01-01", "size": 100, "content_hash": "h"}
        view = revision_view(rev)
        assert view["name"] == "file.txt"
        assert view["size"] == 100
        assert view["server_modified"] == "2024-01-01"
