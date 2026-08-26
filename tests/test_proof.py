"""Tests for the Dropbox Airlock module proof layer.

Validates SHA-256 event chain construction, determinism, and tamper detection.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dropbox_core.proof import build_safety_proof


class TestDropboxSafetyProof:
    def test_basic_chain(self):
        proof = build_safety_proof(
            "dropbox.list_folder", {"path": "/test"}, {"receipt_id": "rc_1"},
            [("intent_validated", {"path": "/test"}), ("state_observed", {"entries": []})],
        )
        assert proof["command"] == "dropbox.list_folder"
        assert len(proof["events"]) == 2
        assert len(proof["chain_root"]) == 64

    def test_deterministic(self):
        events = [("intent_validated", {"a": 1})]
        inputs = {"path": "/x"}
        stamp = {"receipt_id": "r"}
        p1 = build_safety_proof("dropbox.move", inputs, stamp, events)
        p2 = build_safety_proof("dropbox.move", inputs, stamp, events)
        assert p1["chain_root"] == p2["chain_root"]

    def test_different_events_different_chain(self):
        """Different event data produces different chain roots."""
        p1 = build_safety_proof("dropbox.delete", {}, {}, [("e", {"v": 1})])
        p2 = build_safety_proof("dropbox.delete", {}, {}, [("e", {"v": 2})])
        assert p1["chain_root"] != p2["chain_root"]

    def test_different_inputs_different_input_hash(self):
        """Different inputs produce different input_hash."""
        p1 = build_safety_proof("dropbox.delete", {"path": "/a"}, {}, [("e", {})])
        p2 = build_safety_proof("dropbox.delete", {"path": "/b"}, {}, [("e", {})])
        assert p1["input_hash"] != p2["input_hash"]

    def test_chain_tamper_detection(self):
        """Changing one event changes all subsequent hashes."""
        p1 = build_safety_proof("c", {}, {}, [("e1", {"v": 1}), ("e2", {"v": 2})])
        p2 = build_safety_proof("c", {}, {}, [("e1", {"v": 99}), ("e2", {"v": 2})])
        assert p1["events"][1]["hash"] != p2["events"][1]["hash"]
        assert p1["chain_root"] != p2["chain_root"]

    def test_empty_events_root_is_zeros(self):
        proof = build_safety_proof("dropbox.search", {}, {}, [])
        assert proof["chain_root"] == "0" * 64

    def test_key_order_independent(self):
        p1 = build_safety_proof("c", {"a": 1, "b": 2}, {}, [("e", {"x": 1, "y": 2})])
        p2 = build_safety_proof("c", {"b": 2, "a": 1}, {}, [("e", {"y": 2, "x": 1})])
        assert p1["chain_root"] == p2["chain_root"]

    def test_stamp_hash_changes(self):
        p1 = build_safety_proof("c", {}, {"id": "a"}, [])
        p2 = build_safety_proof("c", {}, {"id": "b"}, [])
        assert p1["stamp_hash"] != p2["stamp_hash"]
