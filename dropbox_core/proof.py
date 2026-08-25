"""SHA-256 event-chain proof builder for Dropbox Airlock.

Every successful command builds a deterministic event chain:
  intent_validated -> [state_observed | precondition_verified]
                   -> [decision_planned] -> [mutation_verified]

The chain is SHA-256 hashed sequentially: each event's hash incorporates
the previous event's hash, making tampering detectable. RailCall seals
this proof inside its Ed25519-signed receipt.
"""

import hashlib
import json


def _canonical(value):
    """Deterministic JSON encoding (sorted keys, no extra whitespace)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def build_safety_proof(command_id, inputs, stamp, events):
    """Build a SHA-256 event chain proof from the command's event list.

    Args:
        command_id: The command id from module.json (e.g. "dropbox.list_folder").
        inputs:     The validated inputs dict passed to the handler.
        stamp:      RailCall runtime stamp (dict or None) carrying
                    receipt_id, timestamp, approval hash, etc.
        events:     Ordered list of (event_name, event_data) tuples.

    Returns:
        A dict with the chain hash, individual event hashes, and metadata.
    """
    stamp_data = stamp if isinstance(stamp, dict) else {}

    chain = []
    prev_hash = "0" * 64

    for event_name, event_data in events:
        event_payload = {
            "command": command_id,
            "event": event_name,
            "data": event_data,
            "prev": prev_hash,
        }
        event_bytes = _canonical(event_payload).encode("utf-8")
        event_hash = hashlib.sha256(event_bytes).hexdigest()
        chain.append({
            "event": event_name,
            "hash": event_hash,
        })
        prev_hash = event_hash

    root_hash = prev_hash

    proof = {
        "command": command_id,
        "chain_root": root_hash,
        "events": chain,
        "input_hash": hashlib.sha256(
            _canonical(inputs).encode("utf-8")
        ).hexdigest(),
        "stamp_hash": hashlib.sha256(
            _canonical(stamp_data).encode("utf-8")
        ).hexdigest(),
    }

    return proof
