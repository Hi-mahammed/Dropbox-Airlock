import json
import sys
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.sign_module import canonical, tree_manifest


class SignatureTests(unittest.TestCase):
    def test_module_signature_verifies(self):
        manifest = json.loads((ROOT / "module.json").read_text(encoding="utf-8"))
        handler = (ROOT / "handlers" / "handler.py").read_bytes()
        signature = bytes.fromhex((ROOT / "module.sig").read_text().strip())
        canonical_manifest = canonical(
            {key: value for key, value in manifest.items() if key != "signature"}
        )
        tail = tree_manifest(ROOT) if int(manifest.get("manifest_version") or 1) >= 2 else handler
        payload = canonical_manifest + b"\n" + tail
        Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(manifest["publisher_pubkey"])
        ).verify(signature, payload)


if __name__ == "__main__":
    unittest.main()
