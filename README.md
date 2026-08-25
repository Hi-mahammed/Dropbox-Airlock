# Dropbox Airlock — RailCall Module

A governed bridge to [Dropbox](https://www.dropbox.com). List, search, inspect, upload,
move, copy, delete, and share files and folders — every action reviewed, approved, and
recorded as a signed receipt through RailCall's airlock.

*Agents draft. You approve. Receipts prove.*

---

## Commands

| Command                     | Type   | Risk | What it does                                       |
|-----------------------------|--------|------|-----------------------------------------------------|
| `dropbox.list_folder`       | read   | low  | List contents of a folder (recursive option).      |
| `dropbox.get_metadata`      | read   | low  | Retrieve metadata for a file or folder.             |
| `dropbox.search`            | read   | low  | Search files and folders by name or content.        |
| `dropbox.list_revisions`    | read   | low  | List file revision history for rollback and audit.  |
| `dropbox.create_folder`     | write  | high | Create a new folder.                                |
| `dropbox.move`              | write  | high | Move a file or folder to a new path.                |
| `dropbox.copy`              | write  | high | Copy a file or folder to a new path.                |
| `dropbox.delete`            | write  | high | Delete a file or folder.                            |
| `dropbox.upload`            | write  | high | Upload text content as a new file.                  |
| `dropbox.create_shared_link`| write  | high | Create a shared link for a file or folder.          |

**Read commands** (`mode: read`, `risk: low`) execute immediately and return a signed
receipt with a SHA-256 event chain.

**Write commands** (`mode: write_requires_approval`, `risk: high`) are staged by the
airlock — you see a preview, approve, then the action fires and a receipt is signed.
Nothing reaches Dropbox without your approval. Approval is bound to the payload hash,
so an edited payload has no approval and cannot run.

---

## Architecture

```
dropbox/
├── module.json                  # v2 manifest: id, commands, auth, requires
├── handlers/
│   └── handler.py               # orchestration layer (dropbox_* functions)
├── dropbox_core/
│   ├── __init__.py
│   ├── domain.py                # pure validation + mutation planning (no I/O)
│   ├── transport.py             # fixed-origin HTTP + vault token resolution
│   └── proof.py                 # SHA-256 event chain builder
└── README.md
```

- **domain.py** — Pure input validation and mutation planning. Validates Dropbox paths
  (must start with `/`, root is `""`), clamps limits, parses boolean strings. No I/O.
- **transport.py** — The single network chokepoint. Handles Dropbox's two calling
  styles: RPC (JSON body) for most endpoints and content upload (Dropbox-API-Arg
  header + binary body) for file uploads. Reads the token from RailCall's vault only.
- **proof.py** — Deterministic SHA-256 event chain from intent through observation to
  verified outcome. Sealed inside RailCall's Ed25519-signed receipt.
- **handler.py** — Connects the three layers. Each function returns `(result, None)`
  on success or a structured error dict on failure.

---

## Setup

### 1. Create a Dropbox app

1. Go to **dropbox.com/developers/apps** and create a new app.
2. Choose **Scoped access** and select the scopes you need:
   - `files.content.read`, `files.content.write`
   - `files.metadata.read`
   - `sharing.write`
3. Generate an **access token**.

### 2. Connect in Studio

1. Install the module from the marketplace (or copy the signed folder into your
   station's modules directory).
2. Open Studio:
   ```
   railcall studio
   ```
3. Go to **Modules → Reload all**. The module appears with all ten commands.
4. Go to the **Integrations** tab and add your Dropbox token under the `dropbox`
   connection. The token is stored in the local vault and never leaves your machine.

---

## Using the commands

All commands run through Studio's command palette (or as workflow nodes, or via MCP
from Claude Desktop). There is no CLI runner — the airlock ceremony is the point.

**Example — list a folder:**
```json
{ "path": "/Projects", "recursive": "false", "limit": 50 }
```

**Example — search for files:**
```json
{ "query": "invoice 2024", "max_results": 10 }
```

**Example — upload a text file:**
```json
{
  "path": "/Reports/summary.txt",
  "content": "Q3 revenue exceeded expectations.",
  "mode": "add"
}
```

**Example — move a file:**
```json
{ "from_path": "/Drafts/report.pdf", "to_path": "/Final/report.pdf" }
```

**Example — create a shared link:**
```json
{ "path": "/Public/spec.pdf" }
```

Each call produces an Ed25519-signed receipt with an embedded SHA-256 event chain —
verifiable offline from Studio's **Runs** tab.

---

## Auth

Declared in `module.json` as `api_key` with `vault_provider: dropbox` and
`field: DROPBOX_API_KEY`. The token is configured once in Studio's **Integrations**
tab and read from RailCall's vault at runtime. It is never accepted as command input,
never logged, and never returned in any response.

## Network policy

The module declares `requires.network: ["api.dropboxapi.com", "content.dropboxapi.com"]`,
`subprocess: false`, and no filesystem writes. Only the Dropbox API can be reached.

## Notes

- Built against Dropbox API v2.
- Uses only the Python standard library — no third-party packages required.
- Free module (`license_required: false`).
- Tagged `contest:2026Q3` for the RailCall community contest.
