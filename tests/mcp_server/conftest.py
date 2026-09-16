"""Put the repo root and mcp_server/ on sys.path so `import server` and
`import dredge` resolve when running the MCP test package."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
for p in (_ROOT, _ROOT / "mcp_server"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))
