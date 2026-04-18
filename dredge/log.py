from __future__ import annotations

import json
import logging
from typing import Any


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def event(event_type: str, event_name: str, **details: Any) -> str:
    """Return a JSON-serialisable structured log message string."""
    return json.dumps(
        {"event_type": event_type, "event_name": event_name, **details},
        default=str,
    )
