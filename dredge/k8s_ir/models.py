from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class OperationResult:
    """
    Standard result for an action. Helps you keep everything
    consistent and easy to log/serialize.
    """
    operation: str
    target: str
    success: bool
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    def add_error(self, message: str) -> None:
        self.errors.append(message)
        self.success = False
