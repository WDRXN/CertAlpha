"""Structured error contract for CertAlpha (Xyberix JSON error format)."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional


class CertAlphaError(Exception):
    """Operational error with machine-readable status/code/message/suggestion."""

    def __init__(
        self,
        code: str,
        message: str,
        suggestion: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.suggestion = suggestion
        self.details: Dict[str, Any] = details or {}

    def to_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "status": "ERROR",
            "code": self.code,
            "message": self.message,
            "suggestion": self.suggestion,
        }
        if self.details:
            payload["details"] = self.details
        return payload

    def to_json(self) -> str:
        return json.dumps(self.to_payload(), indent=2, default=str)

    def render(self) -> str:
        lines = [
            "[ERROR] %s" % self.code,
            "  message   : %s" % self.message,
        ]
        if self.suggestion:
            lines.append("  suggestion: %s" % self.suggestion)
        return "\n".join(lines)
