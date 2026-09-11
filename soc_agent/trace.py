"""Structured trace.

CLAUDE.md 13: every tool call and every reasoning string is logged to a
structured trace (list of dicts -> JSON), not printed. The viewer and the
report both consume this trace; it is the single source of truth for both.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Step kinds rendered by viewer.html. Keep in sync with the renderer.
STATE_CHANGE = "state_change"
THOUGHT = "thought"
TOOL_CALL = "tool_call"
TOOL_RESULT = "tool_result"
TOOL_FAILURE = "tool_failure"
SUFFICIENCY = "sufficiency"
DISCONFIRMATION = "disconfirmation"
SCORING = "scoring"
CONCLUSION = "conclusion"
ACTION = "action"
VERIFICATION = "verification"
EVENT = "event"
RECONSIDER = "reconsider"
ERROR = "error"


@dataclass
class Trace:
    """An append-only list of step dicts for one case."""

    case_id: str
    scenario: str
    steps: list[dict[str, Any]] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    def add(self, kind: str, **payload: Any) -> dict[str, Any]:
        step = {
            "seq": len(self.steps) + 1,
            "t": round(time.time() - self.started_at, 3),
            "kind": kind,
            "case_id": self.case_id,
            **payload,
        }
        self.steps.append(step)
        return step

    # Convenience wrappers, so call sites read like the state machine in 6.
    def state(self, name: str, note: str = "") -> dict[str, Any]:
        return self.add(STATE_CHANGE, state=name, note=note)

    def thought(self, text: str) -> dict[str, Any]:
        return self.add(THOUGHT, text=text)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "scenario": self.scenario,
            "steps": self.steps,
        }


def save(payload: dict[str, Any], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
        fh.write("\n")
    return path
