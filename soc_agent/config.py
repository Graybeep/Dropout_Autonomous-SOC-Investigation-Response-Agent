"""Paths, model configuration and environment loading.

Everything that touches the filesystem resolves through here so that the
seed/run split (CLAUDE.md 5.2) is enforced in exactly one place.
"""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SEED_DIR = ROOT / "fixtures" / "seed"
RUN_DIR = ROOT / "fixtures" / "run"
TRACE_DIR = ROOT / "traces"
REPORT_DIR = ROOT / "reports"

# Files inside the run directory. Tools read and write ONLY these.
ALERTS = "alerts.json"
PACKET_LOGS = "packet_logs.json"
ASSET_INVENTORY = "asset_inventory.json"
CVE_KB = "cve_kb.json"
SERVER_LOGS = "server_logs.json"
FIREWALL_STATE = "firewall_state.json"
CASES = "cases.json"  # created at runtime, not seeded


def load_dotenv(path: Path | None = None) -> None:
    """Minimal .env loader. Does not overwrite variables already in the environment."""
    path = path or (ROOT / ".env")
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_dotenv()

# --- Model / provider -------------------------------------------------------
# CLAUDE.md section 2 settles on Claude's native tool-use API. The operator
# supplied a Nara Router key instead, which exposes BOTH an OpenAI-compatible
# /chat/completions surface and an Anthropic-compatible /messages surface.
# We target the Anthropic-compatible surface so the tool-use architecture in
# section 2 is preserved verbatim and swapping back to api.anthropic.com is a
# one-line change to SOC_BASE_URL. See Toknow/DECISIONS.md entry D-002.
API_KEY = os.environ.get("SOC_API_KEY", "")
BASE_URL = os.environ.get("SOC_BASE_URL", "https://router.naraya.ai/v1")
MODEL = os.environ.get("SOC_MODEL", "qwen-3.8-flash")
API_STYLE = os.environ.get("SOC_API_STYLE", "openai")  # "openai" | "anthropic"

MAX_TOKENS = int(os.environ.get("SOC_MAX_TOKENS", "4096"))
TEMPERATURE = float(os.environ.get("SOC_TEMPERATURE", "0"))

# Rate-limit handling. The free tier enforces a per-minute request cap and an
# agent loop is bursty, so requests are paced and 429/5xx are retried with
# exponential backoff.
MIN_INTERVAL = float(os.environ.get("SOC_MIN_INTERVAL", "3.0"))
RETRY_MAX = int(os.environ.get("SOC_RETRY_MAX", "5"))
RETRY_BASE = float(os.environ.get("SOC_RETRY_BASE", "15.0"))

# Hard ceiling on agent loop turns, so a confused model cannot spin forever.
MAX_TURNS_PER_PHASE = int(os.environ.get("SOC_MAX_TURNS", "14"))
