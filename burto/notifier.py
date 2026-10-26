"""
Desktop notification when burto blocks an action.
Fires notify-send (Linux) or osascript (macOS) in a background thread.
Never raises into the evaluator.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading

log = logging.getLogger("burto.notifier")

_BURTO_URL = os.getenv("BURTO_URL", "http://localhost:8000")


def _notify_linux(decision_id: str, tool_name: str, reason: str) -> None:
    short = reason[:80].replace('"', "'")
    approve_url = f"{_BURTO_URL}/decisions/{decision_id}/approve"
    # notify-send with actions (requires libnotify ≥ 0.7.9)
    try:
        subprocess.run(
            ["notify-send", "--urgency=normal", "--expire-time=10000",
             "--action=approve:Approve", "--action=reject:Dismiss",
             f"burto blocked: {tool_name}", short],
            capture_output=True, timeout=5, check=False,
        )
    except FileNotFoundError:
        pass  # no notify-send available


def _notify_mac(decision_id: str, tool_name: str, reason: str) -> None:
    short = reason[:80].replace('"', '\\"').replace("'", "\\'")
    script = (
        f'display notification "{short}" with title "burto blocked: {tool_name}" '
        f'subtitle "Click to approve at {_BURTO_URL}/decisions/{decision_id}/approve"'
    )
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5, check=False)
    except FileNotFoundError:
        pass


def notify_block(decision_id: str, tool_name: str, reason: str) -> None:
    """Fire a desktop notification in a background thread. Never blocks. Never raises."""
    def _run():
        try:
            if sys.platform == "darwin":
                _notify_mac(decision_id, tool_name, reason)
            elif sys.platform.startswith("linux") and shutil.which("notify-send"):
                _notify_linux(decision_id, tool_name, reason)
        except Exception as e:
            log.debug("notification failed: %s", e)

    threading.Thread(target=_run, daemon=True, name="burto-notify").start()
