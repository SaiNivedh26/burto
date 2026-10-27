"""
Desktop notification when burto blocks/steers an action.
Fires notify-send (Linux) or osascript (macOS) in a background thread.
On Linux, waits for user action and auto-calls the approve endpoint if clicked.
Never raises into the evaluator.
"""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import urllib.request

log = logging.getLogger("burto.notifier")

_BURTO_URL = os.getenv("BURTO_URL", "http://localhost:8000")


def _call_approve(decision_id: str) -> None:
    """POST to the approve endpoint — used when developer clicks Approve in notification."""
    try:
        req = urllib.request.Request(
            f"{_BURTO_URL}/decisions/{decision_id}/approve",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
        log.info("notification approve called for decision=%s", decision_id)
    except Exception as e:
        log.debug("approve call failed: %s", e)


def _notify_linux(decision_id: str, tool_name: str, reason: str, is_steer: bool = False) -> None:
    short = reason[:100].replace('"', "'")
    approve_url = f"{_BURTO_URL}/decisions/{decision_id}/approve"
    title = f"burto {'steered' if is_steer else 'blocked'}: {tool_name}"
    body = f"{short}\n→ {approve_url}"
    try:
        # notify-send blocks until user acts or notification expires
        result = subprocess.run(
            ["notify-send", "--urgency=normal", "--expire-time=15000",
             "--action=approve:✓ Approve", "--action=dismiss:✗ Dismiss",
             title, body],
            capture_output=True, timeout=20, check=False,
        )
        action = (result.stdout or b"").decode().strip()
        if action == "approve":
            _call_approve(decision_id)
            log.info("one-click approve: decision=%s tool=%s", decision_id, tool_name)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        pass  # notification expired without user action


def _notify_mac(decision_id: str, tool_name: str, reason: str, is_steer: bool = False) -> None:
    short = reason[:80].replace('"', '\\"').replace("'", "\\'")
    verb = "steered" if is_steer else "blocked"
    script = (
        f'display notification "{short}" with title "burto {verb}: {tool_name}" '
        f'subtitle "Approve: {_BURTO_URL}/decisions/{decision_id}/approve"'
    )
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5, check=False)
    except FileNotFoundError:
        pass


def notify_block(decision_id: str, tool_name: str, reason: str, is_steer: bool = False) -> None:
    """Fire a desktop notification in a background thread. On Linux, handles click-to-approve."""
    def _run():
        try:
            if sys.platform == "darwin":
                _notify_mac(decision_id, tool_name, reason, is_steer=is_steer)
            elif sys.platform.startswith("linux") and shutil.which("notify-send"):
                _notify_linux(decision_id, tool_name, reason, is_steer=is_steer)
        except Exception as e:
            log.debug("notification failed: %s", e)

    threading.Thread(target=_run, daemon=True, name="burto-notify").start()
