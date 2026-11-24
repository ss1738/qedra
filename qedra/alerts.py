"""Ready-made block alerts for the Agent Control Plane.

`ControlPlane(..., on_block=cb)` calls `cb(action, reason)` whenever the gate blocks an action. This
module supplies drop-in callbacks so wiring an alert is one line:

    from qedra.alerts import webhook_alert
    ControlPlane(agent_id, policy, on_block=webhook_alert("https://hooks.slack.com/services/..."))

The callback is best-effort: a slow or dead endpoint never breaks the gate (the Control Plane also
guards on_block, so this is belt-and-suspenders). Uses only the standard library.
"""
from __future__ import annotations

import json
import logging
import urllib.request


def webhook_alert(url: str, timeout: float = 5.0):
    """Return an on_block callback that POSTs a JSON alert to `url` (Slack-compatible `text` field).
    Network failures are swallowed so alerting can never break the gate."""
    def _alert(action, reason: str) -> None:
        # Never forward the blocked command: it may contain the very secret
        # whose exfiltration the gate just stopped.
        what = getattr(action, "kind", "action")
        reason = "blocked by configured policy"
        body = json.dumps({
            "text": f"qedra BLOCKED: {what}  ({reason})",
            "verdict": "BLOCK",
            "action": what,
            "reason": reason,
        }).encode()
        try:
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as response:
                response.read(1024)
        except Exception as exc:
            logging.getLogger(__name__).warning("Webhook failed (%s)", type(exc).__name__)
    return _alert
