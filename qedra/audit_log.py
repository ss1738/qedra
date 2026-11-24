"""Durable, append-only audit log for the Agent Control Plane.

The Control Plane keeps the gated action trace in memory and signs a receipt at session end. If the
process crashes or is killed mid-run, that trace is lost. `AuditLog` appends every gated entry to a
JSONL file as it happens, so a dead agent still leaves a trail on disk.

Two properties the persisted log keeps:
  - Integrity (no key needed). The public SHA-256 hash-chain is recomputed over the file, so any
    inconsistent edits are caught by `verify_log`. Tail truncation and complete
    recomputation require an independently retained head/signature to detect.
  - Authenticity (needs the operator's key). `receipt_from_log` reconstructs a signed `Receipt` from
    the persisted entries, so the durable trail can still be handed to a relying party and verified
    with `verify_receipt` exactly like a live receipt.
"""
from __future__ import annotations

import json
import os
from contextlib import contextmanager
from dataclasses import asdict

from .control_plane import GENESIS, Entry, Receipt, _chain_step, _signing_payload


class AuditLog:
    """Append-only JSONL sink for gated entries. Pass an instance to `ControlPlane(audit_log=...)`;
    every recorded action is flushed to disk as it happens."""

    def __init__(self, path: str):
        self.path = path

    def append(self, entry: Entry) -> None:
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write(json.dumps(asdict(entry), separators=(",", ":")) + "\n")
            f.flush()
            os.fsync(f.fileno())   # durable: survive a crash right after the write

    @staticmethod
    def load(path: str) -> list[Entry]:
        entries: list[Entry] = []
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        entries.append(Entry(**json.loads(line)))
        return entries

    @contextmanager
    def locked(self):
        """Serialize hook read/resume/append transactions on POSIX hosts."""
        import fcntl

        fd = os.open(self.path + ".lock", os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def verify_log(path: str) -> tuple[bool, str]:
    """Check public chain consistency; not authenticity or completeness."""
    return verify_entries(AuditLog.load(path))


def verify_entries(entries: list[Entry]) -> tuple[bool, str]:
    """Check a single snapshot. An unsigned chain cannot detect tail truncation
    or a complete rewrite without an independently retained head/signature."""
    head = GENESIS
    for i, e in enumerate(entries):
        head = _chain_step(head, i, e.commit, e.verdict, e.reason, e.executed)
        if head != e.head:
            return False, f"log broken at entry {i}: the trail was altered"
    return True, f"intact: {len(entries)} entries"


def receipt_from_log(path: str, agent_id: str, policy, signing_key) -> Receipt:
    """Reconstruct a signed Receipt from a persisted log (needs the operator's Ed25519 key). Raises if
    the log is internally inconsistent. A recomputed or truncated chain can still pass."""
    from cryptography.hazmat.primitives import serialization

    entries = AuditLog.load(path)
    ok, why = verify_entries(entries)
    if not ok:
        raise ValueError(why)
    head = entries[-1].head if entries else GENESIS
    sig = signing_key.sign(_signing_payload(agent_id, policy.root(), head, len(entries))).hex()
    pub = signing_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    return Receipt(
        agent_id=agent_id, policy_id=policy.policy_id, policy_root=policy.root(),
        entries=entries, final_head=head, public_key=pub, signature=sig,
    )
