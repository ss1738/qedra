"""`qedra-attest`: turn an agent session's audit log into a signed, verifiable receipt.

The hook (`qedra-hook` with GUARDRAIL_AUDIT_LOG set) appends every gated action to a durable, hash-chained
JSONL log as the agent runs. This command reconstructs that log into a single Ed25519-signed Receipt that any
verifier can check with `qedra-verify` using an expected policy and public key.
The signature attributes the statement; it does not prove complete observation.

    qedra-attest session.jsonl --agent-id my-agent --out receipt.json
    qedra-verify receipt.json --pin-key <printed-public-key>

The signing key lives at ~/.qedra/signing_key (raw Ed25519, hex, mode 600) and is generated on first use.
Its public key is printed so a relying party can pin the agent's identity to it. The log's integrity is
checked first. A truncated or fully recomputed unsigned chain can still pass. Exit 0 = attested, 1 = the
log failed its integrity check or was unreadable, 2 = usage error.
"""
from __future__ import annotations

import argparse
import os
import sys
import tempfile

from .audit_log import receipt_from_log, verify_log
from .control_plane import Policy


def _load_or_create_key(path: str):
    """Load a raw Ed25519 private key from `path` (hex), or generate + persist one at mode 600."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = os.path.expanduser(path)
    key = Ed25519PrivateKey.generate()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    raw = key.private_bytes_raw().hex()
    # write with restrictive permissions from the start (do not widen a pre-existing file)
    if os.path.exists(path):
        with open(path) as fh:
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fh.read().strip()))
    fd, temporary = tempfile.mkstemp(prefix=".qedra-key-", dir=os.path.dirname(path) or ".")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.link(temporary, path)  # atomic publication; never replace another process's key
            return key
        except FileExistsError:
            with open(path) as fh:
                return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(fh.read().strip()))
    finally:
        os.unlink(temporary)


def _build_policy(args) -> Policy:
    from .policy_config import load_policy_spec
    spec = load_policy_spec(args.policy_spec, args.preset or "")
    return Policy(args.policy_id, args.policy_version, spec)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="qedra-attest",
        description="Sign an agent session's audit log into a verifiable receipt.",
    )
    p.add_argument("log", help="path to the audit log (JSONL) written by the hook via GUARDRAIL_AUDIT_LOG")
    p.add_argument("--agent-id", default=os.environ.get("GUARDRAIL_AGENT_ID", "qedra-agent"),
                   help="the agent identity this receipt is bound to")
    p.add_argument("--policy-id", default=os.environ.get("GUARDRAIL_POLICY_ID", "qedra"))
    p.add_argument("--policy-version", default=os.environ.get("GUARDRAIL_POLICY_VERSION", "1"))
    p.add_argument("--preset", help="comma-separated presets layered on the default spec (e.g. 'devops')")
    p.add_argument("--policy-spec", help="path to a PolicySpec JSON (overrides the built-in default)")
    p.add_argument("--key", default=os.environ.get("GUARDRAIL_SIGNING_KEY_FILE", "~/.qedra/signing_key"),
                   help="Ed25519 signing key file (created on first use, mode 600)")
    p.add_argument("--out", help="write the receipt JSON here (default: stdout)")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress the human-readable summary on stderr")
    args = p.parse_args(argv)

    if not os.path.exists(args.log):
        print(f"error: no such log: {args.log}", file=sys.stderr)
        return 1

    # integrity first: refuse to sign a tampered trail
    try:
        ok, why = verify_log(args.log)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print(f"error: could not read audit log ({type(exc).__name__})", file=sys.stderr)
        return 1
    if not ok:
        print(f"error: {why}; refusing to attest", file=sys.stderr)
        return 1

    try:
        policy = _build_policy(args)
        key = _load_or_create_key(args.key)
        receipt = receipt_from_log(args.log, args.agent_id, policy, key)
    except Exception as e:
        print(f"error: could not build receipt: {e}", file=sys.stderr)
        return 1

    out_json = receipt.to_json()
    if args.out:
        open(args.out, "w").write(out_json)
    else:
        print(out_json)

    if not args.quiet:
        n = len(receipt.entries)
        blocked = sum(1 for e in receipt.entries if e.verdict == "BLOCK")
        dest = args.out or "stdout"
        print(f"attested: {n} entries ({blocked} blocked), agent '{receipt.agent_id}' -> {dest}",
              file=sys.stderr)
        print(f"public key: {receipt.public_key}", file=sys.stderr)
        verify_target = args.out or "receipt.json"
        print(f"verify with:  qedra-verify {verify_target} --pin-key {receipt.public_key}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
