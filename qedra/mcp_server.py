"""qedra as an MCP server (package entry point).

MCP (Model Context Protocol) is the tool-call surface that Claude Desktop, Cursor,
Copilot, Windsurf and other agents speak. This server exposes the usual coding-agent
tools (run_shell, write_file, git) but routes every call through the guardrail before
executing it, so the tool call is gated in the actual protocol path, not by trusting
the agent. Any MCP client that points at this server gets the gate for free.

Install and run:

    pip install 'qedra[mcp]'
    qedra-mcp

Point an MCP client at it (e.g. Claude Desktop / Cursor):

    "qedra": {
      "command": "qedra-mcp",
      "env": {"GUARDRAIL_WORKSPACE": "/path/to/your/repo"}
    }

Configuration is entirely by environment variable, so one install serves every repo:
  GUARDRAIL_WORKSPACE   repo the agent operates on (default: ./workspace)
  GUARDRAIL_AGENT_ID    agent identity bound into the receipt (default: agent)
  GUARDRAIL_POLICY_ID   committed policy name (default: default-policy)
  GUARDRAIL_PRESET      comma-separated opt-in presets, e.g. 'devops' (cloud/DB kill-commands)
  GUARDRAIL_POLICY_SPEC path to a PolicySpec JSON (protected branches, extra patterns)
  GUARDRAIL_SIGNING_KEY hex 32-byte Ed25519 seed to pin one identity across runs
  GUARDRAIL_AUDIT_LOG   path to stream every gated action to disk (survives a crash)
  GUARDRAIL_ALERT_URL   Slack-compatible webhook fired on every block
  GUARDRAIL_ZK          1|modp|ec to attach zero-knowledge proofs to git actions
"""
import json
import os
from typing import Annotated


def _signing_key():
    """Ed25519 key for the session receipt. Persist it via GUARDRAIL_SIGNING_KEY (hex 32-byte seed) so
    a relying party can pin one identity across runs; otherwise ephemeral (public key is in the receipt)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    seed = os.environ.get("GUARDRAIL_SIGNING_KEY", "")
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed)) if seed else Ed25519PrivateKey.generate()


def build_server():
    """Construct the FastMCP server from the environment and register the gated tools.

    The `mcp` import is deferred so the base package installs and imports without the
    optional `mcp` extra; it is only required when the server is actually run."""
    try:
        from mcp.server.fastmcp import FastMCP
        from pydantic import Field
    except ImportError as exc:  # pragma: no cover - depends on optional extra
        raise SystemExit(
            "The MCP server needs the 'mcp' extra. Install it with:\n"
            "    pip install 'qedra[mcp]'"
        ) from exc

    from qedra.guardrail import Guardrail
    from qedra.executor import Executor
    from qedra.control_plane import ControlPlane, Policy
    from qedra.audit_log import AuditLog, verify_entries
    from qedra.alerts import webhook_alert

    workspace = os.environ.get("GUARDRAIL_WORKSPACE", os.path.join(os.getcwd(), "workspace"))
    os.makedirs(workspace, exist_ok=True)

    agent_id = os.environ.get("GUARDRAIL_AGENT_ID", "agent")
    zk_env = os.environ.get("GUARDRAIL_ZK", "").lower()
    zk = zk_env if zk_env in ("modp", "ec") else (zk_env in ("1", "true", "yes"))

    # One spec from the environment (default threat model + optional PolicySpec file + opt-in presets),
    # used for BOTH the enforcing gate and the receipt's committed policy, so what is blocked and what the
    # receipt commits to are the same ruleset. Reuses the hook's loader so the two integrations agree.
    from qedra.policy_config import policy_from_environment
    spec = policy_from_environment()
    guard = Guardrail(spec)
    policy = Policy(os.environ.get("GUARDRAIL_POLICY_ID", "default-policy"), spec=spec)
    audit = AuditLog(os.environ["GUARDRAIL_AUDIT_LOG"]) if os.environ.get("GUARDRAIL_AUDIT_LOG") else None
    alert = webhook_alert(os.environ["GUARDRAIL_ALERT_URL"]) if os.environ.get("GUARDRAIL_ALERT_URL") else None
    control = ControlPlane(agent_id, policy, signing_key=_signing_key(), zk=zk, audit_log=audit, on_block=alert)
    if audit is not None:
        entries = AuditLog.load(audit.path)
        ok, why = verify_entries(entries)
        if not ok:
            raise ValueError(why)
        control.resume(entries)
    ex = Executor(workspace, guard, control_plane=control)

    mcp = FastMCP("qedra")

    @mcp.tool()
    def run_shell(cmd: Annotated[str, Field(description="Bash command to run from the configured workspace, for example 'ls -la'. Do not include credentials or secret values.")]) -> str:
        """Execute a Bash command after heuristic policy checks. Use for build,
        test or inspection commands, not file writes or structured Git operations.
        Returns truncated stdout/stderr, or a refusal prefixed with ⛔. BLOCK and
        ESCALATE decisions are not executed. Shell execution is not sandboxed;
        passing a check does not establish that a command is safe."""
        return ex.run_shell(cmd)

    @mcp.tool()
    def write_file(
        path: Annotated[str, Field(description="Destination file path relative to the configured workspace, for example 'src/config.json'. Paths outside the workspace are refused.")],
        content: Annotated[str, Field(description="Complete replacement text for the file, not a patch. Existing content is overwritten. Do not include secrets.")],
    ) -> str:
        """Create or overwrite one workspace file after policy checks. Creates
        parent directories as needed. Recognized secret values and empty workflow
        writes are blocked. Returns a write summary or a refusal prefixed with ⛔.
        This is a whole-file replacement; read and preserve needed content first."""
        return ex.write_file(path, content)

    @mcp.tool()
    def git(args: Annotated[str, Field(description="Git subcommand and arguments without a leading 'git', for example 'status --short' or 'commit -m \"fix input\"'. Shell syntax and global options such as -C are not supported.")]) -> str:
        """Execute Git in the workspace after structured branch-policy checks.
        Use this rather than run_shell for Git operations. Protected-branch force
        pushes, hard resets and rebases are blocked; unresolved force destinations
        are refused for human review. Quoting is preserved. Returns truncated
        stdout/stderr or a refusal prefixed with ⛔; it is not a proof of success."""
        return ex.git(args)

    @mcp.tool()
    def audit_log() -> str:
        """Return the tamper-evident audit chain of every guardrail decision so far."""
        return json.dumps({"chain_verifies": guard.verify_chain(),
                           "blocked": ex.blocked, "executed": ex.executed,
                           "log": guard.log}, indent=2)

    @mcp.tool()
    def policy_info() -> str:
        """Report the exact ruleset being enforced: the committed policy id and root (content hash), the
        protected branches, and any opt-in presets/extra patterns. A relying party can hold the same spec
        and confirm the receipt's policy root matches, so 'the gate enforces this policy' is checkable,
        not a promise."""
        return json.dumps({
            "policy_id": policy.policy_id, "version": policy.version, "policy_root": policy.root(),
            "protected_branches": list(spec.protected_branches),
            "presets": [p for p in os.environ.get("GUARDRAIL_PRESET", "").split(",") if p.strip()],
            "extra_shell_denylist": len(spec.extra_shell_denylist),
            "extra_secret_patterns": len(spec.extra_secret_patterns),
        }, indent=2)

    @mcp.tool()
    def session_receipt(redact: Annotated[bool, Field(description="Set true to omit raw commands, file contents, branch names and salts before sharing. False returns private action data; do not share it without inspection.")] = False) -> str:
        """Export a signed statement of recorded decisions. Verification checks its
        signature, chain and disclosed policy verdicts, not execution or completeness.
        Use an independently obtained policy and pinned key for attribution.

        redact=True strips every raw action (commands, file contents, branches) before returning. In
        zk-mode (GUARDRAIL_ZK=1) git-branch actions stay provably in-policy via their zero-knowledge proof
        even when redacted; other actions keep integrity + authenticity only."""
        r = ex.receipt()
        if r is None:
            return json.dumps({"error": "no control plane attached"})
        if redact:
            r, _ = r.redact(reveal=())
        return r.to_json()

    return mcp


def main():
    """Console entry point: build the server from the environment and serve over stdio."""
    build_server().run()


if __name__ == "__main__":
    main()
