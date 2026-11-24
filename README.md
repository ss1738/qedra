# qedra

[![CI](https://github.com/ss1738/qedra/actions/workflows/ci.yml/badge.svg)](https://github.com/ss1738/qedra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![ss1738/qedra MCP server](https://glama.ai/mcp/servers/ss1738/qedra/badges/score.svg)](https://glama.ai/mcp/servers/ss1738/qedra)

qedra checks coding-agent tool calls before execution. It provides a local MCP
server, a Claude Code permission hook, and a Python adapter for function-calling
loops. The gate blocks selected destructive Git, shell, and file operations and
can export signed receipts of recorded decisions.

**Status:** experimental, single-maintainer software. Shell checks are bypassable
heuristics. The executor is not a sandbox, and receipts do not independently prove
that commands ran or that the operator recorded every action.

## Install from this repository

Requires Python 3.10 or later, Git, and Bash for shell execution.

```bash
git clone https://github.com/ss1738/qedra.git
cd qedra
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[mcp]'
qedra-mcp
```

The MCP integration uses the MCP Python SDK 1.x (`mcp>=1.0,<2`). Installing from
this checkout avoids assuming that an unreleased repository change is on PyPI.
The base package can be installed with `pip install -e .` without MCP support.

## What the policy checks

| Surface | Check | Limit |
|---|---|---|
| Structured Git actions | Force-push, hard reset, and rebase against configured protected branches | z3 checks a finite policy model, not the Python parser, Git itself, or every history-changing command |
| Shell commands | Patterns for repo/home/root deletion, secret exposure, cloud metadata access, reverse shells, and persistence | Default allow; obfuscation and unrecognized forms can bypass the checks |
| File writes | Recognized secret values and empty `.github/workflows/` content | Does not analyze general source changes or validate workflow semantics |
| Optional `devops` preset | Patterns for selected infrastructure, database, and package deletion commands | Off by default; heuristic |

Protected branches default to `main`, `master`, and `release`. A structured Git
call with an unresolved force-push destination is refused for human review.
Global Git options such as `-C` are refused by the executor. Normal arguments are
parsed with `shlex`, so quoted commit messages remain intact.

A write-path check refuses paths outside the workspace. Shell commands still run
with the gate process's filesystem access, environment, credentials, and network
permissions. Put the process inside a separately configured OS/container sandbox;
a working directory alone does not provide isolation. Do not expose the server to
untrusted callers with access to your personal credentials.

Read [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY.md](SECURITY.md) before use.

## MCP client configuration

After installation, merge this entry into your client's `mcpServers` object. Use
an absolute executable path if the client does not inherit your virtualenv PATH.

```json
{
  "mcpServers": {
    "qedra": {
      "command": "/absolute/path/to/qedra/.venv/bin/qedra-mcp",
      "env": {
        "GUARDRAIL_WORKSPACE": "/absolute/path/to/working/repo"
      }
    }
  }
}
```

Tools: `run_shell`, `write_file`, `git`, `audit_log`, `policy_info`, and
`session_receipt`. Calls made through other tools bypass this gate.

| Variable | Meaning |
|---|---|
| `GUARDRAIL_WORKSPACE` | Working repository; defaults to `./workspace` |
| `GUARDRAIL_AGENT_ID` | Receipt identity label; default `agent` |
| `GUARDRAIL_POLICY_ID` | Policy label; default `default-policy` in MCP, `claude-code` in the hook |
| `GUARDRAIL_PRESET` | Comma-separated optional presets, currently `devops` |
| `GUARDRAIL_POLICY_SPEC` | Path to JSON policy data |
| `GUARDRAIL_SIGNING_KEY` | MCP only: hex-encoded 32-byte Ed25519 seed; otherwise an ephemeral key is generated |
| `GUARDRAIL_SIGNING_KEY_FILE` | Attestation CLI default key path; defaults to `~/.qedra/signing_key` |
| `GUARDRAIL_AUDIT_LOG` | Optional JSONL decision log; use a separate file per MCP server/session |
| `GUARDRAIL_ALERT_URL` | Optional webhook; sends action kind and generic reason, not raw commands |
| `GUARDRAIL_ZK` | MCP only: `1`, `modp`, or `ec` enables experimental Git-policy proofs |

Keep audit files, signing keys, policy data, and the gate source inaccessible to
the agent. Audit files contain raw actions, including blocked secret values.
New audit files are created with mode 600; existing file permissions are preserved.
Hook log transactions use POSIX file locks; do not share one log between MCP
servers or mix MCP and hook writers. Audit failures are reported but do not stop
the gate, so a failed log sink can leave the on-disk trail incomplete.

## Claude Code hook

```bash
qedra-hook --print-config
```

Merge the printed hook into `.claude/settings.json`. It matches `Bash` by default;
use `Bash|Write|Edit` to include file operations. `Edit` checks replacement text,
not the final whole file. An empty replacement in a workflow can therefore be
blocked even when the edit would leave other content in place.

The hook denies `BLOCK`, asks the user for `ESCALATE`, and permits `ALLOW`.
**Internal errors fail open:** malformed input or invalid configuration can allow
a call. Errors are printed to stderr. This is an availability tradeoff, not a
fail-closed security boundary.

The hook runs before a tool. Its audit entries record permission decisions with
`executed=false`; they do not observe the eventual command outcome.

```bash
export GUARDRAIL_AUDIT_LOG=/absolute/private/path/session.jsonl
# Run your Claude Code session, then attest its permission-decision log:
qedra-attest "$GUARDRAIL_AUDIT_LOG" --policy-id claude-code \
  --agent-id my-agent --out receipt.json
qedra-verify receipt.json --policy-id claude-code --pin-key PUBLIC_KEY_HEX
```

Replace `PUBLIC_KEY_HEX` with the public key printed by `qedra-attest`. If you used
custom policy data or presets, pass the same `--policy-spec` / `--preset` to
attestation and supply that policy data to the verifier. A verifier must obtain
its expected public key and policy through a trusted channel.

## Python tool adapter

```python
from qedra.control_plane import ControlPlane, Policy
from qedra.tool_gate import ToolGate, openai_tools

gate = ToolGate("/path/to/repo", control_plane=ControlPlane("agent", Policy("local")))
tools = openai_tools()  # OpenAI Chat Completions schema; not Responses format
result = gate.handle("write_file", {"path": "notes.txt", "content": "hello"})
receipt = gate.receipt()
```

`anthropic_tools()` returns Anthropic tool definitions. The adapter refuses
unknown tools, missing arguments, and non-string input fields. It uses the same
executor as MCP and inherits its isolation limits.

## Receipts and policy data

```bash
qedra-policy init --protected main,release --out policy.json
qedra-policy show policy.json --policy-id local
qedra-redact receipt.json --out redacted.json --witness witness.json
qedra-verify redacted.json --witness witness.json --pin-key PUBLIC_KEY_HEX
qedra-serve --policy-id local --host 127.0.0.1
```

Verification checks policy identity, the signed chain, and policy verdicts for
disclosed actions. Redacted entries without a disclosure witness or supported ZK
proof have no verdict soundness check. Identity requires a pinned key or a trusted
registry. A signer can omit actions or create an entirely different compliant
trace, so a valid receipt is not independent evidence of execution or completeness.
Unsigned audit chains cannot detect tail truncation or a complete recomputation.
See [the receipt trust model](docs/CONTROL_PLANE_TRUST_MODEL.md).

Both ZK backends are experimental custom cryptography without an external audit.
They cover only a projection of selected Git actions, not shell/file operations or
execution. See [docs/ZK_ROADMAP.md](docs/ZK_ROADMAP.md).

## Development and validation

```bash
pip install -e '.[mcp,dev]'
python3 -m pytest -q
python3 -m ruff check qedra
python3 demo_receipt.py
python3 demo_attest.py
python3 demo_claude_hook.py
python3 integrations/demo_mcp.py
```

`demo_claude_hook.py` supplies synthetic payloads to the real hook classifier; it
does not launch Claude Code or execute the proposed commands. The MCP demo uses
an actual local stdio client/server connection. No API key is needed for either.
`demo_hijack.py` is a separate opt-in API experiment requiring an Anthropic key and
an explicitly selected model.

`realworld_test.py` and `scripts/expanded_realworld.py` fetch changing GitHub
workflow samples and classify command text without executing it. Historical
claims of 2,836 / 2,848 / 3,790 commands do not have a frozen corpus and result
artifact in this repository. They are not current reproducible performance
baselines. Neither script measures adversarial detection or end-to-end security.

The z3 proof is a check of a manually modeled sub-policy. It does not verify the
Python implementation. Tests complement the model but do not prove the absence
of bugs. Run Rust/cargo commands only on an appropriately isolated build host.

## Reporting issues

For bugs, include the exact tool call, configuration without secrets, observed
verdict, and expected behavior. See [SECURITY.md](SECURITY.md) for sensitive reports.

Maintained by [Satyawan Singh (@ss1738)](https://github.com/ss1738). MIT licensed.
