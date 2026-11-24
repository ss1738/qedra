# Why qedra checks tool calls

A coding agent can propose a destructive operation while carrying out an ordinary
repository task. qedra checks calls routed through its Git, file, and shell tools
before execution. The policy returns `ALLOW`, `BLOCK`, or `ESCALATE`.

The implementation combines a small structured Git policy with pattern checks for
selected destructive shell commands, secret exposure, and empty CI files. A z3
model checks the Git sub-policy for admitted protected-history rewrites. This is
a model check, not verification of the Python executor or shell parser.

The project also records decisions in hash chains and exports Ed25519-signed
receipts. A verifier can check consistency, key attribution, and verdicts for
disclosed actions. A receipt cannot prove that the operator recorded every
operation or truthfully reported execution. Experimental ZK proofs hide a limited
Git-policy projection; neither backend has received an external security audit.

The demonstrations serve different purposes:

- `demo_claude_hook.py` classifies synthetic hook payloads. It does not launch an
  agent or execute those commands.
- `integrations/demo_mcp.py` makes calls through a local MCP client/server pair.
- `demo_compare.py` runs a fixed sequence with and without the gate in temporary
  directories. It deliberately deletes temporary Git metadata in the unguarded run.
- `demo_hijack.py` is an optional Anthropic API experiment. Model behavior and
  availability vary; it requires explicit credentials and model selection.

Historical workflow-sample counts appeared in earlier project copy without a
frozen corpus or result artifact in the repository. They should not be treated as
current reproducible benchmarks. The workflow sampling scripts classify text and
do not measure attack-detection accuracy.

Use the [README](README.md) for installation and current checks,
[THREAT_MODEL.md](THREAT_MODEL.md) for scope, and
[the receipt trust model](docs/CONTROL_PLANE_TRUST_MODEL.md) for verification limits.
