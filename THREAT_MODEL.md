# Threat model

qedra checks selected operations proposed by coding agents. It reduces accidental
or direct destructive calls that pass through its tools. It is not a boundary
against an attacker who can execute arbitrary shell code with the gate's
credentials.

## Policy coverage

| Surface | Examples | Enforcement |
|---|---|---|
| Structured Git | Force-push, hard reset, or rebase of a protected branch | Finite structured policy; a separately written z3 model checks this predicate |
| Raw shell Git | Direct force-push/reset/rebase forms | Regex and branch-token heuristics; unknown branch cases can escalate |
| Repo destruction | `rm -rf .`, `.git`, home, root; selected device-write forms | Regex; quoting, option variants, aliases, and indirect execution can bypass it |
| Secret exposure | Recognized inline secret formats or credential-file paths combined with network commands; secret writes | Regex; does not inspect arbitrary file contents or all exfiltration channels |
| CI files | Empty writes to `.github/workflows/` | Path and replacement-content check; not workflow analysis |
| Cloud metadata | Direct fetches from selected metadata endpoints | Regex; no network firewall |
| Reverse shells/persistence | Selected `/dev/tcp`, netcat, socat, SSH-key, sudoers, and cron forms | Regex |
| Optional `devops` preset | Selected cloud/k8s teardown, database drops, package unpublishing | Extra shell regexes, disabled by default |

The z3 result is about a manually encoded model of `(op, branch, force, hard)`.
It does not prove that every Git command is parsed correctly or that the Python
implementation matches the model. Git aliases, other Git subcommands, hooks,
configuration, and raw shell execution remain outside that proof.

## Execution assumptions

- Only calls sent to the gate are checked. Other agent tools bypass it.
- The gate's source, policy, signing keys, and audit files must be protected by
  actual access controls. A separate process with the same user permissions is
  not sufficient isolation.
- File writes have a realpath-based workspace check, but it is not race-proof
  against concurrent symlink changes. Shell and Git processes have the gate's
  normal OS permissions and can reach outside the workspace.
- The shell defaults to ALLOW. General code edits, dependency installs, indirect
  execution, network access, and resource usage are not comprehensively policed.
- Shell output is truncated in the returned result, but subprocess output is
  captured in memory. Run the executor under resource limits for untrusted work.
- The Claude Code hook fails open on internal/configuration errors. Its printed
  default configuration covers Bash only; file coverage is opt-in.
- The hook observes proposed calls before execution, not execution outcomes. Edit
  coverage approximates replacement text rather than reconstructing the file.
- Audit and webhook failures do not stop gating. New audit files are private, but
  existing file permissions are not tightened. Keep a separate log per MCP process.

## Receipts

Receipts check recorded verdict consistency under an expected policy and attribute
the signed statement to a key. They do not prove execution, complete observation,
or honesty of the signer. An unsigned audit chain cannot detect a removed valid
suffix or a full rewrite. See [the receipt trust model](docs/CONTROL_PLANE_TRUST_MODEL.md).

Both custom ZK backends are prototypes without external cryptographic review.
They cover a projection of selected structured Git actions, not complete commands,
shell/file policies, or execution. Their Python arithmetic is not constant-time.

## Validation limits

Tests cover known cases and regressions. Historical workflow command counts were
not accompanied by a frozen corpus/result artifact in this repository. The live
sampling scripts classify changing workflow text and cannot establish attack
coverage or a statistically verified false-positive rate.

For stronger protection, use independently configured process/container isolation,
least-privilege credentials, server-side branch protection, and review. These are
external controls; qedra does not provision them.
