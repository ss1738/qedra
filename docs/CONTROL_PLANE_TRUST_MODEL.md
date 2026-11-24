# Receipt trust model

A receipt is a signed statement about a recorded sequence of policy decisions.
Its cryptographic checks establish consistency and attribution under the supplied
policy. They cannot establish that the recorded sequence is complete or that the
operator actually executed or blocked a command.

## What verification checks

1. The receipt's policy label and root match the verifier's expected policy.
2. Recomputing the chain matches every entry head and the signed final head.
3. The Ed25519 signature matches the key. A pinned key or verifier-controlled
   registry is needed to associate that key with a known agent.
4. Disclosed actions match their commitments and reproduce the recorded verdict.
   Supported experimental ZK entries instead prove membership of a Git-policy
   projection. The result reports how many entries have been checked for soundness.
5. Entries with `BLOCK` or `ESCALATE` are not marked executed.

`executed` is supplied by the recorder. In the executor it means the operation was
attempted, not that its exit status was successful. In a PreToolUse hook it is
always false because the hook cannot observe a later outcome. `ControlPlane.gate`
is a decision-recording helper and does not run a command.

## What verification cannot establish

An operator holding the signing key can omit an action, fabricate a benign action,
or issue a different, internally consistent receipt. Re-running the policy catches
a false verdict attached to a disclosed action; it does not catch a replacement
trace containing only compliant actions. A signature does not prove observation.
Use an independently trusted recorder and externally retained checkpoints if
completeness or execution evidence is required.

The policy root commits to the policy identifier, version, and serialized
`PolicySpec`. Built-in rules are identified by a version label, not a hash of the
Python source. Retain the matching software revision as well as the spec when
reproducing a historical result. The z3 model covers a finite structured Git
sub-policy; it does not verify the parser, executor, or heuristics.

The gate and its keys must be inaccessible to the agent. A separate process alone
is insufficient if both processes have write/read access to the same source or
keys. The executor does not provide OS isolation, network controls, or a complete
filesystem boundary.

## Durable logs

The JSONL audit log has a public hash chain, not a signature per entry. It detects
an inconsistent edit, insertion, deletion, or reorder against retained chain
links. It cannot detect removal of a valid suffix or a complete rewrite with
recomputed hashes. `qedra-attest` checks chain consistency before signing the
current snapshot; that does not prove the snapshot matches a previous session.

Logs contain raw actions and may contain blocked secrets. New files use mode 600.
Hook read/resume/append transactions are serialized with POSIX file locks. Use one
log per MCP process and do not mix writers from different integrations. Logging
failures do not stop gating and can leave an incomplete persisted trail.

## Redaction

Redaction removes action data and salts while retaining the signed chain. New
receipts use generic reasons so paths and branch names are not retained there.
Older receipts can retain identifying paths in their signed reason strings;
inspect them before sharing. Agent and policy labels remain visible in all modes.
The disclosure witness contains private action data and must be stored separately.

Without a witness or a supported ZK proof, a hidden entry has integrity and
signature checks only. A successful result for a partially hidden receipt must
not be described as full policy soundness.

Both custom ZK backends require external cryptographic review. A proof covers the
Git action's encoded policy projection, not its complete command text or actual
execution. Pure-Python cryptographic arithmetic is not a hardened, constant-time
implementation. Do not treat these experimental proofs as production assurance.
