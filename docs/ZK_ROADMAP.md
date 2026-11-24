# Experimental zero-knowledge receipts

The default receipt commits to raw actions using salted SHA-256 commitments.
Verification can re-run the policy only when an action is disclosed. ZK mode
instead commits to a small Git-policy projection using a Pedersen commitment and
attaches a Fiat-Shamir OR-proof of set membership.

## Implemented structure

- `qedra/zk.py`: protected-branch domain and 2048-bit MODP group adapter.
- `qedra/ec.py`: pure-Python secp256k1 arithmetic, with affine reference and
  Jacobian multiplication paths.
- `qedra/zk_ec.py`: secp256k1 adapter using the shared policy domain.
- `qedra/zk_core.py`: common commitment and OR-proof implementation.
- `qedra/control_plane.py`: proof generation, receipt export, and verification.

The encoded domain is selected Git operations (`push`, `reset`, `rebase`, `commit`,
`branch`), protected-branch membership/index, and force/hard flags. It is not a
commitment to a complete shell command or to all fields in a Git action. A hidden
proof establishes a verdict for that projection. A disclosed entry additionally
checks that the disclosed action's projection opens the same commitment.

Select `ControlPlane(..., zk=True)` or `zk="modp"` for MODP, or `zk="ec"` for
secp256k1. MCP uses `GUARDRAIL_ZK=1|modp|ec`. Unsupported action kinds retain the
ordinary SHA-256 commitment and require disclosure for verdict checking.

## Limits and next work

Neither backend has received an external cryptographic audit. These are research
implementations, not production cryptographic assurance. Python big-integer and
curve arithmetic is not constant-time. Tests and known-answer vectors are useful
checks, not a security proof or substitute for review.

Before relying on this mode, obtain an independent review of the construction,
transcript binding, group validation, encoding, malformed-input handling, and
side channels. Production use also needs a reviewed cryptographic backend and
resource limits. Extending proofs to shell/file policies or replacing the scheme
with a SNARK would be separate work.

Previous timing and size figures were development observations without a retained
benchmark artifact. They are not a supported performance promise. Run explicit
benchmarks on the target revision and hardware before making a comparison.
