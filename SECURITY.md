# Security policy

qedra is experimental. Its shell/file rules are heuristic, its executor is not an
OS sandbox, and its custom ZK implementations have not had an external audit.
See [THREAT_MODEL.md](THREAT_MODEL.md) and
[the receipt trust model](docs/CONTROL_PLANE_TRUST_MODEL.md).

## Reporting

Maintainer: [Satyawan Singh (@ss1738)](https://github.com/ss1738).

For a non-sensitive issue, include the exact tool call with dummy credentials,
the policy configuration, expected verdict, and actual result in a GitHub issue.
Do not post real keys, private commands, audit logs, or disclosure witnesses.

For sensitive findings, use GitHub's private vulnerability reporting option if it
is enabled. Otherwise open an issue asking the maintainer for a private reporting
channel, without including exploit details or private data.

Known heuristic bypasses are limitations, but common direct forms that evade the
checks are still useful bug reports. Parser/model mismatches, verification bugs,
secret leaks, and undocumented failures are also in scope for reporting.

## Support

There is no guaranteed response time or supported-version security SLA. Retain the
exact source revision and policy spec when reporting or reproducing a result.
