"""Policy-gated git, file, and shell execution.

File writes have a workspace path check. Shell execution is NOT sandboxed: a
working directory and a regex cannot confine a process. Use OS-level isolation
and least-privilege credentials for untrusted agents.
"""
from __future__ import annotations
import os
import re
import shlex
import subprocess

from .guardrail import Action, Guardrail


class Executor:
    def __init__(self, sandbox: str, guard: Guardrail, control_plane=None):
        self.sandbox = os.path.realpath(sandbox)
        self.guard = guard
        # Optional Agent Control Plane: records the REAL outcome of every action (verdict + whether it
        # actually ran) into a signed, independently-verifiable receipt for the session.
        self.control_plane = control_plane
        self.blocked: list[str] = []
        self.executed: list[str] = []

    def _record(self, action: Action, decision, executed: bool) -> None:
        if self.control_plane is not None:
            self.control_plane.record(action, decision.verdict, decision.reason, executed)

    def receipt(self):
        """The signed receipt for this session (or None if no control plane is attached)."""
        return self.control_plane.receipt() if self.control_plane is not None else None

    # ---- write-path restriction (not a process sandbox) ------------------
    def _in_sandbox(self, path: str) -> bool:
        full = os.path.realpath(os.path.join(self.sandbox, path))
        return full == self.sandbox or full.startswith(self.sandbox + os.sep)

    def _run(self, argv, cwd=None):
        return subprocess.run(argv, cwd=cwd or self.sandbox, capture_output=True,
                              text=True, timeout=30)

    # ---- the three tools the agent can call ------------------------------
    def git(self, args: str) -> str:
        try:
            toks = shlex.split(args)
        except ValueError:
            return "⛔ REFUSED: malformed git arguments."
        if not toks or toks[0].startswith("-"):
            return "⛔ REFUSED: start with a git subcommand; global options are not supported."
        op = toks[0] if toks else ""
        force = "--mirror" in toks or any(t.startswith(("--force", "+")) or
                    (t.startswith("-") and not t.startswith("--") and "f" in t[1:])
                    for t in toks[1:])
        hard = "--hard" in toks
        # Resolve the actual current branch, including custom protected names.
        current = self._run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"])
        branch = current.stdout.strip() if current.returncode == 0 else ""
        named = set()
        for t in toks[1:]:
            for ref in t.lstrip("+").split(":"):
                named.add(ref.removeprefix("refs/heads/"))
        protected = set(self.guard.spec.protected_branches)
        if named & protected:
            branch = sorted(named & protected)[0]
        if op == "push" and force:
            # Refspecs, configured push destinations and --all/--mirror can target
            # a branch other than HEAD. Unknown destinations need human review.
            if named & protected or "--all" in toks or "--mirror" in toks:
                branch = sorted(protected)[0] if protected else branch
            else:
                return "⛔ REFUSED: force-push destination requires human review."
        if op in ("reset", "rebase") and not branch:
            return "⛔ REFUSED: cannot resolve the branch for a history operation."
        a = Action("git", op=op, branch=branch, force=force, hard=hard, cmd=args)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"git {args}  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. Command not executed."
        r = self._run(["git"] + toks)
        self.executed.append(f"git {args}")
        self._record(a, d, True)
        return (r.stdout + r.stderr).strip()[:400] or "(ok)"

    def write_file(self, path: str, content: str) -> str:
        a = Action("write", path=path, content=content)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"write {path}  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. File not written."
        if not self._in_sandbox(path):
            self._record(a, d, False)  # allowed by policy, but the sandbox backstop refused it
            return "⛔ SANDBOX: path escapes the working directory. Refused."
        full = os.path.join(self.sandbox, path)
        os.makedirs(os.path.dirname(full) or self.sandbox, exist_ok=True)
        with open(full, "w") as f:
            f.write(content)
        self.executed.append(f"write {path}")
        self._record(a, d, True)
        return f"wrote {path} ({len(content)} bytes)"

    def run_shell(self, cmd: str) -> str:
        a = Action("shell", cmd=cmd)
        d = self.guard.check(a)
        if d.verdict != "ALLOW":
            self.blocked.append(f"shell '{cmd}'  ->  {d.verdict}: {d.reason}")
            self._record(a, d, False)
            return f"⛔ GUARDRAIL {d.verdict}: {d.reason}. Command not executed."
        # Convenience restriction only; this does not provide process isolation.
        if re.search(r"(^|\s)/", cmd):
            self._record(a, d, False)  # allowed by policy, but the sandbox backstop refused it
            return "⛔ SANDBOX: absolute path in command. Refused."
        r = self._run(["bash", "-lc", cmd])
        self.executed.append(f"shell: {cmd}")
        self._record(a, d, True)
        return (r.stdout + r.stderr).strip()[:400] or "(ok)"
