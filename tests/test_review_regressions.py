"""Regression cases from the November 2026 repository review."""
import concurrent.futures
import json
import os
import subprocess
from dataclasses import asdict
from unittest.mock import patch

import pytest

from qedra.attest_cli import _load_or_create_key, main as attest
from qedra.audit_log import AuditLog, verify_log
from qedra.claude_code_hook import _maybe_record
from qedra.control_plane import ControlPlane, Policy, Receipt, verify_receipt
from qedra.executor import Executor
from qedra.guardrail import Action, Guardrail, PolicySpec
from qedra.tool_gate import ToolGate


def repo(path, branch="trunk"):
    subprocess.run(["git", "init", "-q", "-b", branch, str(path)], check=True)
    return Executor(str(path), Guardrail(PolicySpec(protected_branches=(branch,))))


@pytest.mark.parametrize("args", [
    "push origin trunk --force", "push origin HEAD:trunk --force-with-lease",
    "push origin +HEAD:refs/heads/trunk", "push --mirror", "reset --hard HEAD~1",
    "rebase HEAD~1", "-C elsewhere reset --hard", "push --force origin feature",
])
def test_git_history_calls_do_not_execute_on_custom_protected_branch(tmp_path, args):
    ex = repo(tmp_path)
    original = ex._run
    calls = []
    def run(argv, cwd=None):
        calls.append(argv)
        assert argv[:2] == ["git", "symbolic-ref"]
        return original(argv, cwd)
    with patch.object(ex, "_run", side_effect=run):
        assert ex.git(args).startswith("⛔")


def test_quoted_git_commit_message_is_preserved(tmp_path):
    ex = repo(tmp_path)
    ex._run(["git", "config", "user.name", "test"])
    ex._run(["git", "config", "user.email", "test@example.invalid"])
    ex.git('commit --allow-empty -m "two words"')
    assert ex._run(["git", "log", "-1", "--format=%s"]).stdout.strip() == "two words"


@pytest.mark.parametrize("args", [{"path": "a", "content": None}, {"cmd": []}, {"cmd": 1}])
def test_tool_arguments_are_not_coerced_into_commands(tmp_path, args):
    g = ToolGate(str(tmp_path))
    tool = "write_file" if "path" in args else "run_shell"
    assert g.handle(tool, args).startswith("⛔ REFUSED")
    assert not g.executed


def test_policy_label_cannot_be_changed_after_signing():
    policy = Policy("expected")
    cp = ControlPlane("agent", policy)
    cp.gate(Action("shell", cmd="echo safe"))
    receipt = cp.receipt()
    receipt.policy_id = "other"
    assert not verify_receipt(receipt, policy).ok


def test_escalation_is_not_recorded_as_executed():
    cp = ControlPlane("agent", Policy("p"))
    assert cp.gate(Action("shell", cmd="git reset --hard HEAD~1")) == "ESCALATE"
    assert cp.receipt().entries[0].executed is False


def test_redacted_receipt_does_not_leak_path_in_reason():
    cp = ControlPlane("agent", Policy("p"))
    cp.gate(Action("write", path=".github/workflows/private-client.yml", content=""))
    receipt, _ = cp.receipt().redact()
    assert "private-client" not in receipt.to_json()
    assert verify_receipt(receipt, Policy("p")).ok


@pytest.mark.parametrize("field,value", [("executed", "false"), ("verdict", "OTHER"), ("action", {"kind": "shell", "cmd": []})])
def test_malformed_receipt_fields_are_rejected(field, value):
    cp = ControlPlane("agent", Policy("p"))
    cp.gate(Action("shell", cmd="echo safe"))
    data = json.loads(cp.receipt().to_json())
    data["entries"][0][field] = value
    with pytest.raises((ValueError, TypeError)):
        Receipt.from_json(json.dumps(data))


def test_malformed_witness_returns_rejection():
    cp = ControlPlane("agent", Policy("p"))
    cp.gate(Action("shell", cmd="echo safe"))
    redacted, _ = cp.receipt().redact()
    assert not verify_receipt(redacted, Policy("p"), witness={"0": {}}).ok


@pytest.mark.parametrize("data", [
    {"protected_branches": "main"}, {"protected_branches": ["main", "main"]},
    {"protected_branches": ["\u0000nonprotected"]}, {"protected_branch": ["trunk"]},
])
def test_invalid_policy_spec_fails_loudly(data):
    with pytest.raises(ValueError):
        PolicySpec.from_json(json.dumps(data))


def test_concurrent_hook_records_form_one_chain(tmp_path, monkeypatch):
    path = str(tmp_path / "session.jsonl")
    monkeypatch.setenv("GUARDRAIL_AUDIT_LOG", path)
    def record(i):
        action = Action("shell", cmd=f"echo {i}")
        _maybe_record({"session_id": "test"}, action, Guardrail().check(action))
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(record, range(12)))
    assert len(AuditLog.load(path)) == 12
    assert verify_log(path)[0]
    assert all(not e.executed for e in AuditLog.load(path))
    assert os.stat(path).st_mode & 0o777 == 0o600


def test_concurrent_key_creation_uses_one_key(tmp_path):
    path = str(tmp_path / "key")
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        keys = list(pool.map(lambda _: _load_or_create_key(path), range(12)))
    assert len({k.private_bytes_raw() for k in keys}) == 1


def test_attest_malformed_log_has_clean_error(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("{broken\n")
    assert attest([str(path), "--key", str(tmp_path / "key")]) == 1


def test_unsigned_log_cannot_detect_tail_truncation(tmp_path):
    # This is a documented limitation, not an authenticity test.
    path = str(tmp_path / "session.jsonl")
    cp = ControlPlane("agent", Policy("p"), audit_log=AuditLog(path))
    for cmd in ("echo first", "echo second"):
        cp.gate(Action("shell", cmd=cmd))
    entries = AuditLog.load(path)
    with open(path, "w") as f:
        f.write(json.dumps(asdict(entries[0])) + "\n")
    assert verify_log(path)[0]


def test_hmac_default_keys_are_not_shared():
    assert Guardrail()._key != Guardrail()._key


def test_in_memory_log_tail_deletion_is_detected():
    guard = Guardrail()
    guard.check(Action("shell", cmd="echo first"))
    guard.check(Action("shell", cmd="echo second"))
    guard.log.pop()
    assert not guard.verify_chain()


def test_same_policy_root_has_same_zk_domain_order():
    left = PolicySpec(protected_branches=("z", "a"))
    right = PolicySpec(protected_branches=("a", "z"))
    assert left.content_hash() == right.content_hash()
    assert left.protected_branches == right.protected_branches


def test_package_version_matches_metadata():
    import importlib.metadata
    import qedra
    assert qedra.__version__ == importlib.metadata.version("qedra")
