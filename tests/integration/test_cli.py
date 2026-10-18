from __future__ import annotations

import json
from pathlib import Path

import pytest

from piisafe.cli import main

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


def run(*args: str) -> int:
    return main(list(args))


def test_sanitize_restore_round_trip(state_dir, tmp_path):
    src = tmp_path / "in.log"
    # write_bytes, not write_text: on Windows text mode would turn each \n into \r\n
    src.write_bytes(b"raj.mehta@corp.com accessed 192.168.1.45\r\nKavishka logged in\n")
    out = tmp_path / "out.log"
    report = tmp_path / "report.json"
    args = ["sanitize", str(src), "-o", str(out), "-s", "S1", "--report", str(report), "-q", "--ner", "heuristic"]
    assert run(*args) == 0
    assert out.read_bytes() == b"MAIL_001 accessed HOST_001\r\nUSER_001 logged in\n"
    rep = json.loads(report.read_text())
    assert rep["findings"] == 3 and rep["records_with_pii"] == 2

    restored = tmp_path / "restored.log"
    assert run("restore", str(out), "-s", "S1", "-o", str(restored)) == 0
    assert restored.read_bytes() == src.read_bytes()


def test_block_aborts_without_output(state_dir, tmp_path):
    src = tmp_path / "in.log"
    src.write_text("ok line\nmail raj@corp.com\n")
    out = tmp_path / "out.log"
    assert run("sanitize", str(src), "-o", str(out), "--hook", "export", "--ephemeral", "-q") == 3
    assert not out.exists()
    assert list(tmp_path.glob(".out.log.*")) == []  # temp file cleaned up
    assert run("sanitize", str(src), "-o", str(out), "--hook", "export", "--on-block", "drop",
               "--ephemeral", "-q") == 0
    assert out.read_text() == "ok line\n"


def test_jsonl_and_csv(state_dir, tmp_path):
    out = tmp_path / "events.jsonl"
    assert run("sanitize", str(EXAMPLES / "events.jsonl"), "-o", str(out), "--ephemeral", "-q") == 0
    lines = out.read_text().splitlines()
    first = json.loads(lines[0])
    assert first["user"] == "MAIL_001" and first["src_ip"] == "HOST_001"
    assert lines[-1].startswith("not json: ")

    out_csv = tmp_path / "c.csv"
    assert run("sanitize", str(EXAMPLES / "customers.csv"), "-o", str(out_csv), "--ephemeral", "-q") == 0
    text = out_csv.read_text()
    assert "raj.mehta@corp.com" not in text and "4111" not in text


def test_scan_gates(state_dir, capsys):
    log = str(EXAMPLES / "security.log")
    assert run("scan", log, "--json") == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["findings"] > 10
    assert all(f["value"] != "raj.mehta@corp.com" for f in data["findings"])  # masked by default
    assert run("scan", log, "--fail-on-pii") == 4


def test_policy_commands(tmp_path):
    p = tmp_path / "piisafe.yaml"
    assert run("init", str(p)) == 0
    assert run("policy", "validate", str(p)) == 0
    assert run("init", str(p)) == 1  # refuses to overwrite
    bad = tmp_path / "bad.yaml"
    bad.write_text("default_action: nope\n")
    assert run("policy", "validate", str(bad)) == 1


def test_missing_session(state_dir, tmp_path):
    f = tmp_path / "x.txt"
    f.write_text("USER_001")
    run("sanitize", str(f), "-s", "exists", "-q", "-o", str(tmp_path / "y"))
    assert run("restore", str(f), "-s", "does-not-exist") == 1


@pytest.mark.parametrize(
    "cmd", [["doctor"], ["sessions", "list"], ["audit"], ["bench", "-n", "50", "--ner", "heuristic"]]
)
def test_commands_run(state_dir, cmd):
    assert run(*cmd) == 0
