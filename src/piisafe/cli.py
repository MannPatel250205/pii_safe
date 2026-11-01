"""piisafe — command-line interface.

    piisafe init                                   write a starter piisafe.yaml
    piisafe sanitize logs.txt -o clean.txt -s INC-001
    piisafe scan logs.txt --fail-over 50           dry run / CI gate
    piisafe restore llm_answer.txt -s INC-001      aliases -> original values
    piisafe reidentify USER_001 -s INC-001
    piisafe sessions list|show|key|merge|delete
    piisafe audit -s INC-001 --deferred
    piisafe policy validate|show
    piisafe bench | doctor

Exit codes: 0 ok · 1 error · 2 usage · 3 blocked by policy · 4 risk threshold exceeded
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, TextIO, overload

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TimeRemainingColumn
from rich.table import Table

from piisafe import __version__
from piisafe.config import DB_FILE, default_state_dir, find_policy_file
from piisafe.exceptions import PIISafeError
from piisafe.guard import PIISafeGuard
from piisafe.io import FORMATS, BlockedAt, Processor, RunStats, detect_format
from piisafe.models import Finding
from piisafe.normalize import normalize_text
from piisafe.policy import KNOWN_HOOKS, Policy
from piisafe.runs import record_run
from piisafe.storage import SQLStore, database_url, describe, open_store

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_BLOCKED, EXIT_RISK = 0, 1, 2, 3, 4
_ACTION_SHORT = {"pseudonymise": "pseudo", "allow": "allow", "redact": "redact", "mask": "mask", "block": "block"}

err = Console(stderr=True, highlight=False)
out = Console(highlight=False)


# =================================================================== helpers


def _load_policy(path: str | None) -> Policy:
    if path:
        return Policy.load(path)
    found = find_policy_file()
    return Policy.load(found) if found else Policy.default()


def _state_dir(a: argparse.Namespace) -> Path:
    return Path(a.state_dir).expanduser() if a.state_dir else default_state_dir()


def _open_input(path: str | None) -> TextIO:
    if path in (None, "-"):
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="surrogateescape", newline="")
    return open(path, encoding="utf-8", errors="surrogateescape", newline="")  # noqa: SIM115


@contextlib.contextmanager
def _atomic_output(path: str | None) -> Iterator[TextIO]:
    """Write to a temp file and rename on success, so a failed run leaves nothing."""
    if path in (None, "-"):
        stream = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="surrogateescape",
                                  newline="", write_through=True)
        try:
            yield stream
        finally:
            stream.flush()
            stream.detach()
        return
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors="surrogateescape", newline="") as fh:
            yield fh
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _read_key(a: argparse.Namespace) -> str | None:
    if getattr(a, "key", None):
        return str(a.key)
    if getattr(a, "key_file", None):
        return Path(a.key_file).read_text().strip()
    return None


@overload
def _open_db(a: argparse.Namespace, must_exist: Literal[True] = ...) -> SQLStore | None: ...


@overload
def _open_db(a: argparse.Namespace, must_exist: Literal[False]) -> SQLStore: ...


def _open_db(a: argparse.Namespace, must_exist: bool = True) -> SQLStore | None:
    """Open the configured database.

    Returns None only when ``must_exist`` and the local SQLite file was never
    created; with ``must_exist=False`` the store is created, so it is never None.
    """
    url = database_url(getattr(a, "database_url", None))
    if url is None and must_exist and not (_state_dir(a) / DB_FILE).exists():
        return None
    return open_store(url, _state_dir(a))


def _where(a: argparse.Namespace) -> str:
    return describe(getattr(a, "database_url", None), _state_dir(a))


def _existing_guard(a: argparse.Namespace, session: str) -> PIISafeGuard:
    store = _open_db(a)
    if store is None:
        raise PIISafeError(f"no PII-Safe state found at {_state_dir(a)}")
    if store.get_session(session) is None:
        store.close()
        raise PIISafeError(f"session '{session}' not found in {_where(a)}")
    return PIISafeGuard(
        _load_policy(getattr(a, "policy", None)), session, state_dir=_state_dir(a), store=store,
        session_key=_read_key(a), ner="off", create_keys=False, key_provider=getattr(a, "key_provider", None),
    )


def _preview(value: str, show: bool) -> str:
    if show or len(value) <= 2:
        return value
    keep = max(1, len(value) // 5)
    return value[:keep] + "•" * min(len(value) - 2 * keep, 10) + value[-keep:]


def _fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _progress(path: str | None, quiet: bool) -> Progress | None:
    if quiet or path in (None, "-") or not err.is_terminal:
        return None
    return Progress(
        TextColumn("[bold]sanitising[/]"), BarColumn(), DownloadColumn(), TimeRemainingColumn(),
        console=err, transient=True,
    )


# ================================================================ summaries


def _summary(stats: RunStats, guard: PIISafeGuard, meta: dict[str, Any], elapsed: float) -> None:
    d = stats.to_dict()
    head = Table.grid(padding=(0, 2))
    head.add_column(style="dim")
    head.add_column()
    for k in ("session", "policy", "hook", "input", "output", "format", "ner"):
        if meta.get(k):
            head.add_row(k, str(meta[k]))
    rate = stats.records / elapsed if elapsed else 0
    head.add_row("records", f"{stats.records:,}  ({stats.records_with_pii:,} with PII, {rate:,.0f}/s)")
    if stats.dropped:
        head.add_row("dropped", f"[yellow]{stats.dropped:,} blocked records omitted[/]")
    risk = d["risk"]
    head.add_row(
        "exposure",
        f"max {risk['max_record_exposure']}  mean {risk['mean_record_exposure']}  "
        f"→ residual max [{'red' if risk['max_residual_exposure'] else 'green'}]"
        f"{risk['max_residual_exposure']}[/]",
    )
    err.print(Panel(head, title=f"PII-Safe {__version__}", border_style="cyan", expand=False))

    if stats.total_findings:
        t = Table(title=f"{stats.total_findings:,} findings", title_justify="left", expand=False)
        t.add_column("entity type")
        t.add_column("count", justify="right")
        for etype, n in stats.by_type.most_common():
            t.add_row(etype, f"{n:,}")
        a = Table(title="actions / resolution", title_justify="left", expand=False)
        a.add_column("")
        a.add_column("count", justify="right")
        for k, v in stats.by_action.most_common():
            a.add_row(k, f"{v:,}")
        for k, v in stats.by_decision.most_common():
            style = "yellow" if k == "DEFERRED" else ""
            a.add_row(f"[{style}]{k}[/]" if style else k, f"{v:,}")
        hit = d["tier1_hit_rate"]
        a.add_row("[dim]tier-1 hit rate[/]", f"[dim]{hit:.0%}[/]" if hit is not None else "-")
        grid = Table.grid(padding=(0, 4))
        grid.add_row(t, a)
        err.print(grid)
    else:
        err.print("[green]No PII detected.[/]")

    lat = guard.latency.summary()
    if lat:
        lt = Table(title="latency per call (ms)", title_justify="left", expand=False)
        for c in ("stage", "calls", "p50", "p90", "p99"):
            lt.add_column(c, justify="right" if c != "stage" else "left")
        for stage in ("tier1", "memory", "tier2", "resolve", "total"):
            if stage in lat:
                s = lat[stage]
                lt.add_row(stage, f"{s['calls']:,}", f"{s['p50_ms']:.3f}", f"{s['p90_ms']:.3f}", f"{s['p99_ms']:.3f}")
        err.print(lt)

    if stats.deferred:
        err.print(
            f"[yellow]{len(stats.deferred)} DEFERRED resolution(s)[/] — ambiguous names were kept "
            f"apart. Review: [bold]piisafe audit -s {meta['session']} --deferred[/]"
        )


# ================================================================ commands


def cmd_init(a: argparse.Namespace) -> int:
    target = Path(a.path)
    if target.is_dir():
        target = target / "piisafe.yaml"
    if target.exists() and not a.force:
        err.print(f"[red]{target} exists[/] (use --force to overwrite)")
        return EXIT_ERROR
    from importlib import resources

    src = resources.files("piisafe").joinpath("policies/default.yaml").read_text("utf-8")
    target.write_text(src, encoding="utf-8")
    err.print(f"[green]wrote[/] {target}\nEdit it, then: [bold]piisafe policy validate {target}[/]")
    return EXIT_OK


def cmd_sanitize(a: argparse.Namespace) -> int:
    same_file = (
        a.output and a.input not in (None, "-") and a.output != "-"
        and Path(a.output).resolve() == Path(a.input).resolve()
    )
    if same_file:
        err.print("[red]output must differ from input[/]")
        return EXIT_USAGE
    policy = _load_policy(a.policy)
    session = a.session or datetime.now().strftime("run-%Y%m%d-%H%M%S")
    fmt = detect_format(a.input, a.format)
    guard = PIISafeGuard(
        policy, session, state_dir=a.state_dir, ephemeral=a.ephemeral, ner=a.ner,
        block_mode="redact" if a.on_block == "redact" else "raise",
        database_url=a.database_url, key_provider=a.key_provider,
    )
    source = a.input if a.input not in (None, "-") else "<stdin>"
    prog = _progress(a.input, a.quiet)
    t0 = time.perf_counter()
    try:
        with _open_input(a.input) as src, _atomic_output(a.output) as dst:
            if prog is not None:
                prog.start()
                task = prog.add_task("", total=os.path.getsize(a.input))
                tick = lambda n: prog.advance(task, n)  # noqa: E731
            else:
                tick = None
            proc = Processor(guard, a.hook, a.policy_id, a.on_block, source, progress=tick)
            try:
                stats = proc.run(fmt, src, dst)
            finally:
                if prog is not None:
                    prog.stop()
    except BlockedAt as exc:
        if not a.ephemeral:
            record_run(guard.store, session_id=session, source=source, origin="cli", hook=a.hook, fmt=fmt,
                       status="blocked", stats=None, duration_s=time.perf_counter() - t0,
                       extra={"blocked_line": exc.line, "blocked_types": exc.error.entity_types})
        guard.close()
        err.print(f"[red bold]BLOCKED[/] {source}:{exc.line}: {exc.error}")
        err.print("No output was written. Use --on-block drop|redact to continue past blocked records.")
        return EXIT_BLOCKED
    except json.JSONDecodeError as exc:
        guard.close()
        err.print(f"[red]invalid JSON input:[/] {exc}")
        return EXIT_ERROR
    elapsed = time.perf_counter() - t0
    if not a.ephemeral:
        record_run(guard.store, session_id=session, source=source, origin="cli", hook=a.hook, fmt=fmt,
                   status="ok", stats=stats, duration_s=elapsed)
    guard.close()

    meta = {
        "session": session, "policy": policy.source, "hook": a.hook + (f" ({a.policy_id})" if a.policy_id else ""),
        "input": source, "output": a.output or "<stdout>", "format": fmt,
        "ner": guard.ner.backend if guard.ner else "off",
    }
    if a.report:
        report = {"piisafe": __version__, "generated_at": datetime.now().isoformat(timespec="seconds"),
                  **meta, "elapsed_s": round(elapsed, 3), **stats.to_dict(),
                  "latency": guard.latency.summary()}
        Path(a.report).write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not a.quiet:
        _summary(stats, guard, meta, elapsed)
        if not a.ephemeral:
            err.print(f"[dim]Restore aliases later with: piisafe restore <file> -s {session}[/]")
    return EXIT_OK


def cmd_scan(a: argparse.Namespace) -> int:
    policy = _load_policy(a.policy)
    fmt = detect_format(a.input, a.format)
    guard = PIISafeGuard(policy, "scan", ephemeral=True, ner=a.ner, block_mode="redact")
    rows: list[dict[str, Any]] = []

    def collect(line: int, raw: str, findings: list[Finding]) -> None:
        text = normalize_text(raw)
        for f in findings:
            if len(rows) >= a.max_findings:
                return
            value = text[f.start:f.end] if fmt in ("text",) or f.end <= len(text) else ""
            rows.append({"line": line, **f.to_dict(), "value": value})

    source = a.input if a.input not in (None, "-") else "<stdin>"
    with _open_input(a.input) as src:
        stats = Processor(guard, a.hook, a.policy_id, "redact", source, on_findings=collect).run(fmt, src, None)
    guard.close()

    if a.json:
        for r in rows:
            r["value"] = _preview(r["value"], a.show_values)
        out.print_json(json.dumps({"input": source, "findings": rows, "summary": stats.to_dict()}))
    else:
        if rows:
            t = Table(title=f"{source}: {stats.total_findings:,} findings", title_justify="left")
            for c in ("line", "type", "value", "action", "detector", "conf"):
                t.add_column(c, justify="right" if c in ("line", "conf") else "left")
            for r in rows:
                t.add_row(str(r["line"]), r["entity_type"], _preview(r["value"], a.show_values),
                          r["action"], r["detector"], f"{r['confidence']:.2f}")
            out.print(t)
            if stats.total_findings > len(rows):
                err.print(f"[dim]… {stats.total_findings - len(rows)} more (raise --max-findings)[/]")
        risk = stats.to_dict()["risk"]
        colour = "red" if risk["max_record_exposure"] >= 50 else "yellow" if risk["max_record_exposure"] else "green"
        err.print(
            f"records {stats.records:,} · with PII {stats.records_with_pii:,} · "
            f"[{colour}]max exposure {risk['max_record_exposure']}[/] · mean {risk['mean_record_exposure']}"
        )
    if a.fail_on_pii and stats.total_findings:
        return EXIT_RISK
    if a.fail_over is not None and stats.max_risk > a.fail_over:
        err.print(f"[red]exposure {stats.max_risk} exceeds --fail-over {a.fail_over}[/]")
        return EXIT_RISK
    return EXIT_OK


def cmd_restore(a: argparse.Namespace) -> int:
    guard = _existing_guard(a, a.session)
    try:
        with _open_input(a.input) as src:
            text = src.read()
        restored = guard.restore(text)
        with _atomic_output(a.output) as dst:
            dst.write(restored)
    finally:
        guard.close()
    err.print("[yellow]Output contains original PII. Handle it accordingly. (logged in audit events)[/]")
    return EXIT_OK


def cmd_reidentify(a: argparse.Namespace) -> int:
    guard = _existing_guard(a, a.session)
    results = []
    try:
        for alias in a.aliases:
            try:
                results.append(guard.reidentify(alias))
            except PIISafeError as exc:
                results.append({"alias": alias, "error": str(exc)})
    finally:
        guard.close()
    if a.json:
        out.print_json(json.dumps(results))
        return EXIT_OK
    t = Table()
    for c in ("alias", "type", "value", "variants", "mentions", "linked"):
        t.add_column(c)
    for r in results:
        if "error" in r:
            t.add_row(r["alias"], "", f"[red]{r['error']}[/]", "", "", "")
        else:
            t.add_row(r["alias"], r["entity_type"], r["value"], ", ".join(r["variants"]),
                      str(r["mentions"]), ", ".join(r["linked"]))
    out.print(t)
    return EXIT_OK


def cmd_sessions(a: argparse.Namespace) -> int:
    store = _open_db(a)
    if store is None:
        err.print(f"no sessions yet ({_where(a)} does not exist)")
        return EXIT_OK
    try:
        if a.action == "list":
            sessions = store.list_sessions()
            if a.json:
                out.print_json(json.dumps(sessions))
                return EXIT_OK
            t = Table(title=_where(a), title_justify="left")
            for c in ("session", "entities", "audit rows", "deferred", "turns", "updated"):
                t.add_column(c, justify="left" if c == "session" else "right")
            for s in sessions:
                t.add_row(s["session_id"], str(s["entities"]), str(s["audit_rows"]),
                          str(s["deferred"]), str(s["turn"]), _fmt_ts(s["updated_at"]))
            out.print(t)
            return EXIT_OK

        if not a.session:
            err.print("[red]--session/-s is required[/]")
            return EXIT_USAGE
        if store.get_session(a.session) is None:
            err.print(f"[red]session '{a.session}' not found[/]")
            return EXIT_ERROR

        if a.action == "show":
            ents = store.entity_summary(a.session)
            t = Table(title=f"session {a.session}", title_justify="left")
            for c in ("alias", "type", "mentions", "merged into"):
                t.add_column(c)
            for e in ents:
                t.add_row(e["alias"], e["entity_type"], str(e["mentions"]), e["merged_into"] or "")
            out.print(t)
            return EXIT_OK
        if a.action == "delete":
            if not a.yes:
                reply = input(f"Delete session '{a.session}' and its audit rows? [y/N] ")
                if reply.strip().lower() not in ("y", "yes"):
                    err.print("aborted")
                    return EXIT_ERROR
            for run in store.query_runs(100_000, a.session):
                if run.get("output_path"):
                    Path(run["output_path"]).unlink(missing_ok=True)
            store.delete_session(a.session)
            store.log_event(a.session, "delete_session", {"by": "cli"})
            err.print(f"[green]deleted[/] {a.session}")
            return EXIT_OK
    finally:
        store.close()

    guard = _existing_guard(a, a.session)
    try:
        if a.action == "key":
            key = guard.session_key()
            guard.store.log_event(a.session, "export_session_key", {})
            err.print("[yellow]This key re-identifies every alias in the session. Share it like a password.[/]")
            print(key)
        elif a.action == "merge":
            if not (a.src and a.dst):
                err.print("[red]usage: piisafe sessions merge -s SESSION SRC_ALIAS DST_ALIAS[/]")
                return EXIT_USAGE
            guard.merge(a.src, a.dst)
            err.print(f"[green]merged[/] {a.src} → {a.dst} (future mentions map to {a.dst})")
    finally:
        guard.close()
    return EXIT_OK


def cmd_audit(a: argparse.Namespace) -> int:
    store = _open_db(a)
    if store is None:
        err.print(f"no audit log yet ({_where(a)} does not exist)")
        return EXIT_OK
    try:
        if a.events:
            rows = store.query_events(a.session, a.limit)
            if a.json:
                out.print_json(json.dumps(rows))
                return EXIT_OK
            t = Table(title="events")
            for c in ("time", "session", "kind", "detail"):
                t.add_column(c)
            for r in rows:
                t.add_row(_fmt_ts(r["ts"]), r["session_id"] or "", r["kind"], json.dumps(r["detail"]))
            out.print(t)
            return EXIT_OK
        rows = store.query_audit(a.session, "DEFERRED" if a.deferred else None, a.type, a.limit)
    finally:
        store.close()
    if a.json:
        out.print_json(json.dumps(rows))
        return EXIT_OK
    title = f"audit{' · ' + a.session if a.session else ''} ({len(rows)} rows, newest first)"
    t = Table(title=title, title_justify="left")
    cols = ["time", *([] if a.session else ["session"]), "src:line", "type", "alias", "action",
            "decision", "score", "candidate"]
    for c in cols:
        t.add_column(c, no_wrap=c in ("time", "alias", "candidate"))
    for r in rows:
        score = f"{r['resolution_score']:.2f}" if r["resolution_score"] is not None else ""
        src = f"{Path(r['source']).name if r['source'] else ''}:{r['line'] or ''}"
        cells = [datetime.fromtimestamp(r["ts"]).strftime("%H:%M:%S"),
                 *([] if a.session else [r["session_id"]]), src, r["entity_type"], r["alias"] or "",
                 _ACTION_SHORT.get(r["action"], r["action"]), r["decision"] or "", score,
                 r["candidate_alias"] or ""]
        t.add_row(*cells)
    out.print(t)
    if a.deferred and rows:
        err.print("[dim]Accept a merge with: piisafe sessions merge -s SESSION <alias> <candidate>[/]")
    return EXIT_OK


def cmd_policy(a: argparse.Namespace) -> int:
    if a.action == "validate":
        path = a.file or a.policy
        if not path:
            err.print("[red]usage: piisafe policy validate FILE[/]")
            return EXIT_USAGE
        pol = Policy.load(path)
        err.print(f"[green]✓ valid[/] {path}: {len(pol.policies)} named policies "
                  f"({', '.join(pol.policy_names())}), default action '{pol.default_action.value}', "
                  f"{len(pol.custom_patterns)} custom pattern(s)")
        unknown = sorted({h for p in pol.policies for h in p.hook_types} - set(KNOWN_HOOKS) - {"*"})
        if unknown:
            err.print(f"[yellow]note:[/] custom hook types {unknown} only apply when called explicitly")
        return EXIT_OK
    pol = _load_policy(a.file or a.policy)
    matrix = pol.matrix()
    colours = {"allow": "red", "pseudonymise": "green", "redact": "cyan", "mask": "blue", "block": "magenta"}
    t = Table(title=f"policy matrix — {pol.source}", title_justify="left")
    t.add_column("entity type")
    for h in KNOWN_HOOKS:
        t.add_column(h)
    for etype, row in matrix.items():
        t.add_row(etype, *[f"[{colours[row[h]]}]{_ACTION_SHORT[row[h]]}[/]" for h in KNOWN_HOOKS])
    out.print(t)
    err.print("[dim]pseudo = pseudonymise (stable alias such as USER_001)[/]")
    return EXIT_OK


def cmd_bench(a: argparse.Namespace) -> int:
    from piisafe import bench

    res = bench.run(a.n, a.seed, a.ner)
    if a.json:
        out.print_json(json.dumps(res))
        return EXIT_OK
    err.print(Panel(
        f"{res['lines']:,} synthetic log lines · NER: {res['ner_backend']} · init {res['init_ms']} ms\n"
        f"total {res['total_ms']:,} ms · {res['throughput_lines_per_s']:,} lines/s\n"
        f"findings {res['findings']:,} · tier-1 hit rate {res['tier1_hit_rate']:.0%} · "
        f"resolution {res['resolution']}\n"
        f"known PII leaked into output: "
        f"[{'green' if not res['known_pii_leaked'] else 'red'}]{res['known_pii_leaked']}[/]",
        title="piisafe bench", expand=False,
    ))
    t = Table(title="latency (ms)", title_justify="left")
    for c in ("stage", "calls", "p50", "p90", "p99", "max"):
        t.add_column(c, justify="left" if c == "stage" else "right")
    for stage, s in res["latency"].items():
        t.add_row(stage, f"{s['calls']:,}",
                  *(f"{s[k]:.3f}" for k in ("p50_ms", "p90_ms", "p99_ms", "max_ms")))
    out.print(t)
    for raw, clean in res["sample"]:
        out.print(f"[dim]{raw}[/]\n  → {clean}")
    return EXIT_OK


def cmd_doctor(a: argparse.Namespace) -> int:
    import importlib.metadata as md

    t = Table(title=f"piisafe {__version__} · Python {sys.version.split()[0]}", title_justify="left")
    t.add_column("component")
    t.add_column("status")

    def ver(pkg: str) -> str | None:
        try:
            return md.version(pkg)
        except md.PackageNotFoundError:
            return None

    for pkg, why in (("pyyaml", "policy files"), ("jellyfish", "tier 3 similarity"),
                     ("phonenumbers", "phone detection"), ("cryptography", "registry encryption"),
                     ("rich", "CLI output"), ("spacy", "tier 2 NER (optional)")):
        v = ver(pkg)
        t.add_row(f"{pkg} [dim]({why})[/]", f"[green]{v}[/]" if v else "[yellow]not installed[/]")
    pol = _load_policy(a.policy)
    from piisafe.detection import NERDetector

    ner = NERDetector(pol.settings.ner, pol.settings.spacy_model)
    status = f"[green]{ner.backend}[/]"
    if ner.spacy_error:
        status += f" [dim](spaCy unavailable: {ner.spacy_error[:80]})[/]"
    t.add_row("tier 2 backend", status)
    t.add_row("policy", pol.source)
    state = _state_dir(a)
    t.add_row("state dir", str(state))
    key = state / "master.key"
    from piisafe.keyproviders import provider_name

    kp = provider_name(a.key_provider)
    if kp in ("aws-kms", "vault-transit"):
        t.add_row("master key", f"[green]{kp}[/] (wrapped key stored in the database)")
    elif kp == "env":
        t.add_row("master key", "[green]from $PIISAFE_MASTER_KEY[/]")
    elif key.exists():
        mode = key.stat().st_mode & 0o777
        ok = mode & 0o077 == 0
        t.add_row("master key", f"{key} [{'green' if ok else 'red'}]mode {oct(mode)}[/]"
                  + ("" if ok else " — run: chmod 600 " + str(key)))
    else:
        t.add_row("master key", "[dim]created on first sanitize[/]")
    if database_url(a.database_url):
        try:
            _open_db(a, must_exist=False).close()
            t.add_row("database", f"[green]reachable[/] {_where(a)}")
        except Exception as exc:  # noqa: BLE001 - report any connection problem
            t.add_row("database", f"[red]unreachable[/] {_where(a)}: {exc}")
    else:
        db = state / DB_FILE
        size = f"{db} ({db.stat().st_size / 1024:.0f} KiB)" if db.exists() else "[dim]not created yet[/]"
        t.add_row("database", size)
    out.print(t)
    if not ver("spacy"):
        err.print("[dim]Optional: pip install 'piisafe[ner]' && python -m spacy download en_core_web_sm[/]")
    return EXIT_OK


def cmd_serve(a: argparse.Namespace) -> int:
    try:
        import uvicorn

        from piisafe.server import create_app, ensure_admin_key
    except ImportError:
        err.print("[red]The web server needs extra packages:[/] pip install 'piisafe[server]'")
        return EXIT_ERROR
    state = _state_dir(a)
    app = create_app(state, a.policy, a.max_upload_mb, a.database_url, a.key_provider)
    key = ensure_admin_key(state, a.database_url)
    url = f"http://{'localhost' if a.host in ('127.0.0.1', '0.0.0.0') else a.host}:{a.port}"
    if key:
        err.print(Panel(
            f"First start: an admin key was created. It is shown [bold]only once[/] — store it safely.\n\n"
            f"[bold]{key}[/]\n\nCreate more keys in the dashboard (API keys) or with: piisafe keys create <name>",
            title="Admin API key", border_style="yellow", expand=False))
    err.print(f"Dashboard: [bold]{url}[/]   API docs: {url}/api/docs   state: {state}")
    if a.host not in ("127.0.0.1", "localhost", "::1"):
        err.print("[yellow]Listening beyond localhost: serve it behind HTTPS (reverse proxy) before exposing it.[/]")
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning", proxy_headers=True)
    return EXIT_OK


def cmd_mcp(a: argparse.Namespace) -> int:
    try:
        from piisafe.integrations import mcp as mcp_server
    except ImportError:
        err.print("[red]The MCP server needs the MCP SDK:[/] pip install 'piisafe[mcp]'")
        return EXIT_ERROR
    if a.allow_restore:
        err.print("[yellow]restore tool enabled: the connected model can turn aliases back into real PII.[/]")
    if a.transport != "stdio":  # stdout carries the protocol on stdio, so only talk on stderr
        err.print(f"MCP endpoint: [bold]http://{a.host}:{a.port}/mcp[/]   state: {_state_dir(a)}")
    mcp_server.run(a.transport, a.host, a.port, policy=_load_policy(a.policy), state_dir=_state_dir(a),
                   database_url=a.database_url, key_provider=a.key_provider, allow_restore=a.allow_restore)
    return EXIT_OK


def cmd_keys(a: argparse.Namespace) -> int:
    from piisafe.server.auth import create_api_key

    store = _open_db(a, must_exist=False)
    try:
        if a.action == "create":
            if not a.name:
                err.print("[red]usage: piisafe keys create NAME [--role analyst|admin][/]")
                return EXIT_USAGE
            key_id, key = create_api_key(store, a.name, a.role)
            store.log_event("", "api_key_created", {"by": "cli", "id": key_id, "role": a.role})
            err.print(f"[green]created[/] {a.role} key '{a.name}' (id {key_id}). Shown only once:")
            print(key)
        elif a.action == "list":
            t = Table()
            for c in ("id", "name", "role", "key", "created", "last used", "status"):
                t.add_column(c)
            for k in store.list_api_keys():
                t.add_row(k["id"], k["name"], k["role"], k["prefix"] + "…", _fmt_ts(k["created_at"]),
                          _fmt_ts(k["last_used"]) if k["last_used"] else "-",
                          "[dim]revoked[/]" if k["revoked"] else "[green]active[/]")
            out.print(t)
        elif a.action == "revoke":
            if not a.name or not store.revoke_api_key(a.name):
                err.print("[red]usage: piisafe keys revoke KEY_ID (see piisafe keys list)[/]")
                return EXIT_USAGE
            store.log_event("", "api_key_revoked", {"by": "cli", "id": a.name})
            err.print(f"[green]revoked[/] {a.name}")
    finally:
        store.close()
    return EXIT_OK


def cmd_master_key(a: argparse.Namespace) -> int:
    """Inspect the master key source, or move an existing key into AWS KMS / Vault."""
    import json as _json

    from piisafe.crypto import KeyManager
    from piisafe.keyproviders import WRAPPED_META_KEY, managed_provider, provider_name

    store = _open_db(a, must_exist=False)
    try:
        wrapped = store.get_meta(WRAPPED_META_KEY)
        if a.action == "status":
            current = provider_name(a.key_provider)
            t = Table(show_header=False)
            t.add_row("configured provider", current)
            t.add_row("database", _where(a))
            if wrapped:
                info = _json.loads(wrapped)
                t.add_row("wrapped key in database", f"{info['provider']} · {info['key_ref']}")
            else:
                t.add_row("wrapped key in database", "none")
            km = KeyManager(_state_dir(a), create=False, provider=current, store=store)
            t.add_row("master key usable", "[green]yes[/]" if km.available else "[yellow]not created yet[/]")
            out.print(t)
            return EXIT_OK

        # migrate: wrap the CURRENT master key (so existing sessions stay readable)
        source = provider_name(a.from_provider)
        if source not in ("local", "env"):
            err.print("[red]--from must be local or env (the key being moved)[/]")
            return EXIT_USAGE
        if wrapped and not a.force:
            err.print("[red]the database already holds a wrapped master key[/] (use --force to replace it)")
            return EXIT_ERROR
        km = KeyManager(_state_dir(a), create=False, provider=source, store=store)
        if not km.available:
            err.print(f"[red]no master key found via '{source}'[/]")
            return EXIT_ERROR
        kms = managed_provider(a.to)
        store.set_meta(WRAPPED_META_KEY, _json.dumps(
            {"provider": a.to, "key_ref": kms.key_ref(), "wrapped": kms.wrap(km.master_bytes())}))
        check = KeyManager(_state_dir(a), create=False, provider=a.to, store=store)
        assert check.master_bytes() == km.master_bytes()
        store.log_event("", "master_key_migrated", {"from": source, "to": a.to, "key_ref": kms.key_ref()})
        err.print(f"[green]master key wrapped with {a.to}[/] ({kms.key_ref()}) and stored in the database.\n"
                  f"Next: set PIISAFE_KEY_PROVIDER={a.to} everywhere PII-Safe runs, verify with "
                  "'piisafe master-key status', then securely delete the old key "
                  f"({_state_dir(a) / 'master.key'} or $PIISAFE_MASTER_KEY).")
        return EXIT_OK
    finally:
        store.close()


# ==================================================================== parser


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--state-dir", help="registry/audit/key location (default $PIISAFE_HOME or ~/.piisafe)")
    common.add_argument("-p", "--policy", help="policy YAML (default ./piisafe.yaml, else built-in)")
    common.add_argument("--database-url", help="postgresql://… or sqlite:///… (default $PIISAFE_DATABASE_URL, "
                        "else SQLite in the state dir)")
    common.add_argument("--key-provider", choices=("local", "env", "aws-kms", "vault-transit"),
                        help="master key source (default $PIISAFE_KEY_PROVIDER, else local file)")

    detect = argparse.ArgumentParser(add_help=False)
    detect.add_argument("--hook", default="on_prompt",
                        help=f"hook whose policy applies: {', '.join(KNOWN_HOOKS)} (default on_prompt)")
    detect.add_argument("--policy-id", help="force a named policy set from the policy file")
    detect.add_argument("-f", "--format", default="auto", choices=("auto", *FORMATS),
                        help="input format (default: from file extension)")
    detect.add_argument("--ner", choices=("auto", "spacy", "heuristic", "off"),
                        help="override settings.ner for this run")

    keyopts = argparse.ArgumentParser(add_help=False)
    keyopts.add_argument("--key", help="session key (instead of the local master key)")
    keyopts.add_argument("--key-file", help="file containing the session key")

    p = argparse.ArgumentParser(
        prog="piisafe",
        description="PII-Safe: consistent, policy-driven pseudonymisation of PII for AI agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Run 'piisafe <command> -h' for command help.",
    )
    p.add_argument("--version", action="version", version=f"piisafe {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    s = sub.add_parser("init", help="write a starter policy file")
    s.add_argument("path", nargs="?", default="piisafe.yaml")
    s.add_argument("--force", action="store_true")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("sanitize", aliases=["sanitise"], parents=[common, detect],
                       help="sanitise a file (or stdin) and write the clean version")
    s.add_argument("input", nargs="?", default="-", help="input file, or - for stdin")
    s.add_argument("-i", "--input", dest="input_opt", help=argparse.SUPPRESS)
    s.add_argument("-o", "--output", help="output file (default stdout); written atomically")
    s.add_argument("-s", "--session", help="session id; reuse it to keep aliases consistent across files")
    s.add_argument("--on-block", choices=("fail", "drop", "redact"), default="fail",
                   help="when a 'block' rule fires: abort (default), drop the record, or redact")
    s.add_argument("--report", help="write a JSON run report here")
    s.add_argument("--ephemeral", action="store_true", help="in-memory only: nothing persisted, no restore")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(func=cmd_sanitize)

    s = sub.add_parser("scan", parents=[common, detect], help="detect PII without writing output (dry run / CI gate)")
    s.add_argument("input", nargs="?", default="-")
    s.add_argument("--json", action="store_true")
    s.add_argument("--show-values", action="store_true", help="print detected values unmasked")
    s.add_argument("--max-findings", type=int, default=200)
    s.add_argument("--fail-over", type=float, metavar="SCORE", help="exit 4 if any record's exposure > SCORE")
    s.add_argument("--fail-on-pii", action="store_true", help="exit 4 if anything is found")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("restore", parents=[common, keyopts], help="replace aliases in a file with original values")
    s.add_argument("input", nargs="?", default="-")
    s.add_argument("-o", "--output")
    s.add_argument("-s", "--session", required=True)
    s.set_defaults(func=cmd_restore)

    s = sub.add_parser("reidentify", parents=[common, keyopts], help="show the original value behind aliases")
    s.add_argument("aliases", nargs="+")
    s.add_argument("-s", "--session", required=True)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_reidentify)

    s = sub.add_parser("sessions", parents=[common, keyopts], help="list / inspect / merge / delete sessions")
    s.add_argument("action", choices=("list", "show", "key", "merge", "delete"), nargs="?", default="list")
    s.add_argument("src", nargs="?", help="merge: alias to fold in (e.g. USER_002)")
    s.add_argument("dst", nargs="?", help="merge: alias to keep (e.g. USER_001)")
    s.add_argument("-s", "--session")
    s.add_argument("--json", action="store_true")
    s.add_argument("-y", "--yes", action="store_true", help="delete without confirmation")
    s.set_defaults(func=cmd_sessions)

    s = sub.add_parser("audit", parents=[common], help="query the audit log")
    s.add_argument("-s", "--session")
    s.add_argument("--deferred", action="store_true", help="only ambiguous resolutions needing review")
    s.add_argument("--type", help="filter by entity type")
    s.add_argument("--events", action="store_true", help="show re-identification / merge events instead")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("policy", parents=[common], help="validate a policy or show its action matrix")
    s.add_argument("action", choices=("validate", "show"))
    s.add_argument("file", nargs="?")
    s.set_defaults(func=cmd_policy)

    s = sub.add_parser("bench", help="latency & detection benchmark on synthetic logs")
    s.add_argument("-n", type=int, default=1000)
    s.add_argument("--seed", type=int, default=7)
    s.add_argument("--ner", choices=("auto", "spacy", "heuristic", "off"))
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_bench)

    s = sub.add_parser("serve", parents=[common], help="run the web dashboard + REST API")
    s.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--max-upload-mb", type=int, default=50)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("mcp", parents=[common], help="run the MCP server (sanitize / scan / score tools for agents)")
    s.add_argument("--transport", choices=("stdio", "streamable-http", "sse"), default="stdio")
    s.add_argument("--host", default="127.0.0.1", help="HTTP transports: bind address (default 127.0.0.1)")
    s.add_argument("--port", type=int, default=8766)
    s.add_argument("--allow-restore", action="store_true",
                   help="also expose the restore tool (aliases -> real values; audited)")
    s.set_defaults(func=cmd_mcp)

    s = sub.add_parser("keys", parents=[common], help="manage API keys for the dashboard / REST API")
    s.add_argument("action", choices=("create", "list", "revoke"))
    s.add_argument("name", nargs="?", help="create: key name · revoke: key id")
    s.add_argument("--role", choices=("analyst", "admin"), default="analyst")
    s.set_defaults(func=cmd_keys)

    s = sub.add_parser("master-key", parents=[common], help="master key status / move it into AWS KMS or Vault")
    s.add_argument("action", choices=("status", "migrate"))
    s.add_argument("--to", choices=("aws-kms", "vault-transit"), help="migrate: target provider")
    s.add_argument("--from", dest="from_provider", choices=("local", "env"), help="migrate: current source")
    s.add_argument("--force", action="store_true", help="migrate: replace an existing wrapped key")
    s.set_defaults(func=cmd_master_key)

    s = sub.add_parser("doctor", parents=[common], help="check installation and configuration")
    s.set_defaults(func=cmd_doctor)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    a = parser.parse_args(argv)
    if not getattr(a, "func", None):
        parser.print_help()
        return EXIT_USAGE
    if getattr(a, "input_opt", None):  # `--input x` spelling from the proposal
        a.input = a.input_opt
    try:
        return int(a.func(a))
    except PIISafeError as exc:
        err.print(f"[red]error:[/] {exc}")
        return EXIT_ERROR
    except FileNotFoundError as exc:
        err.print(f"[red]error:[/] {exc.strerror}: {exc.filename}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        err.print("[red]interrupted[/]")
        return 130
    except BrokenPipeError:
        with contextlib.suppress(Exception):
            sys.stdout = open(os.devnull, "w")  # noqa: SIM115
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
