// Pages. Each view(ctx) returns a DOM node; ctx = { me, go, refreshBadge }.

import { api, ApiError, download, upload } from "./api.js";
import { bars, chartCard, columns } from "./charts.js";
import {
  actionChip, card, clear, exposure, put, fullTime, h, icon, kpi, modal, num, table, toast, when,
} from "./dom.js";

const SAMPLE = `2024-03-12 09:00:01 raj.mehta@corp.com accessed 192.168.1.45 — FAILED_LOGIN
2024-03-12 09:05:12 Raj flagged by the security system
2024-03-12 09:07:40 Raju accessed 192.168.1.67 — SUCCESS
2024-03-12 09:10:03 sshd[2231]: Failed password for invalid user oracle from 10.20.30.40 port 22 ssh2
2024-03-12 09:12:00 Kavishka logged in from 192.168.1.45 using badge EMP-00421
2024-03-12 09:14:31 Kavihska approved the request for 192.168.1.45
2024-03-12 09:15:02 GET /api/v1/users?email=priya.sharma%40corp.com&api_key=sk_live_51HxQ2abcdef12345
2024-03-12 09:18:09 contact Dr. Alice Brown at +1 415-555-0132, card on file 4111 1111 1111 1111`;

function head(title, subtitle, ...actions) {
  return h("div", { class: "page-head" },
    h("div", null, h("h1", null, title), subtitle ? h("p", null, subtitle) : null),
    actions.length ? h("div", { class: "row" }, ...actions) : null);
}

function errorBox(err) {
  return h("div", { class: "callout error", role: "alert" }, err instanceof Error ? err.message : String(err));
}

function loading() {
  return h("div", { class: "empty" }, "Loading…");
}

async function mount(root, build) {
  put(root, loading());
  try {
    const node = await build();
    put(root, node);
  } catch (err) {
    put(root, errorBox(err));
  }
}

function select(name, options, value) {
  return h("select", { name }, options.map(([v, label]) => h("option", { value: v, selected: v === value }, label)));
}

function field(label, control) {
  return h("label", { class: "field" }, label, control);
}

// Highlight aliases (USER_001) and redactions ([EMAIL_ADDRESS]) in sanitised text.
const MARK_RE = /\b[A-Z][A-Z0-9]*_\d{3,}\b|\[[A-Z][A-Z0-9_]*\]/g;
function highlighted(text) {
  const out = h("div", { class: "output", tabindex: 0 });
  let last = 0;
  for (const m of text.matchAll(MARK_RE)) {
    out.append(text.slice(last, m.index));
    out.append(h("span", { class: m[0].startsWith("[") ? "redacted" : "alias" }, m[0]));
    last = m.index + m[0].length;
  }
  out.append(text.slice(last));
  return out;
}

function riskTiles(findings, risk, residual, extra) {
  return h("div", { class: "grid kpis" },
    kpi("PII found", num(findings)),
    kpi("Input exposure", exposure(risk), "before sanitising"),
    kpi("Residual exposure", exposure(residual), "left in clear text (allow rules)"),
    extra || null);
}

// ===================================================================== overview

export function overview(root, ctx) {
  let days = 30;
  const body = h("div");
  const period = select("days", [["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"]], "30");
  period.addEventListener("change", () => { days = Number(period.value); load(); });
  root.append(head("Overview", "What PII-Safe has protected across your sessions.", period,
    h("a", { class: "btn primary", href: "#/sanitize" }, icon("upload"), "Sanitize data")), body);

  const load = () => mount(body, async () => {
    const st = await api(`/api/stats?days=${days}`);
    const byDay = new Map(st.by_day.map((d) => [d.day, d.findings]));
    const series = [];
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(Date.now() - i * 86400000);
      const key = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
      series.push({ day: key, label: d.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
        title: d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" }),
        value: byDay.get(key) || 0 });
    }
    const t1 = st.by_tier.find((t) => t.key === "tier1")?.count || 0;
    const empty = !st.findings && !st.records;
    return h("div", { class: "stack" },
      empty ? h("div", { class: "callout" }, "No activity in this period yet. ",
        h("a", { href: "#/sanitize" }, "Sanitize some text or a log file"), " to see results here.") : null,
      h("div", { class: "grid kpis" },
        kpi("Records processed", num(st.records), `${num(st.requests)} requests`),
        kpi("PII findings", num(st.findings), st.findings ? `${Math.round((t1 / st.findings) * 100)}% caught by fast tier` : "—"),
        kpi("Identities protected", num(st.entities), `${num(st.sessions)} sessions`),
        kpi("Pending reviews", h("a", { href: "#/review" }, num(st.pending_reviews)), "ambiguous name matches"),
        kpi("Peak file exposure", exposure(st.max_risk), `${num(st.blocked_runs)} runs blocked by policy`)),
      h("div", { class: "grid two" },
        chartCard("PII findings per day", series, (el, d) => columns(el, d),
          [{ key: "title", label: "Day" }, { key: "value", label: "Findings", num: true }]),
        chartCard("Findings by entity type", st.by_type.map((d) => ({ label: d.key, value: d.count })),
          (el, d) => bars(el, d), [{ key: "label", label: "Entity type" }, { key: "value", label: "Findings", num: true }])),
      h("div", { class: "grid two" },
        chartCard("How PII was handled", st.by_action.map((d) => ({ label: d.key, value: d.count })),
          (el, d) => bars(el, d, { labelWidth: 108 }), [{ key: "label", label: "Action" }, { key: "value", label: "Count", num: true }]),
        chartCard("Identity resolution", st.by_decision.map((d) => ({ label: d.key, value: d.count })),
          (el, d) => bars(el, d, { labelWidth: 108 }), [{ key: "label", label: "Decision" }, { key: "value", label: "Count", num: true }])),
      card(h("h2", null, "Recent runs"), runsTable(st.recent_runs, ctx)));
  });
  load();
}

function runsTable(runs, ctx, { showSession = true } = {}) {
  return table([
    { label: "When", render: (r) => h("span", { title: fullTime(r.ts), class: "nowrap" }, when(r.ts)) },
    { label: "Source", render: (r) => h("span", { class: "mono" }, r.source) },
    showSession ? { label: "Session", render: (r) => h("a", { href: `#/sessions/${encodeURIComponent(r.session_id)}` }, r.session_id) } : null,
    { label: "Via", key: "origin" },
    { label: "Records", num: true, render: (r) => num(r.records) },
    { label: "Findings", num: true, render: (r) => num(r.findings) },
    { label: "Exposure", render: (r) => (r.status === "ok" ? exposure(r.max_risk) : "—") },
    { label: "Status", render: (r) => r.status === "ok"
      ? h("span", { class: "status good" }, icon("check"), "Done")
      : h("span", { class: "status critical" }, icon("octagon"), "Blocked") },
  ].filter(Boolean), runs || [], { empty: "No file runs yet." });
}

// ===================================================================== sanitize

export function sanitize(root, ctx) {
  const tabs = h("div", { class: "tabs", role: "tablist" });
  const pane = h("div");
  const show = (which) => {
    for (const b of tabs.children) b.setAttribute("aria-selected", String(b.dataset.tab === which));
    put(pane, which === "text" ? textPane(ctx) : filePane(ctx));
  };
  for (const [id, label] of [["text", "Text"], ["file", "File upload"]]) {
    tabs.append(h("button", { role: "tab", "data-tab": id, onclick: () => show(id) }, label));
  }
  root.append(head("Sanitize", "Replace PII with consistent aliases before data reaches an LLM.", tabs), pane);
  show("text");
}

function optionFields(ctx, { withFormat = false } = {}) {
  const session = h("input", { name: "session_id", placeholder: "auto", autocomplete: "off" });
  const hook = select("hook", ctx.me.hooks.map((x) => [x, x]), "on_prompt");
  const policy = select("policy_id", [["", "by hook"], ...ctx.me.policy_ids.map((x) => [x, x])], "");
  const onBlock = select("on_block", withFormat
    ? [["fail", "stop the run"], ["drop", "drop the record"], ["redact", "redact instead"]]
    : [["fail", "stop"], ["redact", "redact instead"]], "fail");
  const format = select("format", [["auto", "auto (extension)"], ...ctx.me.formats.map((x) => [x, x])], "auto");
  const el = h("div", { class: "fields" },
    field("Session ID", session), field("Hook", hook), field("Policy", policy),
    withFormat ? field("Format", format) : null, field("When a block rule fires", onBlock));
  return { el, values: () => ({ session_id: session.value.trim() || null, hook: hook.value,
    policy_id: policy.value || null, on_block: onBlock.value, format: format.value }) };
}

function textPane(ctx) {
  const opts = optionFields(ctx);
  const input = h("textarea", { rows: 12, placeholder: "Paste log lines, a prompt, or any text…", spellcheck: "false" });
  const result = h("div", { class: "stack" });
  const run = async (mode) => {
    const text = input.value;
    if (!text.trim()) return toast("Paste some text first.");
    put(result, loading());
    try {
      if (mode === "scan") {
        const r = await api("/api/scan", { method: "POST", body: { text, hook: opts.values().hook, policy_id: opts.values().policy_id } });
        put(result, card(h("h2", null, `${num(r.count)} findings (dry run — nothing stored)`), table([
          { label: "Line", key: "line", num: true },
          { label: "Type", render: (f) => h("span", { class: "chip" }, f.entity_type) },
          { label: "Value", render: (f) => h("span", { class: "mono" }, f.preview) },
          { label: "Would be", render: (f) => actionChip(f.action) },
          { label: "Detector", render: (f) => h("span", { class: "muted small" }, f.detector) },
          { label: "Confidence", num: true, render: (f) => f.confidence.toFixed(2) },
        ], r.findings, { empty: "No PII detected." })));
        return;
      }
      const v = opts.values();
      const r = await api("/api/sanitize", { method: "POST", body: { text, ...v, on_block: v.on_block } });
      put(result,
        riskTiles(r.findings.length, r.risk_score, r.residual_risk,
          kpi("Session", h("a", { href: `#/sessions/${encodeURIComponent(r.session_id)}` }, r.session_id), `${r.latency_ms} ms`)),
        card([h("h2", null, "Sanitised output"), h("button", { class: "btn sm", onclick: async () => {
          try { await navigator.clipboard.writeText(r.sanitised_text); toast("Copied."); } catch { toast("Copy failed — select the text instead."); }
        } }, icon("copy"), "Copy")], highlighted(r.sanitised_text)),
        card(h("h2", null, "What was found"), findingsTable(r.findings)));
    } catch (err) {
      put(result, blockedOrError(err));
    }
  };
  return h("div", { class: "stack" },
    card(null, h("div", { class: "stack" }, opts.el, input,
      h("div", { class: "row" },
        h("button", { class: "btn primary", onclick: () => run("sanitize") }, icon("shield"), "Sanitize"),
        h("button", { class: "btn", onclick: () => run("scan") }, icon("eye"), "Scan only"),
        h("span", { class: "spacer" }),
        h("button", { class: "btn ghost sm", onclick: () => { input.value = SAMPLE; } }, "Load sample")))),
    result);
}

function findingsTable(findings) {
  return table([
    { label: "Type", render: (f) => h("span", { class: "chip" }, f.entity_type) },
    { label: "Replaced with", render: (f) => h("span", { class: "mono" }, f.replacement) },
    { label: "Action", render: (f) => actionChip(f.action) },
    { label: "Resolution", render: (f) => f.decision ? h("span", { title: f.candidate_alias ? `possible match: ${f.candidate_alias}` : "" },
      f.decision === "DEFERRED" ? h("span", { class: "status warning" }, icon("alert"), `Review vs ${f.candidate_alias}`) : f.decision) : "—" },
    { label: "Linked", render: (f) => f.linked.join(", ") || "—" },
    { label: "Detector", render: (f) => h("span", { class: "muted small" }, `tier ${f.tier} · ${f.detector}`) },
    { label: "Confidence", num: true, render: (f) => f.confidence.toFixed(2) },
  ], findings, { empty: "No PII detected — the text is unchanged." });
}

function blockedOrError(err) {
  if (err instanceof ApiError && err.status === 409 && err.detail?.error === "blocked") {
    const d = err.detail;
    return h("div", { class: "callout error", role: "alert" },
      h("strong", null, "Blocked by policy. "),
      `${d.policy ? `Policy “${d.policy}”` : "The policy"} does not allow ${d.entity_types.join(", ")} at hook ${d.hook}`,
      d.line ? ` (line ${d.line})` : "", ". Nothing was written. Choose “redact instead” to continue anyway.");
  }
  return errorBox(err);
}

function filePane(ctx) {
  const opts = optionFields(ctx, { withFormat: true });
  const fileInput = h("input", { type: "file", class: "hidden", accept: ".log,.txt,.jsonl,.ndjson,.json,.csv,text/*" });
  const label = h("div", null, h("strong", null, "Drop a log file here"), h("div", { class: "muted small" },
    `or click to choose · .log .txt .jsonl .json .csv · up to ${ctx.me.max_upload_mb} MB`));
  const zone = h("div", { class: "dropzone", tabindex: 0, role: "button", "aria-label": "Choose a file to sanitize" },
    icon("upload"), label);
  const bar = h("div", { class: "progress hidden" }, h("div"));
  const result = h("div", { class: "stack" });
  let file = null;
  const pick = (f) => {
    file = f;
    put(label, h("strong", null, f.name), h("div", { class: "muted small" }, `${(f.size / 1024).toFixed(1)} KB · ready`));
  };
  zone.addEventListener("click", () => fileInput.click());
  zone.addEventListener("keydown", (e) => (e.key === "Enter" || e.key === " ") && fileInput.click());
  fileInput.addEventListener("change", () => fileInput.files[0] && pick(fileInput.files[0]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => { e.preventDefault(); zone.classList.remove("over"); e.dataTransfer.files[0] && pick(e.dataTransfer.files[0]); });

  const go = async () => {
    if (!file) return toast("Choose a file first.");
    const v = opts.values();
    const form = new FormData();
    form.append("file", file);
    for (const k of ["session_id", "hook", "policy_id", "format", "on_block"]) if (v[k]) form.append(k, v[k]);
    bar.classList.remove("hidden");
    const fill = bar.firstChild;
    put(result, h("div", { class: "muted" }, "Uploading and sanitising…"));
    try {
      const r = await upload("/api/sanitize/file", form, (p) => fill.style.setProperty("width", `${Math.round(p * 100)}%`));
      const sm = r.summary;
      put(result,
        riskTiles(sm.findings, sm.risk.max_record_exposure, sm.risk.max_residual_exposure,
          kpi("Records", num(sm.records), `${num(sm.records_with_pii)} with PII · ${r.duration_s}s`)),
        sm.deferred.length ? h("div", { class: "callout warn" }, `${sm.deferred.length} ambiguous name match(es) were kept apart. `,
          h("a", { href: "#/review" }, "Review them")) : null,
        sm.dropped_records ? h("div", { class: "callout warn" }, `${sm.dropped_records} record(s) were dropped by block rules.`) : null,
        h("div", { class: "grid split" },
          chartCard("Findings by type", Object.entries(sm.by_entity_type).map(([label, value]) => ({ label, value })),
            (el, d) => bars(el, d), [{ key: "label", label: "Type" }, { key: "value", label: "Count", num: true }]),
          chartCard("Actions", Object.entries(sm.by_action).map(([label, value]) => ({ label, value })),
            (el, d) => bars(el, d, { labelWidth: 108 }), [{ key: "label", label: "Action" }, { key: "value", label: "Count", num: true }])),
        card([h("h2", null, `Preview · ${r.file}`), h("div", { class: "row" },
          h("span", { class: "muted small" }, `session `, h("a", { href: `#/sessions/${encodeURIComponent(r.session_id)}` }, r.session_id)),
          h("button", { class: "btn primary sm", onclick: () => download(r.download).catch((e) => toast(e.message, "error")) },
            icon("download"), "Download sanitised file"))], highlighted(r.preview)));
    } catch (err) {
      put(result, blockedOrError(err));
    } finally {
      bar.classList.add("hidden");
      fill.style.setProperty("width", "0");
    }
  };
  return h("div", { class: "stack" },
    card(null, h("div", { class: "stack" }, zone, fileInput, opts.el, bar,
      h("div", { class: "row" }, h("button", { class: "btn primary", onclick: go }, icon("shield"), "Sanitize file")))),
    result);
}

// ===================================================================== review

export function review(root, ctx) {
  const body = h("div");
  root.append(head("Review queue",
    "Names that looked similar but not certain enough to merge. They were kept as separate aliases until you decide."), body);
  const load = () => mount(body, async () => {
    const items = await api("/api/reviews");
    ctx.refreshBadge(items.length);
    const revealed = new Map();
    const tbl = table([
      { label: "Session", render: (r) => h("a", { href: `#/sessions/${encodeURIComponent(r.session_id)}` }, r.session_id) },
      { label: "New alias", render: (r) => h("span", { class: "alias mono" }, r.alias) },
      { label: "Possible match", render: (r) => h("span", { class: "alias mono" }, r.candidate) },
      { label: "Type", render: (r) => h("span", { class: "chip" }, r.entity_type) },
      { label: "Similarity", num: true, render: (r) => (r.score ?? 0).toFixed(2) },
      { label: "First seen", render: (r) => h("span", { class: "muted small mono" }, `${r.source || ""}${r.line ? ":" + r.line : ""}`) },
      { label: "", render: (r) => {
        const cell = h("div", { class: "row" });
        const decide = async (decision) => {
          try {
            await api("/api/reviews", { method: "POST", body: { session_id: r.session_id, alias: r.alias, candidate: r.candidate, decision } });
            toast(decision === "merge" ? `${r.alias} now maps to ${r.candidate}.` : `${r.alias} kept as a separate person.`);
            load();
          } catch (e) { toast(e.message, "error"); }
        };
        cell.append(
          h("button", { class: "btn sm primary", onclick: () => decide("merge") }, "Same person — merge"),
          h("button", { class: "btn sm", onclick: () => decide("keep") }, "Different"));
        if (ctx.me.role === "admin") {
          cell.append(h("button", { class: "btn sm ghost", title: "Show real values (logged)", onclick: async (e) => {
            const btn = e.currentTarget;
            try {
              const res = await api("/api/reidentify", { method: "POST", body: { session_id: r.session_id, aliases: [r.alias, r.candidate] } });
              btn.replaceWith(h("span", { class: "small" }, `${res[0].value ?? "?"} vs ${res[1].value ?? "?"}`));
              revealed.set(r.alias, res);
            } catch (err) { toast(err.message, "error"); }
          } }, icon("eye"), "Reveal"));
        }
        return cell;
      } },
    ], items, { empty: "Nothing to review. Ambiguous matches will appear here." });
    return card(null, ctx.me.role === "admin" ? h("p", { class: "muted small" }, "Reveal shows the original values and is recorded in the activity log.") : null, tbl);
  });
  load();
}

// ===================================================================== sessions

export function sessions(root, ctx) {
  const body = h("div");
  root.append(head("Sessions", "Aliases are consistent within a session — one incident, one investigation, one agent run."), body);
  mount(body, async () => {
    const items = await api("/api/sessions");
    return card(null, table([
      { label: "Session", render: (r) => h("span", { class: "mono" }, r.session_id) },
      { label: "Identities", num: true, render: (r) => num(r.entities) },
      { label: "Findings logged", num: true, render: (r) => num(r.audit_rows) },
      { label: "Pending review", num: true, render: (r) => (r.deferred ? num(r.deferred) : "—") },
      { label: "Updated", render: (r) => h("span", { title: fullTime(r.updated_at) }, when(r.updated_at)) },
    ], items, { empty: "No sessions yet.", onRow: (r) => ctx.go(`#/sessions/${encodeURIComponent(r.session_id)}`) }));
  });
}

export function sessionDetail(root, ctx, id) {
  const body = h("div");
  const del = ctx.me.role === "admin" ? h("button", { class: "btn danger", onclick: async () => {
    const confirmInput = h("input", { placeholder: id, "aria-label": "Type the session ID to confirm" });
    const ok = await modal("Delete session", [
      h("p", null, "This permanently deletes the session's encrypted identity registry, its audit rows and stored outputs. Aliases from this session can never be restored afterwards."),
      field(`Type ${id} to confirm`, confirmInput)],
    [{ label: "Cancel", value: false }, { label: "Delete", value: true, class: "danger solid" }]);
    if (!ok) return;
    if (confirmInput.value !== id) return toast("Session ID did not match — nothing deleted.", "error");
    try { await api(`/api/sessions/${encodeURIComponent(id)}`, { method: "DELETE" }); toast("Session deleted."); ctx.go("#/sessions"); }
    catch (e) { toast(e.message, "error"); }
  } }, icon("trash"), "Delete session") : null;
  root.append(head(id, "Session detail", h("a", { class: "btn", href: `#/audit?session=${encodeURIComponent(id)}` }, icon("list"), "Audit log"), del), body);
  mount(body, async () => {
    const d = await api(`/api/sessions/${encodeURIComponent(id)}`);
    const byType = {};
    for (const e of d.entities) if (!e.merged_into) byType[e.entity_type] = (byType[e.entity_type] || 0) + 1;
    return h("div", { class: "stack" },
      h("div", { class: "grid kpis" },
        kpi("Identities", num(d.entities.filter((e) => !e.merged_into).length), `${num(d.entities.filter((e) => e.merged_into).length)} merged`),
        kpi("Turns", num(d.turn), "lines / records / calls"),
        kpi("Created", when(d.created_at), fullTime(d.created_at)),
        kpi("Last activity", when(d.updated_at), fullTime(d.updated_at))),
      chartCard("Identities by type", Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value })),
        (el, x) => bars(el, x), [{ key: "label", label: "Type" }, { key: "value", label: "Identities", num: true }]),
      card(h("h2", null, "File runs"), runsTable(d.runs, ctx, { showSession: false })),
      card(h("h2", null, "Alias registry"), h("p", { class: "muted small" }, "Original values are encrypted with this session's key and are not shown here."),
        table([
          { label: "Alias", render: (e) => h("span", { class: "alias mono" }, e.alias) },
          { label: "Type", render: (e) => h("span", { class: "chip" }, e.entity_type) },
          { label: "Mentions", num: true, render: (e) => num(e.mentions) },
          { label: "Merged into", render: (e) => (e.merged_into ? h("span", { class: "mono" }, e.merged_into) : "—") },
        ], d.entities)));
  });
}

// ===================================================================== audit

export function audit(root, ctx, params) {
  const session = h("input", { placeholder: "any", value: params.get("session") || "" });
  const decision = select("decision", [["", "any"], ["EXACT", "EXACT"], ["MERGE", "MERGE"], ["NEW_ENTITY", "NEW_ENTITY"], ["DEFERRED", "DEFERRED"]], "");
  const etype = h("input", { placeholder: "e.g. EMAIL_ADDRESS" });
  const body = h("div");
  let offset = 0;
  const LIMIT = 100;
  const load = () => mount(body, async () => {
    const q = new URLSearchParams({ limit: LIMIT, offset });
    if (session.value.trim()) q.set("session_id", session.value.trim());
    if (decision.value) q.set("decision", decision.value);
    if (etype.value.trim()) q.set("entity_type", etype.value.trim().toUpperCase());
    const rows = await api(`/api/audit?${q}`);
    return card(null, table([
      { label: "Time", render: (r) => h("span", { title: fullTime(r.ts) }, when(r.ts)) },
      { label: "Session", render: (r) => h("span", { class: "mono small" }, r.session_id) },
      { label: "Hook", key: "hook_type" },
      { label: "Source", render: (r) => h("span", { class: "mono small" }, `${r.source || ""}${r.line ? ":" + r.line : ""}`) },
      { label: "Type", render: (r) => h("span", { class: "chip" }, r.entity_type) },
      { label: "Alias", render: (r) => (r.alias ? h("span", { class: "mono" }, r.alias) : "—") },
      { label: "Action", render: (r) => actionChip(r.action) },
      { label: "Decision", render: (r) => r.decision || "—" },
      { label: "Score", num: true, render: (r) => (r.resolution_score != null ? r.resolution_score.toFixed(2) : "") },
      { label: "Detector", render: (r) => h("span", { class: "muted small" }, r.detector) },
    ], rows, { empty: "No audit records match." }),
    h("div", { class: "row", style: { "margin-top": "12px" } },
      h("button", { class: "btn sm", disabled: offset === 0, onclick: () => { offset = Math.max(0, offset - LIMIT); load(); } }, "Previous"),
      h("span", { class: "muted small" }, `rows ${offset + 1}–${offset + rows.length}`),
      h("button", { class: "btn sm", disabled: rows.length < LIMIT, onclick: () => { offset += LIMIT; load(); } }, "Next")));
  });
  const apply = () => { offset = 0; load(); };
  root.append(head("Audit log", "One record per detected value: what was found, where, and what was done. Values are stored as keyed hashes only."),
    card(null, h("div", { class: "fields" }, field("Session", session), field("Decision", decision), field("Entity type", etype),
      h("div", { class: "row", style: { "align-self": "end" } }, h("button", { class: "btn primary", onclick: apply }, "Apply")))),
    h("div", { style: { height: "16px" } }), body);
  for (const el of [session, etype]) el.addEventListener("keydown", (e) => e.key === "Enter" && apply());
  load();
}

// ===================================================================== policy

export function policy(root, ctx) {
  const body = h("div");
  root.append(head("Policy", "Which action applies to each type of PII at each point in the agent's lifecycle."), body);
  mount(body, async () => {
    const p = await api("/api/policy");
    const isAdmin = ctx.me.role === "admin";
    const editor = h("textarea", { rows: 26, spellcheck: "false", readonly: !isAdmin }, );
    editor.value = p.yaml;
    const status = h("div");
    const matrixHolder = h("div", null, matrix(p.matrix, p.hooks));
    const validate = async () => {
      const r = await api("/api/policy/validate", { method: "POST", body: { yaml: editor.value } });
      put(status, r.valid
        ? h("div", { class: "callout" }, h("span", { class: "status good" }, icon("check"), "Valid"), ` — policies: ${r.policy_ids.join(", ") || "none"}`)
        : h("pre", { class: "callout error mono", role: "alert" }, r.error));
      if (r.valid) put(matrixHolder, matrix(r.matrix, p.hooks));
      return r.valid;
    };
    const save = async () => {
      if (!(await validate())) return;
      const ok = await modal("Save policy", h("p", null, `This replaces ${p.path} and applies to all new requests immediately.`),
        [{ label: "Cancel", value: false }, { label: "Save", value: true, class: "primary" }]);
      if (!ok) return;
      try { await api("/api/policy", { method: "PUT", body: { yaml: editor.value } }); toast("Policy saved and active."); }
      catch (e) { toast(e.message, "error"); }
    };
    return h("div", { class: "stack" },
      card([h("h2", null, "Action matrix"), h("span", { class: "muted small" }, "rows: entity types · columns: hooks")], matrixHolder),
      card([h("h2", null, "Policy file"), h("span", { class: "muted small mono" }, p.path)],
        h("div", { class: "stack" }, editor, status,
          h("div", { class: "row" },
            h("button", { class: "btn", onclick: () => validate().catch((e) => toast(e.message, "error")) }, "Validate"),
            isAdmin ? h("button", { class: "btn primary", onclick: save }, "Save & apply") : h("span", { class: "muted small" }, "Read-only: an admin key is needed to edit.")))));
  });
}

function matrix(m, hooks) {
  const rows = Object.entries(m).map(([type, acts]) => ({ type, ...acts }));
  return table([{ label: "Entity type", render: (r) => h("span", { class: "chip" }, r.type) },
    ...hooks.map((hk) => ({ label: hk, render: (r) => actionChip(r[hk]) }))], rows);
}

// ===================================================================== re-identify (admin)

export function reidentify(root, ctx) {
  const body = h("div");
  root.append(head("Re-identify", "Turn aliases back into real values — for example in an LLM's answer. Every use is recorded."), body);
  mount(body, async () => {
    const list = await api("/api/sessions");
    const sessionSel = select("session", list.map((x) => [x.session_id, x.session_id]), list[0]?.session_id);
    const input = h("textarea", { rows: 8, placeholder: "e.g. USER_003 approved the request from HOST_001 after MAIL_001 failed to log in." });
    const out = h("div");
    const aliases = h("input", { placeholder: "USER_001 MAIL_001 …" });
    const aliasOut = h("div");
    return h("div", { class: "stack" },
      h("div", { class: "callout warn" }, h("strong", null, "This reveals personal data. "), "Use it only when you are authorised to see the original values. Each restore and lookup is written to the activity log with your key name."),
      card(h("h2", null, "Restore text"), h("div", { class: "stack" }, field("Session", sessionSel), input,
        h("div", { class: "row" }, h("button", { class: "btn primary", onclick: async () => {
          try {
            const r = await api("/api/restore", { method: "POST", body: { session_id: sessionSel.value, text: input.value } });
            put(out, h("div", { class: "output" }, r.text));
          } catch (e) { put(out, errorBox(e)); }
        } }, icon("unlock"), "Restore")), out)),
      card(h("h2", null, "Look up aliases"), h("div", { class: "stack" }, h("div", { class: "row" }, aliases,
        h("button", { class: "btn", onclick: async () => {
          const names = aliases.value.split(/[\s,]+/).filter(Boolean);
          if (!names.length) return;
          try {
            const r = await api("/api/reidentify", { method: "POST", body: { session_id: sessionSel.value, aliases: names } });
            put(aliasOut, table([
              { label: "Alias", render: (x) => h("span", { class: "mono" }, x.alias) },
              { label: "Type", render: (x) => x.entity_type || "—" },
              { label: "Value", render: (x) => x.error ? h("span", { class: "status critical" }, x.error) : h("strong", null, x.value) },
              { label: "Variants seen", render: (x) => (x.variants || []).join(", ") },
              { label: "Linked", render: (x) => (x.linked || []).join(", ") || "—" },
            ], r));
          } catch (e) { put(aliasOut, errorBox(e)); }
        } }, "Look up")), aliasOut)));
  });
}

// ===================================================================== activity (admin)

export function activity(root) {
  const body = h("div");
  root.append(head("Activity log", "Re-identifications, merges, deletions, policy changes and key management."), body);
  mount(body, async () => {
    const rows = await api("/api/events?limit=300");
    return card(null, table([
      { label: "Time", render: (r) => h("span", { title: fullTime(r.ts) }, when(r.ts)) },
      { label: "Event", render: (r) => h("span", { class: "chip" }, r.kind) },
      { label: "Session", render: (r) => h("span", { class: "mono small" }, r.session_id || "—") },
      { label: "Details", render: (r) => h("span", { class: "mono small" }, Object.entries(r.detail).map(([k, v]) => `${k}=${Array.isArray(v) ? v.join("|") : v}`).join("  ")) },
    ], rows, { empty: "No activity yet." }));
  });
}

// ===================================================================== API keys (admin)

export function keys(root, ctx) {
  const body = h("div");
  const name = h("input", { placeholder: "e.g. soc-agent-prod", maxlength: 64 });
  const role = select("role", [["analyst", "analyst — sanitize, dashboards, review"], ["admin", "admin — also re-identify, policy, keys"]], "analyst");
  const load = () => mount(body, async () => {
    const rows = await api("/api/keys");
    return card(null, table([
      { label: "Name", key: "name" },
      { label: "Role", render: (k) => h("span", { class: `badge ${k.role === "admin" ? "accent" : ""}` }, k.role) },
      { label: "Key", render: (k) => h("span", { class: "mono" }, `${k.prefix}…`) },
      { label: "Created", render: (k) => when(k.created_at) },
      { label: "Last used", render: (k) => when(k.last_used) },
      { label: "Status", render: (k) => k.revoked ? h("span", { class: "muted" }, "revoked") : h("span", { class: "status good" }, icon("check"), "active") },
      { label: "", render: (k) => k.revoked ? "" : h("button", { class: "btn sm danger", onclick: async () => {
        const ok = await modal("Revoke key", h("p", null, `Requests using “${k.name}” will be rejected immediately.`),
          [{ label: "Cancel", value: false }, { label: "Revoke", value: true, class: "danger solid" }]);
        if (!ok) return;
        try { await api(`/api/keys/${k.id}`, { method: "DELETE" }); toast("Key revoked."); load(); } catch (e) { toast(e.message, "error"); }
      } }, "Revoke") },
    ], rows));
  });
  const create = async () => {
    if (!name.value.trim()) return toast("Give the key a name.");
    try {
      const r = await api("/api/keys", { method: "POST", body: { name: name.value.trim(), role: role.value } });
      name.value = "";
      await modal("New API key", [
        h("p", null, "Copy it now — it is shown only once and cannot be recovered."),
        h("div", { class: "keybox" }, r.key),
        h("button", { class: "btn sm", onclick: async () => { try { await navigator.clipboard.writeText(r.key); toast("Copied."); } catch { toast("Select the key and copy it manually."); } } }, icon("copy"), "Copy key")],
      [{ label: "Done", value: true, class: "primary" }]);
      load();
    } catch (e) { toast(e.message, "error"); }
  };
  root.append(head("API keys", "Keys for people (dashboard sign-in) and for agents calling the REST API."),
    card(h("h2", null, "Create a key"), h("div", { class: "fields" }, field("Name", name), field("Role", role),
      h("div", { class: "row", style: { "align-self": "end" } }, h("button", { class: "btn primary", onclick: create }, icon("key"), "Create")))),
    h("div", { style: { height: "16px" } }), body);
  load();
}
