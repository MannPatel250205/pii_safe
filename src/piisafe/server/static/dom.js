// DOM helpers. All user/log data goes through text nodes — never innerHTML —
// so a log line containing "<script>" is just text.

export function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

const SVG_NS = "http://www.w3.org/2000/svg";
export function s(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  setAttrs(el, attrs);
  append(el, children);
  return el;
}

function setAttrs(el, attrs) {
  if (!attrs) return;
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") el.setAttribute("class", v);
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "style" && typeof v === "object") for (const [p, val] of Object.entries(v)) el.style.setProperty(p, val);
    else if (k === "value" && "value" in el) el.value = v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

// Replace an element's children (null/false children are skipped, unlike Element.append).
export function put(el, ...children) {
  return append(clear(el), children);
}

// ------------------------------------------------------------------ icons
// 24px stroke icons, built as SVG nodes.
const ICONS = {
  shield: ["M12 2l8 3v6c0 5-3.4 9.3-8 11-4.6-1.7-8-6-8-11V5l8-3z", "M9 12l2 2 4-4"],
  grid: ["M3 3h7v7H3z", "M14 3h7v7h-7z", "M14 14h7v7h-7z", "M3 14h7v7H3z"],
  wand: ["M15 4V2", "M15 16v-2", "M8 9h2", "M20 9h2", "M17.8 11.8L19 13", "M17.8 6.2L19 5", "M12.2 6.2L11 5", "M3 21l9-9"],
  review: ["M9 11l3 3L22 4", "M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"],
  layers: ["M12 2l10 5-10 5L2 7l10-5z", "M2 17l10 5 10-5", "M2 12l10 5 10-5"],
  list: ["M8 6h13", "M8 12h13", "M8 18h13", "M3 6h.01", "M3 12h.01", "M3 18h.01"],
  sliders: ["M4 21v-7", "M4 10V3", "M12 21v-9", "M12 8V3", "M20 21v-5", "M20 12V3", "M1 14h6", "M9 8h6", "M17 16h6"],
  key: ["M21 2l-2 2", "M15.5 7.5l3 3L22 7l-3-3", "M11.4 11.6a5.5 5.5 0 1 1-7.8 7.8 5.5 5.5 0 0 1 7.8-7.8z", "M11.4 11.6L19 4"],
  unlock: ["M5 11h14v10H5z", "M7 11V7a5 5 0 0 1 9.9-1"],
  activity: ["M22 12h-4l-3 9L9 3l-3 9H2"],
  upload: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M17 8l-5-5-5 5", "M12 3v12"],
  download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "M7 10l5 5 5-5", "M12 15V3"],
  sun: ["M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z", "M12 1v2", "M12 21v2", "M4.2 4.2l1.4 1.4", "M18.4 18.4l1.4 1.4", "M1 12h2", "M21 12h2", "M4.2 19.8l1.4-1.4", "M18.4 5.6l1.4-1.4"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"],
  menu: ["M3 12h18", "M3 6h18", "M3 18h18"],
  check: ["M20 6L9 17l-5-5"],
  info: ["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 16v-4", "M12 8h.01"],
  alert: ["M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"],
  octagon: ["M7.9 2h8.2L22 7.9v8.2L16.1 22H7.9L2 16.1V7.9z", "M15 9l-6 6", "M9 9l6 6"],
  eye: ["M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"],
  trash: ["M3 6h18", "M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6", "M10 11v6", "M14 11v6", "M9 6V4h6v2"],
  copy: ["M9 9h13v13H9z", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  table: ["M3 3h18v18H3z", "M3 9h18", "M3 15h18", "M9 3v18"],
};

export function icon(name) {
  return s("svg", { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2,
    "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" },
  ...(ICONS[name] || []).map((d) => s("path", { d })));
}

// ------------------------------------------------------------------ formatting
const nf = new Intl.NumberFormat();
export const num = (n) => nf.format(n ?? 0);

export function when(ts) {
  if (!ts) return "—";
  const d = new Date(ts * 1000);
  const diff = (Date.now() - d.getTime()) / 1000;
  if (diff < 60) return "just now";
  if (diff < 3600) return `${Math.floor(diff / 60)} min ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)} h ago`;
  return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " +
    d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
export const fullTime = (ts) => (ts ? new Date(ts * 1000).toLocaleString() : "");

// Exposure score -> status (icon + label, never colour alone).
export function exposure(score) {
  const v = Number(score || 0);
  const [cls, label, ic] = v >= 75 ? ["critical", "Critical", "octagon"] : v >= 50 ? ["serious", "High", "alert"]
    : v >= 25 ? ["warning", "Moderate", "alert"] : ["good", "Low", "check"];
  return h("span", { class: `status ${cls}`, title: `Exposure score ${v.toFixed(1)} / 100` },
    icon(ic), `${label} · ${v.toFixed(0)}`);
}

export function actionChip(action) {
  const short = { pseudonymise: "pseudonymise", redact: "redact", mask: "mask", block: "block", allow: "allow" };
  return h("span", { class: `act ${action}` }, short[action] || action);
}

// ------------------------------------------------------------------ feedback
let toastTimer;
export function toast(message, kind = "") {
  document.querySelector(".toast")?.remove();
  const t = h("div", { class: `toast ${kind}`, role: "status" }, message);
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), 4200);
}

export function modal(title, body, actions) {
  return new Promise((resolve) => {
    const close = (v) => { bg.remove(); resolve(v); };
    const bg = h("div", { class: "modal-bg", onclick: (e) => e.target === bg && close(null) },
      h("div", { class: "card modal", role: "dialog", "aria-modal": "true", "aria-label": title },
        h("div", { class: "card-head" }, h("h2", null, title)),
        h("div", { class: "stack" }, body),
        h("div", { class: "row", style: { "margin-top": "18px", "justify-content": "flex-end" } },
          ...actions.map((a) => h("button", { class: `btn ${a.class || ""}`, onclick: () => close(a.value) }, a.label)))));
    bg.addEventListener("keydown", (e) => e.key === "Escape" && close(null));
    document.body.append(bg);
    (bg.querySelector("input, button.primary, button.solid") || bg.querySelector("button"))?.focus();
  });
}

export function table(columns, rows, { empty = "Nothing here yet.", onRow } = {}) {
  if (!rows.length) return h("div", { class: "empty" }, empty);
  return h("div", { class: "table-wrap" },
    h("table", null,
      h("thead", null, h("tr", null, columns.map((c) => h("th", { class: c.num ? "num" : null }, c.label)))),
      h("tbody", null, rows.map((r) => h("tr", {
        class: onRow ? "click" : null, tabindex: onRow ? 0 : null,
        onclick: onRow ? () => onRow(r) : null,
        onkeydown: onRow ? (e) => e.key === "Enter" && onRow(r) : null,
      }, columns.map((c) => h("td", { class: c.num ? "num" : null }, c.render ? c.render(r) : r[c.key])))))));
}

export function card(title, ...body) {
  return h("section", { class: "card" }, title ? h("div", { class: "card-head" }, ...[].concat(title)) : null, ...body);
}

export function kpi(label, value, sub, extra) {
  return h("div", { class: "card kpi" }, h("div", { class: "label" }, label), h("div", { class: "value" }, value),
    sub ? h("div", { class: "sub" }, sub) : null, extra || null);
}
