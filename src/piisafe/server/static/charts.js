// Small dependency-free SVG charts.
// Single-series only (one hue, --series-1); identity is given by the card
// title, values by axis + tooltip + a table view. Bars: 4px rounded data end
// anchored to the baseline, 2px gaps, recessive grid, hover/focus tooltip.

import { h, s, clear, num, icon, put } from "./dom.js";

let tip;
function tooltip() {
  if (!tip) {
    tip = h("div", { class: "tooltip hidden", role: "tooltip" });
    document.body.append(tip);
  }
  return tip;
}
function showTip(evt, value, label) {
  const t = tooltip();
  put(t, h("strong", null, value), h("span", null, label));
  t.classList.remove("hidden");
  const r = evt.target.getBoundingClientRect();
  const x = evt.clientX ?? r.left + r.width / 2;
  const y = evt.clientY ?? r.top;
  const w = t.offsetWidth;
  t.style.setProperty("left", `${Math.min(window.innerWidth - w - 8, Math.max(8, x + 12))}px`);
  t.style.setProperty("top", `${Math.max(8, y - t.offsetHeight - 10)}px`);
}
function hideTip() { tip?.classList.add("hidden"); }

function niceMax(v) {
  if (v <= 4) return 4;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 2.5, 5, 10]) if (m * p >= v) return m * p;
  return 10 * p;
}

// Bar with a rounded data end; the baseline end stays square.
function barPath(x, y, w, hgt, horizontal) {
  const r = Math.min(4, (horizontal ? hgt : w) / 2, horizontal ? w : hgt);
  if (horizontal) return `M${x},${y}h${w - r}a${r},${r} 0 0 1 ${r},${r}v${hgt - 2 * r}a${r},${r} 0 0 1 -${r},${r}h-${w - r}z`;
  return `M${x},${y + hgt}v-${hgt - r}a${r},${r} 0 0 1 ${r},-${r}h${w - 2 * r}a${r},${r} 0 0 1 ${r},${r}v${hgt - r}z`;
}

function responsive(container, draw) {
  let last = 0;
  const render = () => {
    const w = Math.floor(container.clientWidth);
    if (w && w !== last) { last = w; clear(container); container.append(draw(w)); }
  };
  new ResizeObserver(render).observe(container);
  requestAnimationFrame(render);
}

/** Vertical columns over a continuous time axis. data: [{label, value, title}] */
export function columns(container, data, { unit = "findings" } = {}) {
  if (!data.some((d) => d.value)) return emptyChart(container);
  responsive(container, (width) => {
    const H = 200, m = { t: 10, r: 4, b: 24, l: 40 };
    const iw = width - m.l - m.r, ih = H - m.t - m.b;
    const max = niceMax(Math.max(...data.map((d) => d.value)));
    const band = iw / data.length, bw = Math.max(2, Math.min(28, band - 2));
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${width} ${H}`, height: H, role: "img",
      "aria-label": `${unit} per day` });
    for (let i = 0; i <= 4; i++) {
      const v = (max / 4) * i, y = m.t + ih - (v / max) * ih;
      svg.append(s("line", { class: i ? "gridline" : "baseline", x1: m.l, x2: width - m.r, y1: y, y2: y }),
        s("text", { x: m.l - 6, y: y + 4, "text-anchor": "end" }, num(v)));
    }
    const every = Math.ceil(data.length / Math.max(2, Math.floor(iw / 64)));
    data.forEach((d, i) => {
      const x = m.l + i * band + (band - bw) / 2;
      const bh = (d.value / max) * ih;
      const g = s("g");
      const hit = s("rect", { class: "hit", x: m.l + i * band, y: m.t, width: band, height: ih, tabindex: 0,
        "aria-label": `${d.title || d.label}: ${num(d.value)} ${unit}` });
      const on = (e) => { g.classList.add("on"); showTip(e, `${num(d.value)} ${unit}`, d.title || d.label); };
      const off = () => { g.classList.remove("on"); hideTip(); };
      hit.addEventListener("pointermove", on); hit.addEventListener("focus", on);
      hit.addEventListener("pointerleave", off); hit.addEventListener("blur", off);
      g.append(hit);
      if (bh > 0) g.append(s("path", { class: "bar", d: barPath(x, m.t + ih - bh, bw, bh, false) }));
      svg.append(g);
      if (i % every === 0) svg.append(s("text", { x: x + bw / 2, y: H - 6, "text-anchor": "middle" }, d.label));
    });
    return svg;
  });
}

/** Horizontal bars, sorted by the caller. data: [{label, value}] */
export function bars(container, data, { unit = "", labelWidth = 128 } = {}) {
  if (!data.length) return emptyChart(container);
  responsive(container, (width) => {
    const row = 26, gap = 2, m = { t: 4, r: 52, b: 4, l: labelWidth };
    const H = m.t + m.b + data.length * row;
    const iw = Math.max(40, width - m.l - m.r);
    const max = Math.max(...data.map((d) => d.value)) || 1;
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${width} ${H}`, height: H, role: "img",
      "aria-label": data.map((d) => `${d.label} ${d.value}`).join(", ") });
    svg.append(s("line", { class: "baseline", x1: m.l, x2: m.l, y1: m.t, y2: H - m.b }));
    data.forEach((d, i) => {
      const y = m.t + i * row + gap, bh = row - 2 * gap - 6, w = (d.value / max) * iw;
      const g = s("g");
      const hit = s("rect", { class: "hit", x: 0, y: m.t + i * row, width, height: row, tabindex: 0,
        "aria-label": `${d.label}: ${num(d.value)} ${unit}` });
      const on = (e) => { g.classList.add("on"); showTip(e, `${num(d.value)} ${unit}`.trim(), d.label); };
      const off = () => { g.classList.remove("on"); hideTip(); };
      hit.addEventListener("pointermove", on); hit.addEventListener("focus", on);
      hit.addEventListener("pointerleave", off); hit.addEventListener("blur", off);
      g.append(hit,
        s("path", { class: "bar", d: barPath(m.l, y + 3, Math.max(w, 2), bh, true) }),
        s("text", { class: "cat", x: m.l - 8, y: y + 3 + bh / 2 + 4, "text-anchor": "end" }, d.label),
        s("text", { class: "val", x: m.l + Math.max(w, 2) + 6, y: y + 3 + bh / 2 + 4 }, num(d.value)));
      svg.append(g);
    });
    return svg;
  });
}

function emptyChart(container) {
  put(container, h("div", { class: "chart-empty" }, "No data in this period"));
}

/** Card with a chart and a Table toggle (table view keeps values reachable without hover). */
export function chartCard(title, data, draw, cols) {
  const body = h("div");
  const tbl = h("div", { class: "hidden" });
  const btn = h("button", { class: "btn ghost sm", "aria-pressed": "false", onclick: () => {
    const showing = tbl.classList.toggle("hidden");
    body.classList.toggle("hidden", !showing);
    btn.setAttribute("aria-pressed", String(!showing));
  } }, icon("table"), "Table");
  tbl.append(h("div", { class: "table-wrap" }, h("table", null,
    h("thead", null, h("tr", null, cols.map((c) => h("th", { class: c.num ? "num" : null }, c.label)))),
    h("tbody", null, data.map((d) => h("tr", null, cols.map((c) =>
      h("td", { class: c.num ? "num" : null }, c.num ? num(d[c.key]) : d[c.key]))))))));
  const el = h("section", { class: "card" }, h("div", { class: "card-head" }, h("h2", null, title), btn), body, tbl);
  draw(body, data);
  return el;
}
