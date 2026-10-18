// App shell: sign-in, navigation, hash router, theme.

import { api, auth } from "./api.js";
import { clear, h, icon, put, toast } from "./dom.js";
import * as views from "./views.js";

const root = document.getElementById("root");

const NAV = [
  { href: "#/overview", label: "Overview", icon: "grid", view: views.overview },
  { href: "#/sanitize", label: "Sanitize", icon: "wand", view: views.sanitize },
  { href: "#/review", label: "Review queue", icon: "review", view: views.review, badge: true },
  { href: "#/sessions", label: "Sessions", icon: "layers", view: views.sessions },
  { href: "#/audit", label: "Audit log", icon: "list", view: views.audit },
  { href: "#/policy", label: "Policy", icon: "sliders", view: views.policy },
  { section: "Admin", admin: true },
  { href: "#/reidentify", label: "Re-identify", icon: "unlock", view: views.reidentify, admin: true },
  { href: "#/activity", label: "Activity log", icon: "activity", view: views.activity, admin: true },
  { href: "#/keys", label: "API keys", icon: "key", view: views.keys, admin: true },
];

// ------------------------------------------------------------------ theme
const THEME_KEY = "piisafe.theme";
function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
}
function currentTheme() {
  try { return localStorage.getItem(THEME_KEY) || "system"; } catch { return "system"; }
}
function cycleTheme() {
  const next = { system: "light", light: "dark", dark: "system" }[currentTheme()];
  try { localStorage.setItem(THEME_KEY, next); } catch { /* ignore */ }
  applyTheme(next);
  toast(`Theme: ${next}`);
}
applyTheme(currentTheme());

// ------------------------------------------------------------------ sign-in
function login(message) {
  const key = h("input", { type: "password", placeholder: "psk_…", autocomplete: "off", "aria-label": "API key" });
  const err = h("div", { role: "alert" }, message ? h("div", { class: "callout error" }, message) : null);
  const submit = async (e) => {
    e.preventDefault();
    auth.set(key.value.trim());
    try {
      const me = await api("/api/me");
      start(me);
    } catch (ex) {
      auth.clear();
      put(err, h("div", { class: "callout error" }, ex.status === 401 ? "That key is not valid or has been revoked." : ex.message));
    }
  };
  put(root, h("div", { class: "login" },
    h("form", { class: "card stack", onsubmit: submit },
      h("div", { class: "brand" }, icon("shield"), "PII-Safe"),
      h("p", { class: "muted", style: { margin: "0" } }, "Privacy guard for AI agents. Sign in with your API key."),
      h("label", { class: "field" }, "API key", key), err,
      h("button", { class: "btn primary", type: "submit" }, "Sign in"),
      h("p", { class: "muted small", style: { margin: "0" } }, "No key? An administrator can create one under API keys, or run ",
        h("code", null, "piisafe keys create <name>"), " on the server."))));
  key.focus();
}

// ------------------------------------------------------------------ shell
let me = null;
let badgeEl = null;

function start(user) {
  me = user;
  const nav = h("nav", { class: "nav", "aria-label": "Main" });
  for (const item of NAV) {
    if (item.admin && me.role !== "admin") continue;
    if (item.section) { nav.append(h("div", { class: "nav-section" }, item.section)); continue; }
    const a = h("a", { href: item.href }, icon(item.icon), item.label);
    if (item.badge) { badgeEl = h("span", { class: "badge count hidden" }); a.append(badgeEl); }
    nav.append(a);
  }
  const sidebar = h("aside", { class: "sidebar" },
    h("div", { class: "brand" }, icon("shield"), "PII-Safe"), nav,
    h("div", { class: "sidebar-foot" },
      h("div", { class: "who" }, h("b", null, me.name), h("span", { class: "muted small" }, `${me.role} · v${me.version}`)),
      h("div", { class: "row" },
        h("button", { class: "btn sm", onclick: cycleTheme, title: "Theme: system / light / dark" }, icon("sun"), "Theme"),
        h("button", { class: "btn sm", onclick: () => { auth.clear(); me = null; location.hash = ""; login(); } }, icon("logout"), "Sign out"))));
  const main = h("main", { class: "main", id: "main", tabindex: -1 });
  const menu = h("button", { class: "btn sm menu-btn", "aria-label": "Menu", onclick: () => sidebar.classList.toggle("open") }, icon("menu"));
  put(root, h("div", { class: "shell" }, sidebar, h("div", null, h("div", { class: "topbar" }, menu,
    h("span", { class: "brand" }, icon("shield"), "PII-Safe")), main)));
  if (!location.hash || location.hash === "#/") location.hash = "#/overview";
  route();
  refreshBadge();
}

async function refreshBadge(count) {
  if (!badgeEl) return;
  try {
    const n = count ?? (await api("/api/reviews")).length;
    badgeEl.textContent = String(n);
    badgeEl.classList.toggle("hidden", !n);
  } catch { /* ignore */ }
}

function go(hash) { location.hash = hash; }

function route() {
  if (!me) return;
  const main = document.getElementById("main");
  if (!main) return;
  const [path, query] = location.hash.slice(1).split("?");
  const params = new URLSearchParams(query || "");
  const parts = path.split("/").filter(Boolean);
  document.querySelector(".sidebar")?.classList.remove("open");
  for (const a of document.querySelectorAll(".nav a")) {
    a.toggleAttribute("aria-current", a.getAttribute("href") === `#/${parts[0] || "overview"}`);
    if (a.hasAttribute("aria-current")) a.setAttribute("aria-current", "page");
  }
  clear(main);
  const ctx = { me, go, refreshBadge };
  if (parts[0] === "sessions" && parts[1]) return views.sessionDetail(main, ctx, decodeURIComponent(parts[1]));
  const item = NAV.find((n) => n.href === `#/${parts[0]}` && (!n.admin || me.role === "admin"));
  (item?.view || views.overview)(main, ctx, params);
  main.focus({ preventScroll: true });
  window.scrollTo(0, 0);
}

window.addEventListener("hashchange", route);
window.addEventListener("piisafe:logout", () => { if (me) { auth.clear(); me = null; login("Your session ended — sign in again."); } });

// ------------------------------------------------------------------ boot
(async () => {
  if (!auth.get()) return login();
  try { start(await api("/api/me")); } catch { auth.clear(); login(); }
})();
