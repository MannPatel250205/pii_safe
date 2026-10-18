// API client. The key lives in sessionStorage (cleared when the tab closes),
// with an in-memory fallback when storage is unavailable.

const STORE = "piisafe.apiKey";
let memoryKey = null;

export const auth = {
  get() {
    try { return sessionStorage.getItem(STORE) || memoryKey; } catch { return memoryKey; }
  },
  set(key) {
    memoryKey = key;
    try { sessionStorage.setItem(STORE, key); } catch { /* private mode */ }
  },
  clear() {
    memoryKey = null;
    try { sessionStorage.removeItem(STORE); } catch { /* ignore */ }
  },
};

export class ApiError extends Error {
  constructor(status, detail) {
    super(typeof detail === "string" ? detail : detail?.message || `HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

function headers(extra = {}) {
  const key = auth.get();
  return key ? { Authorization: `Bearer ${key}`, ...extra } : extra;
}

async function handle(res) {
  let body = null;
  const type = res.headers.get("content-type") || "";
  if (type.includes("application/json")) body = await res.json();
  if (res.status === 401) window.dispatchEvent(new Event("piisafe:logout"));
  if (!res.ok) {
    let detail = body?.detail ?? `HTTP ${res.status}`;
    if (Array.isArray(detail)) detail = detail.map((d) => `${(d.loc || []).slice(1).join(".")}: ${d.msg}`).join("; ");
    throw new ApiError(res.status, detail);
  }
  return body;
}

export async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: headers(body !== undefined ? { "Content-Type": "application/json" } : {}),
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  return handle(res);
}

// Multipart upload with progress (fetch has no upload progress events).
export function upload(path, form, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", path);
    const key = auth.get();
    if (key) xhr.setRequestHeader("Authorization", `Bearer ${key}`);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress?.(e.loaded / e.total);
    xhr.onload = () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch { /* not json */ }
      if (xhr.status === 401) window.dispatchEvent(new Event("piisafe:logout"));
      if (xhr.status >= 200 && xhr.status < 300) resolve(body);
      else reject(new ApiError(xhr.status, body?.detail ?? `HTTP ${xhr.status}`));
    };
    xhr.onerror = () => reject(new ApiError(0, "network error"));
    xhr.send(form);
  });
}

// Authenticated download -> browser save dialog.
export async function download(path) {
  const res = await fetch(path, { headers: headers() });
  if (!res.ok) return handle(res);
  const blob = await res.blob();
  const name = /filename="?([^";]+)"?/.exec(res.headers.get("content-disposition") || "")?.[1] || "output.txt";
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
