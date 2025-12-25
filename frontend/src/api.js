const TOKEN_KEY = "access_token";

function normalizeErrText(txt) {
  if (!txt) return "";
  // If upstream returned HTML (nginx 502/504), avoid dumping tags into the UI.
  const t = String(txt)
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  return t.slice(0, 140);
}

async function readErrorText(res) {
  // Prefer JSON error if backend returns it
  const ct = (res.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("application/json")) {
    const j = await res.json().catch(() => null);
    if (j && typeof j === "object") {
      const msg = j.detail || j.message || j.error;
      if (msg) return String(msg).slice(0, 140);
    }
    return "";
  }
  const txt = await res.text().catch(() => "");
  return normalizeErrText(txt);
}

export async function apiGet(path) {
  const token = localStorage.getItem(TOKEN_KEY) || "";
  const headers = { Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(path, { headers });
  if (!res.ok) {
    const msg = await readErrorText(res);
    const tail = msg ? ` - ${msg}` : "";
    throw new Error(`GET ${path} -> ${res.status} ${res.statusText}${tail}`);
  }
  return await res.json();
}

export async function apiPost(path, body) {
  const token = localStorage.getItem(TOKEN_KEY) || "";
  const headers = { "Content-Type": "application/json", Accept: "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const msg = await readErrorText(res);
    const tail = msg ? ` - ${msg}` : "";
    throw new Error(`POST ${path} -> ${res.status} ${res.statusText}${tail}`);
  }

  // Some endpoints may return empty body
  return await res.json().catch(() => ({}));
}

export const authTokenStorageKey = TOKEN_KEY;
