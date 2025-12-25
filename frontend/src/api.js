export async function apiGet(path) {
  const token = localStorage.getItem("session") || "";
  const headers = { "Accept": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, { headers });
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return await res.json();
}

export async function apiPost(path, body) {
  const token = localStorage.getItem("session") || "";
  const headers = { "Content-Type": "application/json", "Accept": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(path, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => "");
    throw new Error(`POST ${path} -> ${res.status} ${txt.slice(0,200)}`);
  }
  return await res.json().catch(() => ({}));
}
