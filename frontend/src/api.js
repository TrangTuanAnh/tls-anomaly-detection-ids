// Read-only API helper (no auth / no write operations)
export async function apiGet(path) {
  const headers = { "Accept": "application/json" };
  const res = await fetch(path, { headers });
  if (!res.ok) throw new Error(`GET ${path} -> ${res.status}`);
  return await res.json();
}
