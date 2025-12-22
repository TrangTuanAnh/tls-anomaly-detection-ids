import React, { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { apiGet, apiPost } from "./api";
import { Table } from "./components/Table";

function fmtTime(s) {
  if (!s) return "";
  // backend returns ISO or "YYYY-MM-DDTHH:MM:SS"
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(s);
  return d.toLocaleString();
}

function SeverityBadge({ sev }) {
  const label = sev || "—";
  return <span className="badge">{label}</span>;
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("jwt") || "");
  const [me, setMe] = useState(null);
  const [loginUser, setLoginUser] = useState("admin");
  const [loginPass, setLoginPass] = useState("Admin@12345");
  const [loginMsg, setLoginMsg] = useState("");

  async function doLogin(e) {
    e.preventDefault();
    setLoginMsg("");
    try {
      const r = await apiPost("/api/auth/login", { username: loginUser, password: loginPass });
      const t = r.access_token || "";
      if (!t) throw new Error("No token returned");
      localStorage.setItem("jwt", t);
      setToken(t);
    } catch (err) {
      setLoginMsg(String(err.message || err));
    }
  }

  function logout() {
    localStorage.removeItem("jwt");
    setToken("");
    setMe(null);
  }

  const [tab, setTab] = useState("dashboard");

  // data
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [actions, setActions] = useState([]);

  const [onlyAnom, setOnlyAnom] = useState(true);
  const [alertStatus, setAlertStatus] = useState("");
  const [alertSeverity, setAlertSeverity] = useState("");
  const [actionStatus, setActionStatus] = useState("");

  // manual action form
  const [ip, setIp] = useState("");
  const [atype, setAtype] = useState("BLOCK");
  const [msg, setMsg] = useState("");

  async function refresh() {
    try {
      const e = await apiGet(`/api/events?only_anomaly=${onlyAnom ? "true" : "false"}&limit=200`);
      setEvents(e);
    } catch {}
    try {
      const qs = new URLSearchParams();
      if (alertStatus) qs.set("status", alertStatus);
      if (alertSeverity) qs.set("severity", alertSeverity);
      qs.set("limit", "200");
      const a = await apiGet(`/api/alerts?${qs.toString()}`);
      setAlerts(a);
    } catch {}
    try {
      const qs = new URLSearchParams();
      if (actionStatus) qs.set("status", actionStatus);
      qs.set("limit", "200");
      const fa = await apiGet(`/api/firewall-actions?${qs.toString()}`);
      setActions(fa);
    } catch {}
  }

  useEffect(() => {
    // Fetch current user if logged in
    (async () => {
      if (!token) return;
      try {
        const u = await apiGet("/api/auth/me");
        setMe(u);
      } catch {
        // invalid token
        logout();
      }
    })();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    refresh();
  }, [token, onlyAnom, alertStatus, alertSeverity, actionStatus]);

  const kpis = useMemo(() => {
    const totalEvents = events.length;
    const totalAlerts = alerts.length;
    const blocked = actions.filter(x => x.action_type === "BLOCK" && x.status === "EXECUTED").length;
    const pending = actions.filter(x => x.status === "PENDING").length;
    return { totalEvents, totalAlerts, blocked, pending };
  }, [events, alerts, actions]);

  async function submitAction(e) {
    e.preventDefault();
    setMsg("");
    try {
      // Requires backend endpoint described in README-in-zip:
      await apiPost("/api/firewall-actions", { src_ip: ip.trim(), action_type: atype });
      setMsg("Created firewall action (PENDING).");
      setIp("");
      await refresh();
    } catch (err) {
      setMsg(String(err.message || err));
    }
  }

  const eventsCols = [
    { key: "event_time", title: "Time", render: r => fmtTime(r.event_time) },
    { key: "src_ip", title: "Src IP" },
    { key: "dst_ip", title: "Dst IP" },
    { key: "tls_version", title: "TLS" },
    { key: "ja3_hash", title: "JA3" },
    { key: "verdict", title: "Verdict", render: r => <span className="badge">{r.verdict}</span> },
  ];

  const alertsCols = [
    { key: "created_at", title: "Time", render: r => fmtTime(r.created_at) },
    { key: "severity", title: "Severity", render: r => <SeverityBadge sev={r.severity} /> },
    { key: "status", title: "Status", render: r => <span className="badge">{r.status}</span> },
    { key: "title", title: "Title" },
    { key: "tls_event_id", title: "Event ID" },
  ];

  const actionsCols = [
    { key: "created_at", title: "Time", render: r => fmtTime(r.created_at) },
    { key: "src_ip", title: "Src IP" },
    { key: "action_type", title: "Action", render: r => <span className="badge">{r.action_type}</span> },
    { key: "status", title: "Status", render: r => <span className="badge">{r.status}</span> },
    { key: "executed_at", title: "Executed", render: r => fmtTime(r.executed_at) },
    { key: "error_message", title: "Error", render: r => (r.error_message ? String(r.error_message).slice(0, 80) : "") },
  ];

  if (!token) {
    return (
      <div className="container">
        <div className="card" style={{maxWidth: 520, margin: "40px auto"}}>
          <div className="header">
            <div>
              <div className="h-title">TLS IDS Admin</div>
              <div className="muted">Login để truy cập dashboard (JWT)</div>
            </div>
          </div>
          <form style={{padding: 16}} onSubmit={doLogin}>
            <div className="muted" style={{marginBottom: 6}}>Username</div>
            <input value={loginUser} onChange={e => setLoginUser(e.target.value)} required />
            <div className="muted" style={{margin: "12px 0 6px"}}>Password</div>
            <input type="password" value={loginPass} onChange={e => setLoginPass(e.target.value)} required />
            <div className="row" style={{marginTop: 12}}>
              <button className="btn primary" type="submit">Login</button>
              <span className="muted">{loginMsg}</span>
            </div>
            <div className="muted" style={{marginTop: 12}}>
              Default: admin / Admin@12345 (đổi trong .env khi deploy)
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="container">
      <div className="card">
        <div className="header">
          <div>
            <div className="h-title">TLS IDS Admin</div>
            <div className="muted">Frontend-only UI (calls Backend API via /api/*)</div>
          </div>
          <div className="row">
            <span className="badge">User: {me ? `${me.username} (${me.role})` : "..."}</span>
            <span className="badge">Events: {kpis.totalEvents}</span>
            <span className="badge">Alerts: {kpis.totalAlerts}</span>
            <span className="badge">Blocked: {kpis.blocked}</span>
            <span className="badge">Pending: {kpis.pending}</span>
            <button className="btn" onClick={refresh}>Refresh</button>
            <button className="btn" onClick={logout}>Logout</button>
          </div>
        </div>

        <div className="nav">
          <button className={tab==="dashboard" ? "active" : ""} onClick={() => setTab("dashboard")}>Dashboard</button>
          <button className={tab==="alerts" ? "active" : ""} onClick={() => setTab("alerts")}>Alerts</button>
          <button className={tab==="firewall" ? "active" : ""} onClick={() => setTab("firewall")}>Firewall</button>
          <button className={tab==="events" ? "active" : ""} onClick={() => setTab("events")}>Events</button>
        </div>

        {tab === "dashboard" && (
          <div className="grid">
            <div className="card kpi">
              <div className="label">Events loaded</div>
              <div className="value">{kpis.totalEvents}</div>
              <div className="muted">Toggle anomaly-only in Events tab.</div>
            </div>
            <div className="card kpi">
              <div className="label">Alerts loaded</div>
              <div className="value">{kpis.totalAlerts}</div>
              <div className="muted">Filter by status/severity in Alerts tab.</div>
            </div>
            <div className="card kpi">
              <div className="label">Firewall actions</div>
              <div className="value">{actions.length}</div>
              <div className="muted">Pending / Executed / Failed actions.</div>
            </div>
          </div>
        )}

        {tab === "alerts" && (
          <>
            <div className="header" style={{borderBottom: "none"}}>
              <div className="controls">
                <label className="muted">Status</label>
                <select value={alertStatus} onChange={e => setAlertStatus(e.target.value)}>
                  <option value="">All</option>
                  <option value="OPEN">OPEN</option>
                  <option value="IN_PROGRESS">IN_PROGRESS</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="DISMISSED">DISMISSED</option>
                </select>
                <label className="muted">Severity</label>
                <select value={alertSeverity} onChange={e => setAlertSeverity(e.target.value)}>
                  <option value="">All</option>
                  <option value="LOW">LOW</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="HIGH">HIGH</option>
                  <option value="CRITICAL">CRITICAL</option>
                </select>
              </div>
            </div>
            <Table columns={alertsCols} rows={alerts} rowKey={r => r.id} />
          </>
        )}

        {tab === "firewall" && (
          <>
            <div className="header" style={{borderBottom: "none"}}>
              <div className="controls">
                <label className="muted">Status</label>
                <select value={actionStatus} onChange={e => setActionStatus(e.target.value)}>
                  <option value="">All</option>
                  <option value="PENDING">PENDING</option>
                  <option value="EXECUTED">EXECUTED</option>
                  <option value="FAILED">FAILED</option>
                  <option value="CANCELLED">CANCELLED</option>
                </select>
              </div>

              <form className="row" onSubmit={submitAction}>
                <input placeholder="src_ip (e.g. 192.168.56.10)" value={ip} onChange={e => setIp(e.target.value)} required />
                <select value={atype} onChange={e => setAtype(e.target.value)}>
                  <option value="BLOCK">BLOCK</option>
                  <option value="UNBLOCK">UNBLOCK</option>
                </select>
                <button className={"btn " + (atype === "BLOCK" ? "danger" : "primary")} type="submit">
                  Create {atype}
                </button>
                <span className="muted">{msg}</span>
              </form>
            </div>
            <Table columns={actionsCols} rows={actions} rowKey={r => r.id} />
            <div className="muted" style={{padding:"0 16px 16px"}}>
              Note: This UI creates firewall_actions with status=PENDING. Your firewall-controller will execute them.
            </div>
          </>
        )}

        {tab === "events" && (
          <>
            <div className="header" style={{borderBottom: "none"}}>
              <div className="controls">
                <label className="muted">Only anomaly</label>
                <select value={onlyAnom ? "true" : "false"} onChange={e => setOnlyAnom(e.target.value === "true")}>
                  <option value="true">true</option>
                  <option value="false">false</option>
                </select>
              </div>
            </div>
            <Table columns={eventsCols} rows={events} rowKey={r => r.id} />
          </>
        )}
      </div>
    </div>
  );
}
