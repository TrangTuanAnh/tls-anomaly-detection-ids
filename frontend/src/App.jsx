import React, { useEffect, useMemo, useState } from "react";
import "./styles.css";
import { apiGet } from "./api";
import { Table } from "./components/Table";

function fmtTime(s) {
  if (!s) return "";
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) return String(s);
  return d.toLocaleString();
}

function Badge({ children }) {
  return <span className="badge">{children}</span>;
}

function SeverityBadge({ sev }) {
  const label = sev || "—";
  return <Badge>{label}</Badge>;
}

export default function App() {
  const [tab, setTab] = useState("events");

  // data
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [actions, setActions] = useState([]);

  const [errMsg, setErrMsg] = useState("");

  async function refresh() {
    setErrMsg("");

    // Events (read-only, no filter)
    try {
      const e = await apiGet(`/api/events?limit=200`);
      setEvents(e);
    } catch (e) {
      setErrMsg(String(e.message || e));
    }

    // Alerts (read-only, no filter)
    try {
      const a = await apiGet(`/api/alerts?limit=200`);
      setAlerts(a);
    } catch {}

    // Firewall actions (read-only, no filter)
    try {
      const fa = await apiGet(`/api/firewall-actions?limit=200`);
      setActions(fa);
    } catch {}
  }

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 5000); // auto refresh
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const kpis = useMemo(() => {
    const totalEvents = events.length;
    const totalAlerts = alerts.length;
    const blocked = actions.filter(
      (x) => x.action_type === "BLOCK" && x.status === "EXECUTED"
    ).length;
    const pending = actions.filter((x) => x.status === "PENDING").length;
    return { totalEvents, totalAlerts, blocked, pending };
  }, [events, alerts, actions]);

  const eventsCols = [
    { key: "event_time", title: "Time", render: (r) => fmtTime(r.event_time) },
    { key: "src_ip", title: "Src IP" },
    { key: "dst_ip", title: "Dst IP" },
    { key: "tls_version", title: "TLS" },
    { key: "ja3_hash", title: "JA3" },
    { key: "verdict", title: "Verdict", render: (r) => <Badge>{r.verdict}</Badge> },
  ];

  const alertsCols = [
    { key: "created_at", title: "Time", render: (r) => fmtTime(r.created_at) },
    { key: "severity", title: "Severity", render: (r) => <SeverityBadge sev={r.severity} /> },
    { key: "status", title: "Status", render: (r) => <Badge>{r.status}</Badge> },
    { key: "title", title: "Title" },
    { key: "tls_event_id", title: "Event ID" },
  ];

  const actionsCols = [
    { key: "created_at", title: "Time", render: (r) => fmtTime(r.created_at) },
    { key: "src_ip", title: "Src IP" },
    { key: "action_type", title: "Action", render: (r) => <Badge>{r.action_type}</Badge> },
    { key: "status", title: "Status", render: (r) => <Badge>{r.status}</Badge> },
    { key: "executed_at", title: "Executed", render: (r) => fmtTime(r.executed_at) },
    {
      key: "error_message",
      title: "Error",
      render: (r) => (r.error_message ? String(r.error_message).slice(0, 80) : ""),
    },
  ];

  return (
    <div className="container">
      <div className="card">
        <div className="header">
          <div>
            <div className="h-title">TLS IDS Viewer</div>
          </div>
          <div className="row">
            <Badge>Events: {kpis.totalEvents}</Badge>
            <Badge>Alerts: {kpis.totalAlerts}</Badge>
            <Badge>Blocked: {kpis.blocked}</Badge>
            <Badge>Pending: {kpis.pending}</Badge>
            <button className="btn" onClick={refresh}>
              Refresh
            </button>
          </div>
        </div>

        {errMsg ? (
          <div className="muted" style={{ padding: "0 16px 12px" }}>
            <Badge>Error</Badge> {errMsg}
          </div>
        ) : null}

        <div className="nav">
          <button
            className={tab === "alerts" ? "active" : ""}
            onClick={() => setTab("alerts")}
          >
            Alerts
          </button>
          <button
            className={tab === "firewall" ? "active" : ""}
            onClick={() => setTab("firewall")}
          >
            Firewall
          </button>
          <button
            className={tab === "events" ? "active" : ""}
            onClick={() => setTab("events")}
          >
            Events
          </button>
        </div>

        {tab === "alerts" && (
          <Table columns={alertsCols} rows={alerts} rowKey={(r) => r.id} />
        )}

        {tab === "firewall" && (
          <Table columns={actionsCols} rows={actions} rowKey={(r) => r.id} />
        )}

        {tab === "events" && (
          <Table columns={eventsCols} rows={events} rowKey={(r) => r.id} />
        )}
      </div>
    </div>
  );
}
