import React from "react";

export function Table({ columns, rows, rowKey }) {
  return (
    <div className="tableWrap">
      <table>
        <thead>
          <tr>
            {columns.map(c => <th key={c.key}>{c.title}</th>)}
          </tr>
        </thead>
        <tbody>
          {rows.length === 0 ? (
            <tr><td colSpan={columns.length} className="muted">No data</td></tr>
          ) : rows.map((r, idx) => (
            <tr key={rowKey ? rowKey(r) : idx}>
              {columns.map(c => <td key={c.key}>{c.render ? c.render(r) : String(r[c.key] ?? "")}</td>)}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
