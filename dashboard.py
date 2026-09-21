"""
Local read-only dashboard for the process monitor.

Serves a modern, interactive dashboard at http://127.0.0.1:8787 with:
- Live stats cards (total events, alerts, threat breakdowns)
- Risk-level filter buttons
- Process name search
- Client-side filtering with a JSON API
- Auto-refresh every 5 seconds

Run alongside monitor.py.
"""

import json
import os
import signal
import sqlite3
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.db")
PORT = 8787


# ---------------------------------------------------------------------------
# Data access
# ---------------------------------------------------------------------------

def get_stats():
    if not os.path.exists(DB_PATH):
        return {"total": 0, "alerts": 0, "suspicious": 0, "malicious": 0,
                "benign": 0, "error": 0, "classified": 0}
    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        """SELECT
             COUNT(*) AS total,
             SUM(CASE WHEN risk IN ('suspicious','malicious') THEN 1 ELSE 0 END) AS alerts,
             SUM(CASE WHEN risk='suspicious' THEN 1 ELSE 0 END) AS suspicious,
             SUM(CASE WHEN risk='malicious' THEN 1 ELSE 0 END) AS malicious,
             SUM(CASE WHEN risk='benign' THEN 1 ELSE 0 END) AS benign,
             SUM(CASE WHEN risk='error' THEN 1 ELSE 0 END) AS error,
             SUM(CASE WHEN classified=1 THEN 1 ELSE 0 END) AS classified
           FROM events"""
    ).fetchone()
    conn.close()
    keys = ["total", "alerts", "suspicious", "malicious", "benign", "error", "classified"]
    return {k: (v or 0) for k, v in zip(keys, row)}


def get_events(limit=500, risk=None, search=None):
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    query = "SELECT * FROM events"
    params = []
    clauses = []
    if risk:
        if risk == "alerts":
            clauses.append("risk IN ('suspicious','malicious')")
        elif risk in ("benign", "error"):
            clauses.append("risk = ?")
            params.append(risk)
        else:
            clauses.append("risk = ?")
            params.append(risk)
    if search:
        clauses.append("(name LIKE ? OR path LIKE ? OR command_line LIKE ?)")
        term = f"%{search}%"
        params.extend([term, term, term])
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Process Monitor</title>
<style>
  :root {
    --bg: #0b0e14;
    --surface: #141820;
    --surface2: #1a1f2b;
    --border: #262d3a;
    --text: #e2e8f0;
    --text-dim: #7b879a;
    --accent: #3b82f6;
    --green: #22c55e;
    --yellow: #eab308;
    --red: #ef4444;
    --orange: #f97316;
    --radius: 10px;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    line-height: 1.5; min-height: 100vh;
  }
  .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

  /* Header */
  .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 28px; }
  .header h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.3px; }
  .header h1 span { color: var(--accent); }
  .live-badge {
    display: inline-flex; align-items: center; gap: 6px;
    font-size: 12px; color: var(--green); font-weight: 500;
    background: rgba(34,197,94,0.1); padding: 4px 12px; border-radius: 20px;
  }
  .live-badge::before {
    content: ''; width: 7px; height: 7px; border-radius: 50%;
    background: var(--green); animation: pulse 2s infinite;
  }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }

  /* Stats cards */
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 28px; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); padding: 18px 20px;
    transition: border-color 0.15s;
  }
  .stat-card:hover { border-color: #3a4355; }
  .stat-card .label { font-size: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; font-weight: 500; }
  .stat-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; }
  .stat-card .value.accent { color: var(--accent); }
  .stat-card .value.red { color: var(--red); }
  .stat-card .value.yellow { color: var(--yellow); }
  .stat-card .value.green { color: var(--green); }
  .stat-card .value.orange { color: var(--orange); }

  /* Toolbar */
  .toolbar {
    display: flex; align-items: center; gap: 10px; margin-bottom: 18px; flex-wrap: wrap;
  }
  .filter-btn {
    background: var(--surface); border: 1px solid var(--border);
    color: var(--text-dim); padding: 6px 14px; border-radius: 6px;
    font-size: 13px; cursor: pointer; transition: all 0.15s; font-weight: 500;
  }
  .filter-btn:hover { border-color: #3a4355; color: var(--text); }
  .filter-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }
  .search-box {
    flex: 1; min-width: 220px; background: var(--surface); border: 1px solid var(--border);
    color: var(--text); padding: 7px 14px; border-radius: 6px;
    font-size: 13px; outline: none; transition: border-color 0.15s;
  }
  .search-box::placeholder { color: var(--text-dim); }
  .search-box:focus { border-color: var(--accent); }

  /* Table */
  .table-wrap {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius); overflow: hidden;
  }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  thead th {
    text-align: left; padding: 12px 14px; font-size: 11px; font-weight: 600;
    color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.4px;
    background: var(--surface2); border-bottom: 1px solid var(--border);
    position: sticky; top: 0; cursor: pointer; user-select: none;
  }
  thead th:hover { color: var(--text); }
  tbody td {
    padding: 10px 14px; border-bottom: 1px solid var(--border);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 300px;
  }
  tbody tr { transition: background 0.1s; }
  tbody tr:hover { background: rgba(59,130,246,0.06); }
  tbody tr.malicious { background: rgba(239,68,68,0.08); }
  tbody tr.malicious:hover { background: rgba(239,68,68,0.14); }
  tbody tr.suspicious { background: rgba(234,179,8,0.07); }
  tbody tr.suspicious:hover { background: rgba(234,179,8,0.12); }

  /* Badges */
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.3px;
  }
  .badge.malicious { background: rgba(239,68,68,0.2); color: var(--red); }
  .badge.suspicious { background: rgba(234,179,8,0.2); color: var(--yellow); }
  .badge.benign { background: rgba(123,135,154,0.15); color: var(--text-dim); }
  .badge.error { background: rgba(249,115,22,0.2); color: var(--orange); }

  .empty { color: var(--text-dim); font-style: italic; padding: 32px 20px; text-align: center; }
  .conf { color: var(--text-dim); font-variant-numeric: tabular-nums; }
  .cmd { color: var(--text-dim); font-family: 'SF Mono', 'Cascadia Code', Consolas, monospace; font-size: 12px; }
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>&#x1f6e1;&#xfe0f; Process <span>Monitor</span></h1>
    <div class="live-badge">LIVE</div>
  </div>

  <div class="stats" id="stats">
    <div class="stat-card"><div class="label">Total Events</div><div class="value accent" id="s-total">-</div></div>
    <div class="stat-card"><div class="label">Alerts</div><div class="value red" id="s-alerts">-</div></div>
    <div class="stat-card"><div class="label">Suspicious</div><div class="value yellow" id="s-suspicious">-</div></div>
    <div class="stat-card"><div class="label">Malicious</div><div class="value red" id="s-malicious">-</div></div>
    <div class="stat-card"><div class="label">Benign</div><div class="value green" id="s-benign">-</div></div>
    <div class="stat-card"><div class="label">Classified</div><div class="value accent" id="s-classified">-</div></div>
  </div>

  <div class="toolbar">
    <button class="filter-btn active" data-filter="all">All</button>
    <button class="filter-btn" data-filter="alerts">Alerts</button>
    <button class="filter-btn" data-filter="malicious">Malicious</button>
    <button class="filter-btn" data-filter="suspicious">Suspicious</button>
    <button class="filter-btn" data-filter="benign">Benign</button>
    <button class="filter-btn" data-filter="error">Errors</button>
    <input class="search-box" id="search" type="text" placeholder="Search process name, path, or command line...">
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Time (UTC)</th>
          <th>Risk</th>
          <th>Name</th>
          <th>Path</th>
          <th>Command Line</th>
          <th>Parent</th>
          <th>Reason</th>
          <th>Conf.</th>
        </tr>
      </thead>
      <tbody id="tbody"></tbody>
    </table>
    <div class="empty" id="empty-state">No events yet &mdash; start monitor.py first.</div>
  </div>
</div>

<script>
let allRows = [];
let currentFilter = 'all';
let currentSearch = '';

function esc(s) {
  if (s == null) return '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function renderTable() {
  const tbody = document.getElementById('tbody');
  const empty = document.getElementById('empty-state');
  let filtered = allRows;

  if (currentFilter !== 'all') {
    if (currentFilter === 'alerts') {
      filtered = filtered.filter(r => r.risk === 'suspicious' || r.risk === 'malicious');
    } else {
      filtered = filtered.filter(r => r.risk === currentFilter);
    }
  }

  if (currentSearch) {
    const q = currentSearch.toLowerCase();
    filtered = filtered.filter(r =>
      (r.name || '').toLowerCase().includes(q) ||
      (r.path || '').toLowerCase().includes(q) ||
      (r.command_line || '').toLowerCase().includes(q)
    );
  }

  if (filtered.length === 0) {
    tbody.innerHTML = '';
    empty.style.display = 'block';
    return;
  }
  empty.style.display = 'none';

  tbody.innerHTML = filtered.map(r => {
    const cls = (r.risk === 'malicious' || r.risk === 'suspicious') ? r.risk : '';
    const badgeCls = r.risk || 'benign';
    const confTxt = r.confidence != null ? Math.round(r.confidence * 100) + '%' : '-';
    const ts = (r.ts || '').slice(0, 19).replace('T', ' ');
    return `<tr class="${cls}">
      <td>${esc(ts)}</td>
      <td><span class="badge ${badgeCls}">${esc(r.risk || '-')}</span></td>
      <td>${esc(r.name)}</td>
      <td title="${esc(r.path)}">${esc(r.path)}</td>
      <td class="cmd" title="${esc(r.command_line)}">${esc(r.command_line)}</td>
      <td>${esc(r.parent_name)} (${esc(r.parent_pid)})</td>
      <td>${esc(r.reason)}</td>
      <td class="conf">${confTxt}</td>
    </tr>`;
  }).join('');
}

function updateStats(s) {
  document.getElementById('s-total').textContent = s.total;
  document.getElementById('s-alerts').textContent = s.alerts;
  document.getElementById('s-suspicious').textContent = s.suspicious;
  document.getElementById('s-malicious').textContent = s.malicious;
  document.getElementById('s-benign').textContent = s.benign;
  document.getElementById('s-classified').textContent = s.classified;
}

async function refresh() {
  try {
    const params = new URLSearchParams();
    if (currentFilter !== 'all') params.set('risk', currentFilter);
    if (currentSearch) params.set('q', currentSearch);
    params.set('limit', '500');
    const [statsRes, eventsRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/events?' + params.toString()),
    ]);
    const stats = await statsRes.json();
    const events = await eventsRes.json();
    updateStats(stats);
    allRows = events;
    renderTable();
  } catch (e) {
    console.error('refresh failed', e);
  }
}

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.filter;
    refresh();
  });
});

// Search
let searchTimer;
document.getElementById('search').addEventListener('input', e => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    currentSearch = e.target.value.trim();
    refresh();
  }, 250);
});

// Initial load + auto-refresh
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, status, content_type, body_bytes):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body_bytes)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8",
                        DASHBOARD_HTML.encode("utf-8"))

        elif path == "/api/stats":
            data = get_stats()
            self._send(200, "application/json",
                        json.dumps(data).encode("utf-8"))

        elif path == "/api/events":
            limit = int(qs.get("limit", ["500"])[0])
            risk = qs.get("risk", [None])[0]
            search = qs.get("q", [None])[0]
            events = get_events(limit=limit, risk=risk, search=search)
            rows = []
            for r in events:
                (_id, ts, pid, name, pth, cmd, pname, ppid,
                 risk_val, reason, conf, classified) = r
                rows.append({
                    "id": _id, "ts": ts, "pid": pid, "name": name,
                    "path": pth, "command_line": cmd,
                    "parent_name": pname, "parent_pid": ppid,
                    "risk": risk_val, "reason": reason,
                    "confidence": conf, "classified": classified,
                })
            self._send(200, "application/json",
                        json.dumps(rows).encode("utf-8"))

        else:
            self._send(404, "text/plain", b"Not found")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    # Auto-start monitor.py in background if not already running
    script_dir = os.path.dirname(os.path.abspath(__file__))
    monitor_script = os.path.join(script_dir, "monitor.py")
    monitor_proc = None
    if os.path.exists(monitor_script):
        try:
            monitor_proc = subprocess.Popen(
                [sys.executable, monitor_script],
                cwd=script_dir,
            )
            print(f"Started monitor.py (pid {monitor_proc.pid})")
        except Exception as e:
            print(f"Warning: could not start monitor.py: {e}")
    print(f"Dashboard running at http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    try:
        HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
    finally:
        if monitor_proc and monitor_proc.poll() is None:
            print("Stopping monitor.py...")
            monitor_proc.terminate()
            try:
                monitor_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                monitor_proc.kill()


if __name__ == "__main__":
    main()
