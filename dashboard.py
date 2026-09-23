"""
Local dashboard for the process monitor.

Serves an auto-refreshing page at http://127.0.0.1:8787 showing pending
block approvals, recent alerts, and the full event log from events.db.
Run this alongside monitor.py - monitor.py polls the same DB and acts on
any decision you make here (Block / Dismiss) within about a second.
"""

import html
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.db")
PORT = 8787

PAGE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="5">
<title>Process Monitor</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background: #0f1117; color: #e6e6e6; margin: 0; padding: 24px; }}
  h1 {{ font-size: 20px; }}
  h2 {{ font-size: 15px; color: #9aa0ac; margin-top: 32px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #262a35; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 320px; }}
  th {{ color: #9aa0ac; font-weight: 500; }}
  tr.malicious {{ background: rgba(220, 60, 60, 0.18); }}
  tr.suspicious {{ background: rgba(220, 170, 40, 0.14); }}
  tr.pending {{ background: rgba(220, 170, 40, 0.28); }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge.malicious {{ background: #dc3c3c; color: white; }}
  .badge.suspicious {{ background: #dcaa28; color: #1a1a1a; }}
  .badge.benign {{ background: #2a2f3a; color: #9aa0ac; }}
  .badge.error {{ background: #555; color: white; }}
  .empty {{ color: #6b7280; font-style: italic; padding: 12px 0; }}
  .btn {{ display: inline-block; padding: 4px 10px; border-radius: 4px; text-decoration: none; font-size: 12px; font-weight: 600; margin-right: 6px; }}
  .btn.block {{ background: #dc3c3c; color: white; }}
  .btn.dismiss {{ background: #2a2f3a; color: #e6e6e6; }}
  .banner {{ background: rgba(220, 170, 40, 0.15); border: 1px solid #dcaa28; border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; font-size: 13px; }}
</style>
</head>
<body>
  <h1>Process Monitor</h1>
  <h2>Pending approval</h2>
  {pending_section}
  <h2>Recent alerts (suspicious / malicious)</h2>
  {alerts_table}
  <h2>All events (last 200)</h2>
  {events_table}
</body>
</html>
"""

DECISION_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="1;url=/">
<title>Recorded</title>
<style>body{{font-family:sans-serif;background:#0f1117;color:#e6e6e6;padding:40px;}}</style>
</head><body>{message} Redirecting back to the dashboard...</body></html>
"""


# Columns the current code expects that a database created by an older
# monitor.py doesn't have yet. Add them in place (existing rows are kept)
# so an old events.db doesn't crash every page load with "no such column".
ADDED_COLUMNS = (
    ("suggested_action", "TEXT"),
    ("action_taken", "TEXT"),
    ("confirmation_status", "TEXT DEFAULT 'none'"),
    ("user_decision", "TEXT"),
)


def open_db():
    """Open events.db and bring an old schema up to date (see ADDED_COLUMNS)."""
    conn = sqlite3.connect(DB_PATH)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    if existing:  # table exists; otherwise let the caller's query report it
        for col, decl in ADDED_COLUMNS:
            if col not in existing:
                conn.execute(f"ALTER TABLE events ADD COLUMN {col} {decl}")
        conn.commit()
    return conn


def esc(v):
    return html.escape(str(v)) if v is not None else ""


def render_rows(rows):
    out = []
    for r in rows:
        (_id, ts, pid, name, path, cmd, pname, ppid, risk, reason, conf,
         suggested_action, action_taken, confirmation_status, user_decision,
         classified) = r
        cls = risk if risk in ("malicious", "suspicious") else ""
        badge_cls = risk or "benign"
        conf_txt = f"{conf:.0%}" if conf is not None else "-"
        status = action_taken or confirmation_status or "-"
        out.append(
            f"<tr class='{cls}'>"
            f"<td>{esc(ts)[:19]}</td>"
            f"<td><span class='badge {badge_cls}'>{esc(risk or '-')}</span></td>"
            f"<td>{esc(name)}</td>"
            f"<td title='{esc(path)}'>{esc(path)}</td>"
            f"<td title='{esc(cmd)}'>{esc(cmd)}</td>"
            f"<td>{esc(pname)} ({esc(ppid)})</td>"
            f"<td>{esc(reason)}</td>"
            f"<td>{conf_txt}</td>"
            f"<td>{esc(status)}</td>"
            f"</tr>"
        )
    return "".join(out)


def build_table(rows, headers):
    if not rows:
        return "<div class='empty'>No events yet.</div>"
    head = "".join(f"<th>{h}</th>" for h in headers)
    return f"<table><tr>{head}</tr>{render_rows(rows)}</table>"


def render_pending(rows):
    if not rows:
        return "<div class='empty'>Nothing waiting on you right now.</div>"
    parts = ["<div class='banner'>These processes were flagged by Jev as "
             "likely malicious but confidence wasn't high enough to "
             "auto-block (or the process is on the protected list). "
             "Choose Block to terminate it now, or Dismiss to leave it running.</div>"]
    for (row_id, ts, pid, name, path, cmd, pname, ppid, risk, reason, conf,
         suggested_action, action_taken, confirmation_status, user_decision,
         classified) in rows:
        conf_txt = f"{conf:.0%}" if conf is not None else "n/a"
        parts.append(
            f"<table><tr>"
            f"<td><b>{esc(name)}</b> (pid {esc(pid)})</td>"
            f"<td>{esc(path)}</td>"
            f"<td>reason: {esc(reason)}, confidence: {conf_txt}</td>"
            f"<td>"
            f"<a class='btn block' href='/decide?id={row_id}&decision=block'>Block</a>"
            f"<a class='btn dismiss' href='/decide?id={row_id}&decision=ignore'>Dismiss</a>"
            f"</td>"
            f"</tr></table>"
        )
    return "".join(parts)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep console quiet

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/decide":
            self.handle_decide(parsed)
            return

        if parsed.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return

        headers = ["Time (UTC)", "Risk", "Name", "Path", "Command line",
                   "Parent", "Reason", "Conf.", "Status"]

        if not os.path.exists(DB_PATH):
            empty = "<div class='empty'>events.db not found yet - start monitor.py first.</div>"
            pending_html = alerts_html = events_html = empty
        else:
            conn = open_db()
            pending = conn.execute(
                "SELECT * FROM events WHERE confirmation_status = 'pending' "
                "ORDER BY id DESC"
            ).fetchall()
            alerts = conn.execute(
                """SELECT * FROM events WHERE risk IN ('suspicious','malicious')
                   ORDER BY id DESC LIMIT 100"""
            ).fetchall()
            events = conn.execute(
                "SELECT * FROM events ORDER BY id DESC LIMIT 200"
            ).fetchall()
            conn.close()
            pending_html = render_pending(pending)
            alerts_html = build_table(alerts, headers)
            events_html = build_table(events, headers)

        page = PAGE_TEMPLATE.format(
            pending_section=pending_html,
            alerts_table=alerts_html,
            events_table=events_html,
        )
        self._send_html(page)

    def handle_decide(self, parsed):
        qs = urllib.parse.parse_qs(parsed.query)
        row_id = qs.get("id", [None])[0]
        decision = qs.get("decision", [None])[0]

        if decision not in ("block", "ignore") or not row_id or not row_id.isdigit():
            self._send_html(DECISION_PAGE.format(message="Invalid request."), code=400)
            return

        if not os.path.exists(DB_PATH):
            self._send_html(DECISION_PAGE.format(message="No events database found."), code=404)
            return

        conn = open_db()
        conn.execute(
            "UPDATE events SET user_decision = ? "
            "WHERE id = ? AND confirmation_status = 'pending'",
            (decision, row_id),
        )
        conn.commit()
        conn.close()

        verb = "Block" if decision == "block" else "Dismiss"
        self._send_html(DECISION_PAGE.format(
            message=f"{verb} recorded - monitor.py will act on it shortly."
        ))

    def _send_html(self, page, code=200):
        body = page.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main():
    print(f"Dashboard running at http://127.0.0.1:{PORT}  (Ctrl+C to stop)")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
