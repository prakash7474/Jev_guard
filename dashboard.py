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
from datetime import datetime, timezone
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
  .btn.allow {{ background: #2f7d43; color: white; }}
  .btn.remove {{ background: #2a2f3a; color: #dcaa28; }}
  a.evt {{ color: #7fb3ff; text-decoration: none; }}
  a.evt:hover {{ text-decoration: underline; }}
  .banner {{ background: rgba(220, 170, 40, 0.15); border: 1px solid #dcaa28; border-radius: 6px; padding: 10px 14px; margin-bottom: 12px; font-size: 13px; }}
  .banner.ok {{ background: rgba(60, 200, 120, 0.12); border-color: #3cc878; }}
  .banner.down {{ background: rgba(220, 60, 60, 0.18); border-color: #dc3c3c; }}
  .recorded {{ color: #7fb3ff; font-size: 12px; margin-top: 4px; }}
  .stats {{ display: flex; gap: 24px; margin-bottom: 12px; flex-wrap: wrap; }}
  .stat {{ background: #171a22; border: 1px solid #262a35; border-radius: 6px; padding: 10px 16px; }}
  .stat .val {{ font-size: 20px; font-weight: 700; }}
  .stat .lbl {{ font-size: 11px; color: #9aa0ac; text-transform: uppercase; }}
</style>
</head>
<body>
  <h1>Process Monitor</h1>
  {monitor_status}
  {pending_section}
  {allowlist_section}
  {alerts_section}
  {events_section}
  {usage_section}
</body>
</html>
"""

DECISION_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta http-equiv="refresh" content="1;url=/">
<title>Recorded</title>
<style>body{{font-family:sans-serif;background:#0f1117;color:#e6e6e6;padding:40px;}}</style>
</head><body>{message} Redirecting back to the dashboard...</body></html>
"""

DETAIL_PAGE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Event detail - Process Monitor</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background: #0f1117; color: #e6e6e6; margin: 0; padding: 24px; }}
  h1 {{ font-size: 18px; }}
  h2 {{ font-size: 15px; color: #9aa0ac; margin-top: 28px; }}
  .back {{ font-size: 13px; }}
  .back a {{ color: #7fb3ff; text-decoration: none; }}
  table {{ border-collapse: collapse; font-size: 13px; width: 100%; }}
  th, td {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid #262a35; vertical-align: top; }}
  th {{ color: #9aa0ac; font-weight: 500; white-space: nowrap; width: 180px; }}
  td.cmd {{ font-family: Consolas, monospace; white-space: pre-wrap; word-break: break-all; }}
  .empty {{ color: #6b7280; font-style: italic; padding: 12px 0; }}
  .badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
  .badge.malicious {{ background: #dc3c3c; color: white; }}
  .badge.suspicious {{ background: #dcaa28; color: #1a1a1a; }}
  .badge.benign {{ background: #2a2f3a; color: #9aa0ac; }}
  .badge.error {{ background: #555; color: white; }}
</style>
</head>
<body>
  <p class='back'><a href="/">&larr; Back to dashboard</a></p>
  <h1>Event {event_id} - {name}</h1>
  {fields_table}
  {usage_section}
</body>
</html>
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
    # Usage table from a newer monitor.py - create it if the dashboard is
    # opened against an events.db that predates it.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS jev_usage (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event_id INTEGER,
            model TEXT,
            status TEXT,
            input_tokens INTEGER,
            output_tokens INTEGER,
            latency_ms INTEGER,
            error TEXT
        )
    """)
    # Allowlist table from a newer monitor.py - create it if needed so the
    # dashboard works even when it opens the DB before the monitor does.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS allowlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            name TEXT NOT NULL,
            path TEXT
        )
    """)
    # Heartbeat key/value store from monitor.py - created here too so this
    # page can render the monitor-status banner against a fresh DB.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()
    return conn


def esc(v):
    return html.escape(str(v)) if v is not None else ""


def section(title, content):
    """Heading + content, or nothing at all when the list is empty - so an
    empty section doesn't render a heading with a 'nothing here' note."""
    if not content:
        return ""
    return f"<h2>{title}</h2>{content}"


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
            f"<td><a class='evt' href='/event?id={_id}'>{esc(name)}</a></td>"
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
        return ""
    head = "".join(f"<th>{h}</th>" for h in headers)
    return f"<table><tr>{head}</tr>{render_rows(rows)}</table>"


def render_pending(rows):
    if not rows:
        return ""
    parts = ["<div class='banner'>These processes were flagged by Jev as "
             "likely malicious but confidence wasn't high enough to "
             "auto-block (or the process is on the protected list). "
             "Choose Block to terminate it now, Dismiss to leave it running, "
             "or Allow to trust this process name/path and skip Jev "
             "classification for future launches.</div>"]
    for (row_id, ts, pid, name, path, cmd, pname, ppid, risk, reason, conf,
         suggested_action, action_taken, confirmation_status, user_decision,
         classified) in rows:
        conf_txt = f"{conf:.0%}" if conf is not None else "n/a"
        decision_note = ""
        if user_decision:
            verb = "Block" if user_decision == "block" else "Dismiss"
            decision_note = (
                f"<div class='recorded'>&#10003; {verb} recorded - "
                "monitor.py will apply it as soon as it checks in.</div>"
            )
        parts.append(
            f"<table><tr>"
            f"<td><b><a class='evt' href='/event?id={row_id}'>{esc(name)}</a></b> "
            f"(pid {esc(pid)})</td>"
            f"<td>{esc(path)}</td>"
            f"<td>reason: {esc(reason)}, confidence: {conf_txt}"
            f"{decision_note}</td>"
            f"<td>"
            f"<a class='btn block' href='/decide?id={row_id}&decision=block'>Block</a>"
            f"<a class='btn dismiss' href='/decide?id={row_id}&decision=ignore'>Dismiss</a>"
            f"<a class='btn allow' href='/allow?id={row_id}'>Allow</a>"
            f"</td>"
            f"</tr></table>"
        )
    return "".join(parts)


def monitor_is_alive(last_seen):
    """True if monitor.py's heartbeat is fresh enough (<= 20s) that decisions
    recorded now will actually get applied. The monitor stamps its
    heartbeat every loop pass (~1/s idle, slower when classifying)."""
    if not last_seen:
        return False
    try:
        last = datetime.fromisoformat(last_seen)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - last).total_seconds()
    except ValueError:
        return False
    return age <= 20


def render_monitor_status(last_seen):
    """Banner showing whether monitor.py is alive enough to actually apply
    Block/Dismiss/Allow decisions. This is the #1 reason a click 'does
    nothing': the dashboard records the decision, but a stopped monitor
    never picks it up."""
    if not last_seen:
        return ("<div class='banner'>monitor.py hasn't checked in yet - "
                "decisions you record here will not be applied until it "
                "is running.</div>")
    try:
        last = datetime.fromisoformat(last_seen)
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)
        age = int((datetime.now(timezone.utc) - last).total_seconds())
    except ValueError:
        return "<div class='banner'>Monitor heartbeat unreadable.</div>"
    if age <= 20:
        return (f"<div class='banner ok'>Monitor running - checked in "
                f"{max(age, 0)}s ago. Decisions are applied within about "
                "a second.</div>")
    return (f"<div class='banner down'>monitor.py was seen {age}s ago but "
            "seems to have stopped. Your clicks are recorded, but nothing "
            "will apply them until monitor.py is running again.</div>")


def render_allowlist(rows):
    if not rows:
        return ""
    head = "".join(f"<th>{h}</th>" for h in
                   ["Added (UTC)", "Name", "Path", ""])
    body_rows = []
    for (row_id, ts, name, path) in rows:
        body_rows.append(
            f"<tr><td>{esc(ts)[:19]}</td><td>{esc(name)}</td>"
            f"<td title='{esc(path)}'>{esc(path) or '(any path)'}</td>"
            f"<td><a class='btn remove' href='/unallow?id={row_id}'>Remove</a></td>"
            f"</tr>"
        )
    return f"<table><tr>{head}</tr>{''.join(body_rows)}</table>"


def render_detail_fields(row):
    """Key/value table for one events row (full values - no ellipsis).
    row is a SELECT * tuple in the events column order."""
    (_id, ts, pid, name, path, cmd, pname, ppid, risk, reason, conf,
     suggested_action, action_taken, confirmation_status, user_decision,
     classified) = row
    badge_cls = risk or "benign"
    conf_txt = f"{conf:.0%}" if conf is not None else "n/a"
    parent_txt = (f"{esc(pname)} (pid {esc(ppid)})"
                  if pname or ppid is not None else "-")
    fields = [
        ("Time (UTC)", esc(ts), False),
        ("Risk",
         f"<span class='badge {badge_cls}'>{esc(risk or '-')}</span>", False),
        ("Confidence", conf_txt, False),
        ("Process", f"{esc(name)} (pid {esc(pid) if pid is not None else '-'})",
         False),
        ("Path", esc(path) or "-", True),
        ("Command line", esc(cmd) or "-", True),
        ("Parent", parent_txt, False),
        ("Reason", esc(reason) or "-", False),
        ("Suggested action", esc(suggested_action) or "-", False),
        ("Action taken", esc(action_taken) or "-", False),
        ("Confirmation status", esc(confirmation_status) or "-", False),
        ("User decision", esc(user_decision) or "-", False),
        ("Classified by Jev", "yes" if classified else "no (skipped)", False),
    ]
    rows_html = []
    for label, value, is_cmd in fields:
        cls = " class='cmd'" if is_cmd else ""
        rows_html.append(f"<tr><th>{label}</th><td{cls}>{value}</td></tr>")
    return f"<table>{''.join(rows_html)}</table>"


def render_usage_summary(rows):
    """rows: list of (date, calls, ok_calls, error_calls, input_tokens,
    output_tokens, avg_latency_ms) grouped by day, most recent first."""
    if not rows:
        return ""

    total_calls = sum(r[1] for r in rows)
    total_errors = sum(r[3] for r in rows)
    total_input_tokens = sum(r[4] or 0 for r in rows)
    # Jev pricing: ~$0.042 per million input tokens, output is free.
    est_cost = (total_input_tokens / 1_000_000) * 0.042

    stats = f"""
    <div class='stats'>
      <div class='stat'><div class='val'>{total_calls}</div><div class='lbl'>Total calls</div></div>
      <div class='stat'><div class='val'>{total_errors}</div><div class='lbl'>Errors</div></div>
      <div class='stat'><div class='val'>{total_input_tokens:,}</div><div class='lbl'>Input tokens</div></div>
      <div class='stat'><div class='val'>${est_cost:.4f}</div><div class='lbl'>Est. cost</div></div>
    </div>
    """

    head = "".join(f"<th>{h}</th>" for h in
                   ["Date (UTC)", "Calls", "OK", "Errors", "Input tokens",
                    "Output tokens", "Avg latency"])
    body_rows = []
    for (day, calls, ok, err, in_tok, out_tok, avg_lat) in rows:
        body_rows.append(
            f"<tr><td>{esc(day)}</td><td>{calls}</td><td>{ok}</td>"
            f"<td>{err}</td><td>{(in_tok or 0):,}</td><td>{(out_tok or 0):,}</td>"
            f"<td>{int(avg_lat) if avg_lat else 0} ms</td></tr>"
        )
    table = f"<table><tr>{head}</tr>{''.join(body_rows)}</table>"
    return stats + table


def render_usage_rows(rows):
    if not rows:
        return ""
    head = "".join(f"<th>{h}</th>" for h in
                   ["Timestamp (UTC)", "Status", "Input tokens",
                    "Output tokens", "Latency", "Error"])
    body_rows = []
    for (_id, ts, event_id, model, status, in_tok, out_tok, lat, error) in rows:
        body_rows.append(
            f"<tr><td>{esc(ts)[:19]}</td><td>{esc(status)}</td>"
            f"<td>{esc(in_tok) if in_tok is not None else '-'}</td>"
            f"<td>{esc(out_tok) if out_tok is not None else '-'}</td>"
            f"<td>{esc(lat)} ms</td><td title='{esc(error)}'>{esc(error) or '-'}</td></tr>"
        )
    return f"<table><tr>{head}</tr>{''.join(body_rows)}</table>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # keep console quiet

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/decide":
            self.handle_decide(parsed)
            return

        if parsed.path == "/allow":
            self.handle_allow(parsed)
            return

        if parsed.path == "/unallow":
            self.handle_unallow(parsed)
            return

        if parsed.path == "/event":
            self.handle_event(parsed)
            return

        if parsed.path not in ("/", "/index.html"):
            self.send_response(404)
            self.end_headers()
            return

        headers = ["Time (UTC)", "Risk", "Name", "Path", "Command line",
                   "Parent", "Reason", "Conf.", "Status"]

        if not os.path.exists(DB_PATH):
            # DB doesn't exist yet - show one actionable note, no sections.
            pending_section = (
                "<div class='empty'>events.db not found yet - start "
                "monitor.py first.</div>"
            )
            allowlist_section = alerts_section = events_section = ""
            usage_section = ""
            heartbeat_ts = None
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
            usage_by_day = conn.execute(
                """SELECT substr(ts, 1, 10) AS day,
                          COUNT(*) AS calls,
                          SUM(CASE WHEN status = 'ok' THEN 1 ELSE 0 END) AS ok_calls,
                          SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_calls,
                          SUM(input_tokens) AS input_tokens,
                          SUM(output_tokens) AS output_tokens,
                          AVG(latency_ms) AS avg_latency_ms
                   FROM jev_usage
                   GROUP BY day
                   ORDER BY day DESC
                   LIMIT 30"""
            ).fetchall()
            usage_recent = conn.execute(
                "SELECT * FROM jev_usage ORDER BY id DESC LIMIT 200"
            ).fetchall()
            allowlist_rows = conn.execute(
                "SELECT id, ts, name, path FROM allowlist ORDER BY id DESC"
            ).fetchall()
            hb_row = conn.execute(
                "SELECT value FROM meta WHERE key = 'last_seen'"
            ).fetchone()
            heartbeat_ts = hb_row[0] if hb_row else None
            conn.close()
            # Each section (heading + content) is dropped entirely when
            # its list is empty - no "No events yet" placeholder.
            pending_section = section("Pending approval",
                                      render_pending(pending))
            allowlist_section = section(
                "Allowlist (trusted - skips Jev classification)",
                render_allowlist(allowlist_rows))
            alerts_section = section(
                "Recent alerts (suspicious / malicious)",
                build_table(alerts, headers))
            events_section = section("All events (last 200)",
                                     build_table(events, headers))
            usage_section = section(
                "Jev usage",
                render_usage_summary(usage_by_day)
                + render_usage_rows(usage_recent))

        page = PAGE_TEMPLATE.format(
            monitor_status=render_monitor_status(heartbeat_ts),
            pending_section=pending_section,
            allowlist_section=allowlist_section,
            alerts_section=alerts_section,
            events_section=events_section,
            usage_section=usage_section,
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
        hb_row = conn.execute(
            "SELECT value FROM meta WHERE key = 'last_seen'"
        ).fetchone()
        conn.close()

        verb = "Block" if decision == "block" else "Dismiss"
        msg = f"{verb} recorded - monitor.py will act on it shortly."
        if not monitor_is_alive(hb_row[0] if hb_row else None):
            msg += (" WARNING: monitor.py hasn't checked in recently, so "
                    "this will not be applied until it is running again.")
        self._send_html(DECISION_PAGE.format(message=msg))

    def handle_event(self, parsed):
        """Detail page for one event: full command line, every logged field,
        plus the Jev API usage rows recorded for this classification."""
        qs = urllib.parse.parse_qs(parsed.query)
        row_id = qs.get("id", [None])[0]

        if not row_id or not row_id.isdigit():
            self._send_html(DECISION_PAGE.format(message="Invalid request."), code=400)
            return

        if not os.path.exists(DB_PATH):
            self._send_html(DECISION_PAGE.format(message="No events database found."), code=404)
            return

        conn = open_db()
        row = conn.execute(
            "SELECT * FROM events WHERE id = ?", (row_id,)
        ).fetchone()
        if row is None:
            conn.close()
            self._send_html(DECISION_PAGE.format(message="Event not found."), code=404)
            return
        usage = conn.execute(
            "SELECT * FROM jev_usage WHERE event_id = ? ORDER BY id",
            (row_id,),
        ).fetchall()
        conn.close()

        name = esc(row[2] or "-")
        if usage:
            usage_html = "<h2>Jev usage for this event</h2>" + \
                render_usage_rows(usage)
        else:
            # Empty list - hide the section entirely (incl. its heading).
            usage_html = ""
        page = DETAIL_PAGE.format(
            event_id=esc(row_id),
            name=name,
            fields_table=render_detail_fields(row),
            usage_section=usage_html,
        )
        self._send_html(page)

    def handle_allow(self, parsed):
        """Trust this event's process name/path: add it to the allowlist so
        monitor.py skips Jev for future launches, and close out the pending
        item (as if Dismissed) so it stops waiting on a decision."""
        qs = urllib.parse.parse_qs(parsed.query)
        row_id = qs.get("id", [None])[0]

        if not row_id or not row_id.isdigit():
            self._send_html(DECISION_PAGE.format(message="Invalid request."), code=400)
            return

        if not os.path.exists(DB_PATH):
            self._send_html(DECISION_PAGE.format(message="No events database found."), code=404)
            return

        conn = open_db()
        row = conn.execute(
            "SELECT name, path, confirmation_status FROM events WHERE id = ?",
            (row_id,),
        ).fetchone()
        if row is None:
            conn.close()
            self._send_html(DECISION_PAGE.format(message="Event not found."), code=404)
            return

        name, path, status = row
        conn.execute(
            "INSERT INTO allowlist (ts, name, path) VALUES (?, ?, ?)",
            (datetime.now(timezone.utc).isoformat(), name, path),
        )
        if status == "pending":
            conn.execute(
                "UPDATE events SET user_decision = 'ignore' "
                "WHERE id = ? AND confirmation_status = 'pending'",
                (row_id,),
            )
        conn.commit()
        conn.close()

        self._send_html(DECISION_PAGE.format(
            message=(f"Allowed {esc(name)} - future launches will skip Jev "
                     "classification.")
        ))

    def handle_unallow(self, parsed):
        """Remove an entry from the allowlist so it gets classified again."""
        qs = urllib.parse.parse_qs(parsed.query)
        row_id = qs.get("id", [None])[0]

        if not row_id or not row_id.isdigit():
            self._send_html(DECISION_PAGE.format(message="Invalid request."), code=400)
            return

        if not os.path.exists(DB_PATH):
            self._send_html(DECISION_PAGE.format(message="No events database found."), code=404)
            return

        conn = open_db()
        conn.execute("DELETE FROM allowlist WHERE id = ?", (row_id,))
        conn.commit()
        conn.close()

        self._send_html(DECISION_PAGE.format(
            message="Removed from the allowlist - it will be classified again."
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
