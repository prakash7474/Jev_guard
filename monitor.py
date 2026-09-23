"""
Windows process monitor with Jev-based classification.

Watches for new process creation in real time (via WMI), builds a short
description of each process, and asks TypeSafe's Jev model whether it looks
suspicious and what to do about it. Every event is logged to a local SQLitedatabase; suspicious/malicious results where Jev's confidence is above 60%
also trigger a desktop toast notification (lower-confidence flags are still
logged, just without a pop-up - see ALERT_CONFIDENCE_THRESHOLD).

By default this is log/alert-only. Set AUTO_BLOCK=1 to let it terminate
processes Jev rates "malicious" with very high confidence automatically;
anything below that threshold (or on the protected-process list) is queued
as a pending item you approve or dismiss from the dashboard instead. See
NEVER_BLOCK_NAMES and AUTO_BLOCK_CONFIDENCE_THRESHOLD below.
Run dashboard.py alongside this to view alerts and approve/dismiss actions.

Requires Windows + admin privileges (WMI process creation/termination needs it).
"""

import os
import sqlite3
import sys
import time
import traceback
from datetime import datetime, timezone

import requests
import wmi
from dotenv import load_dotenv

# Pick up TYPESAFE_API_KEY (and anything else) from the .env file next to this
# script, so a fresh terminal doesn't need setx/$env: first. Existing process
# environment variables are never overwritten by load_dotenv().
load_dotenv()

try:
    from win10toast_click import ToastNotifier
    _toaster = ToastNotifier()
except Exception:
    _toaster = None

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

TYPESAFE_API_KEY = os.environ.get("TYPESAFE_API_KEY")
TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "events.db")

# Auto-blocking is OFF by default. Set the AUTO_BLOCK env var to "1" to let
# the monitor actually terminate processes automatically for very-high
# confidence cases - do this only after you trust the classifications on
# your machine. Even with it off, "block" suggestions still get queued for
# you to approve from the dashboard.
AUTO_BLOCK = os.environ.get("AUTO_BLOCK", "0") == "1"

# >= this confidence AND AUTO_BLOCK=1: terminate immediately, no confirmation.
AUTO_BLOCK_CONFIDENCE_THRESHOLD = 0.90

# Below that (but Jev still suggested "block"): queued as "pending" for you
# to approve or dismiss from the dashboard, instead of acting automatically.

# Desktop toast notifications only fire for suspicious/malicious results
# whose confidence clears this bar (strictly greater than 70%). Uncertain
# flags are still written to events.db and shown in the dashboard - they
# just don't pop a notification.
ALERT_CONFIDENCE_THRESHOLD = 0.70

# Hard safety list: these are NEVER terminated automatically, no matter what
# Jev says. Killing any of these can crash or destabilize Windows.
NEVER_BLOCK_NAMES = {
    "system", "system idle process", "svchost.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
    "smss.exe", "dwm.exe", "explorer.exe", "registry",
}

# Processes we treat as routine and don't bother classifying, UNLESS their
# executable path looks wrong (see is_known_safe below). Malware frequently
# spoofs these exact names, so the name alone is never enough to trust it.
KNOWN_SAFE_NAMES = {
    "svchost.exe", "explorer.exe", "lsass.exe", "winlogon.exe",
    "services.exe", "csrss.exe", "wininit.exe", "smss.exe",
    "dwm.exe", "taskhostw.exe", "conhost.exe", "RuntimeBroker.exe",
    "SearchIndexer.exe", "spoolsv.exe",
}
EXPECTED_SYSTEM_DIRS = (r"c:\windows\system32", r"c:\windows\syswow64")

# Locations that are common for both legitimate installers and malware
# droppers - these always get classified rather than auto-skipped.
WATCH_CLOSELY_DIRS = (
    r"\appdata\local\temp", r"\appdata\roaming", r"\downloads",
    r"\public\\", r"\programdata",
)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

# Columns added after the first release. A database created by an older
# version doesn't have them, and CREATE TABLE IF NOT EXISTS silently leaves
# that old schema in place - so init_db() ALTERs them in (non-destructive,
# existing rows are kept). Without this, monitor.py and dashboard.py both
# crash querying confirmation_status against an existing events.db.
ADDED_COLUMNS = (
    ("suggested_action", "TEXT"),
    ("action_taken", "TEXT"),
    ("confirmation_status", "TEXT DEFAULT 'none'"),
    ("user_decision", "TEXT"),
)


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            pid INTEGER,
            name TEXT,
            path TEXT,
            command_line TEXT,
            parent_name TEXT,
            parent_pid INTEGER,
            risk TEXT,
            reason TEXT,
            confidence REAL,
            suggested_action TEXT,
            action_taken TEXT,
            confirmation_status TEXT DEFAULT 'none',
            user_decision TEXT,
            classified INTEGER DEFAULT 0
        )
    """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(events)")}
    for col, decl in ADDED_COLUMNS:
        if col not in existing:
            conn.execute(f"ALTER TABLE events ADD COLUMN {col} {decl}")
    conn.commit()
    return conn


def log_event(conn, info, risk=None, reason=None, confidence=None,
               suggested_action=None, action_taken=None,
               confirmation_status="none", classified=0):
    cur = conn.execute(
        """INSERT INTO events
           (ts, pid, name, path, command_line, parent_name, parent_pid,
            risk, reason, confidence, suggested_action, action_taken,
            confirmation_status, classified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            info["pid"], info["name"], info["path"], info["command_line"],
            info["parent_name"], info["parent_pid"],
            risk, reason, confidence, suggested_action, action_taken,
            confirmation_status, classified,
        ),
    )
    conn.commit()
    return cur.lastrowid


def poll_user_decisions(conn, wmi_conn):
    """Check for pending items the user approved/dismissed from the
    dashboard, and act on them: block on 'block', just close out on 'ignore'."""
    rows = conn.execute(
        """SELECT id, pid, name, path, command_line, parent_name, parent_pid,
                  user_decision
           FROM events
           WHERE confirmation_status = 'pending' AND user_decision IS NOT NULL"""
    ).fetchall()

    for (row_id, pid, name, path, cmd, pname, ppid, decision) in rows:
        info = {"pid": pid, "name": name, "path": path, "command_line": cmd,
                "parent_name": pname, "parent_pid": ppid}
        if decision == "block":
            success, detail = block_process(wmi_conn, info)
            action_taken = "blocked_by_user" if success else f"block_failed:{detail}"
            print(f"[user action] {name} (pid {pid}): {action_taken}")
        else:
            action_taken = "ignored_by_user"

        conn.execute(
            "UPDATE events SET action_taken = ?, confirmation_status = 'resolved' "
            "WHERE id = ?",
            (action_taken, row_id),
        )
        conn.commit()


# --------------------------------------------------------------------------
# Process info collection
# --------------------------------------------------------------------------

def get_process_info(wmi_conn, proc):
    pid = int(proc.ProcessId)
    name = proc.Name or ""
    path = proc.ExecutablePath or ""
    cmdline = proc.CommandLine or ""
    parent_pid = int(proc.ParentProcessId) if proc.ParentProcessId else None

    parent_name = ""
    if parent_pid:
        try:
            parent = wmi_conn.Win32_Process(ProcessId=parent_pid)
            if parent:
                parent_name = parent[0].Name or ""
        except Exception:
            pass

    return {
        "pid": pid, "name": name, "path": path, "command_line": cmdline,
        "parent_pid": parent_pid, "parent_name": parent_name,
    }


def is_known_safe(info):
    """Cheap pre-filter so we don't spend a Jev call on every svchost.exe.
    Only skips classification when name AND path both look legitimate."""
    name = (info["name"] or "").strip()
    path = (info["path"] or "").lower().strip()

    if name not in KNOWN_SAFE_NAMES:
        return False
    if not path:
        # No path info available - can't verify, so don't skip.
        return False
    if not path.startswith(EXPECTED_SYSTEM_DIRS):
        return False
    if any(d in path for d in WATCH_CLOSELY_DIRS):
        return False
    return True


# --------------------------------------------------------------------------
# Jev classification
# --------------------------------------------------------------------------

def classify_process(info):
    """Ask Jev whether this process launch looks suspicious and what to do
    about it. Returns (risk, reason, suggested_action, confidence)."""
    if not TYPESAFE_API_KEY:
        raise RuntimeError("TYPESAFE_API_KEY environment variable is not set")

    state = (
        f"A new process started on a Windows machine.\n"
        f"Process name: {info['name']}\n"
        f"Executable path: {info['path'] or 'unknown'}\n"
        f"Command line: {info['command_line'] or 'unknown'}\n"
        f"Parent process: {info['parent_name'] or 'unknown'} "
        f"(pid {info['parent_pid']})\n"
    )

    payload = {
        "model": JEV_MODEL,
        "state": state,
        "questions": {
            "risk": {
                "type": "choice",
                "instructions": "How risky does this process launch look?",
                "criteria": {
                    "benign": "Normal, expected software or system behavior",
                    "suspicious": (
                        "Unusual but not clearly malicious - e.g. a script "
                        "interpreter launched from a temp folder, an "
                        "uncommon parent/child pairing, odd command-line flags"
                    ),
                    "malicious": (
                        "Strong indicators of malware - e.g. a system "
                        "process name running from the wrong path, "
                        "obfuscated/encoded command-line arguments, known "
                        "living-off-the-land abuse patterns"
                    ),
                },
            },
            "reason": {
                "type": "choice",
                "instructions": "What is the primary basis for that risk rating?",
                "criteria": {
                    "normal_operation": "Fits expected system/software behavior",
                    "unusual_location": "Running from an unexpected directory",
                    "spoofed_system_name": "Common system name in the wrong path",
                    "script_or_interpreter_abuse": (
                        "PowerShell/cmd/wscript etc. with suspicious arguments"
                    ),
                    "persistence_mechanism": (
                        "Looks like it is trying to survive reboot/re-launch"
                    ),
                    "unknown": "Not enough information to tell",
                },
            },
            "action": {
                "type": "choice",
                "instructions": (
                    "Given the risk and reason, what should happen to this "
                    "process?"
                ),
                "criteria": {
                    "allow": "Let it run - normal or low-risk behavior",
                    "monitor": (
                        "Let it run but keep watching - suspicious but not "
                        "clearly harmful, or not worth disrupting yet"
                    ),
                    "block": (
                        "Terminate it now - clear, high-confidence signs of "
                        "malware or active harm to the system"
                    ),
                },
            },
        },
    }

    resp = requests.post(
        TYPESAFE_API_URL,
        headers={
            "Authorization": f"Bearer {TYPESAFE_API_KEY}",
            "Content-Type": "application/json",
        },
        json=payload,
        timeout=5,
    )
    resp.raise_for_status()
    data = resp.json()

    risk_ans = data["answers"]["risk"]
    reason_ans = data["answers"]["reason"]
    action_ans = data["answers"]["action"]
    return (
        risk_ans["choice"],
        reason_ans["choice"],
        action_ans["choice"],
        risk_ans.get("confidence"),
    )


# --------------------------------------------------------------------------
# Alerting + blocking
# --------------------------------------------------------------------------

def alert(info, risk, reason, suggested_action, confidence, action_taken,
          confirmation_status):
    title = f"{risk.upper()} process: {info['name']}"
    conf_txt = f"{confidence:.0%}" if confidence is not None else "n/a"
    if action_taken == "blocked":
        status = f"BLOCKED automatically (pid {info['pid']} terminated)"
    elif confirmation_status == "pending":
        status = "AWAITING YOUR APPROVAL - open the dashboard to block or dismiss"
    else:
        status = f"suggested action: {suggested_action}"
    msg = (
        f"{info['path'] or info['name']}\n"
        f"reason: {reason}  confidence: {conf_txt}\n"
        f"parent: {info['parent_name']} (pid {info['parent_pid']})\n"
        f"{status}"
    )
    print(f"[ALERT] {title}\n        {msg}")
    if _toaster is not None:
        try:
            if confirmation_status == "pending":
                _toaster.show_toast(
                    title, msg, duration=10, threaded=True,
                    callback_on_click=lambda: __import__("webbrowser").open(
                        "http://127.0.0.1:8787/"
                    ),
                )
            else:
                _toaster.show_toast(title, msg, duration=8, threaded=True)
        except Exception:
            pass


def should_notify(risk, confidence):
    """Desktop toast only for suspicious/malicious results Jev is more than
    ALERT_CONFIDENCE_THRESHOLD sure of. Everything else stays log-only."""
    if risk not in ("suspicious", "malicious"):
        return False
    if confidence is None:
        return False
    return confidence > ALERT_CONFIDENCE_THRESHOLD


def decide_disposition(risk, suggested_action, confidence):
    """Returns one of: 'auto_block', 'needs_confirmation', 'none'."""
    if risk != "malicious" or suggested_action != "block":
        return "none"
    if confidence is None:
        return "needs_confirmation"
    if AUTO_BLOCK and confidence >= AUTO_BLOCK_CONFIDENCE_THRESHOLD:
        return "auto_block"
    return "needs_confirmation"


def is_protected(info):
    name = (info["name"] or "").strip().lower()
    if name in NEVER_BLOCK_NAMES:
        return True
    if not info["pid"] or info["pid"] <= 4:
        return True
    return False


def block_process(wmi_conn, info):
    """Terminate a process by PID via WMI. Returns True on success."""
    try:
        procs = wmi_conn.Win32_Process(ProcessId=info["pid"])
        if not procs:
            return False, "process_not_found"
        result = procs[0].Terminate()
        # Win32_Process.Terminate() returns 0 on success.
        if isinstance(result, tuple):
            result = result[0]
        return (result == 0), f"terminate_return_code_{result}"
    except Exception as e:
        return False, f"terminate_error: {e}"


def resolve_action(wmi_conn, info, risk, suggested_action, confidence):
    """Apply the auto-block decision to a classified process and return
    (action_taken, confirmation_status) for the event log.

    risk=malicious + action=block with confidence >=
    AUTO_BLOCK_CONFIDENCE_THRESHOLD (and AUTO_BLOCK=1) and the process not
    on the protected list -> terminate it now ("blocked"). Anything else
    Jev wants blocked -> "pending", queued for dashboard approval.
    """
    disposition = decide_disposition(risk, suggested_action, confidence)
    action_taken = None
    confirmation_status = "none"

    if disposition == "auto_block" and not is_protected(info):
        success, detail = block_process(wmi_conn, info)
        action_taken = "blocked" if success else f"block_failed:{detail}"
        print(f"[action] {info['name']} (pid {info['pid']}): {action_taken}")
    elif disposition in ("auto_block", "needs_confirmation"):
        # Either confidence wasn't high enough for auto-block, or the
        # process is on the protected list and must never be
        # auto-killed - either way, queue it for your approval.
        confirmation_status = "pending"

    return action_taken, confirmation_status


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------

def main():
    if not TYPESAFE_API_KEY:
        print("ERROR: set the TYPESAFE_API_KEY environment variable first.")
        sys.exit(1)

    print("Connecting to WMI...")
    c = wmi.WMI()
    conn = init_db()
    print(f"Logging to {DB_PATH}")
    print(f"AUTO_BLOCK is {'ON' if AUTO_BLOCK else 'off'} "
          f"(auto-block confidence threshold: {AUTO_BLOCK_CONFIDENCE_THRESHOLD:.0%}; "
          f"anything below that gets queued for your approval in the dashboard)")
    print("Watching for new processes. Ctrl+C to stop.\n")

    watcher = c.Win32_Process.watch_for("creation")

    while True:
        try:
            try:
                new_proc = watcher(timeout_ms=1000)
            except wmi.x_wmi_timed_out:
                # No new process in the last second - use the idle moment to
                # check whether you've approved/dismissed anything pending.
                poll_user_decisions(conn, c)
                continue

            info = get_process_info(c, new_proc)

            if is_known_safe(info):
                log_event(conn, info, risk="benign", reason="known_safe_skip",
                           classified=0)
                continue

            try:
                risk, reason, suggested_action, confidence = classify_process(info)
            except Exception as e:
                print(f"[classify error] {info['name']} (pid {info['pid']}): {e}")
                log_event(conn, info, risk="error", reason=str(e)[:200],
                           classified=0)
                continue

            # Decide + (maybe) terminate - one function, also unit-tested.
            action_taken, confirmation_status = resolve_action(
                c, info, risk, suggested_action, confidence)

            row_id = log_event(
                conn, info, risk=risk, reason=reason, confidence=confidence,
                suggested_action=suggested_action, action_taken=action_taken,
                confirmation_status=confirmation_status, classified=1,
            )

            if should_notify(risk, confidence):
                alert(info, risk, reason, suggested_action, confidence,
                      action_taken, confirmation_status)

        except KeyboardInterrupt:
            print("\nStopping.")
            break
        except Exception:
            # Keep the watcher alive through transient WMI hiccups.
            traceback.print_exc()
            time.sleep(1)


if __name__ == "__main__":
    main()
