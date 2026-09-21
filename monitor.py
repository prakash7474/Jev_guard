"""
Windows process monitor with Jev-based classification.

Watches for new process creation in real time (via WMI), builds a short
description of each process, and asks TypeSafe's Jev model whether it looks
suspicious. Every event is logged to a local SQLite database; anything Jev
flags as suspicious/malicious also triggers a desktop toast notification.

This is a log/alert-only tool: it never kills processes or blocks anything.
Run dashboard.py alongside this to view alerts in a browser.

Requires Windows + admin privileges (WMI process-creation events need it).
"""

import os
import sqlite3
import sys
import time
import traceback
from datetime import datetime, timezone

from dotenv import load_dotenv
import requests
import wmi

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
    "\\public\\", r"\programdata",
)


# --------------------------------------------------------------------------
# Storage
# --------------------------------------------------------------------------

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
            classified INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    return conn


def log_event(conn, info, risk=None, reason=None, confidence=None, classified=0):
    conn.execute(
        """INSERT INTO events
           (ts, pid, name, path, command_line, parent_name, parent_pid,
            risk, reason, confidence, classified)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            datetime.now(timezone.utc).isoformat(),
            info["pid"], info["name"], info["path"], info["command_line"],
            info["parent_name"], info["parent_pid"],
            risk, reason, confidence, classified,
        ),
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
    """Ask Jev whether this process launch looks suspicious.
    Returns (risk, reason, confidence) or (None, None, None) on failure."""
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
    return risk_ans["choice"], reason_ans["choice"], risk_ans.get("confidence")


# --------------------------------------------------------------------------
# Alerting
# --------------------------------------------------------------------------

def alert(info, risk, reason, confidence):
    title = f"{risk.upper()} process: {info['name']}"
    conf_txt = f"{confidence:.0%}" if confidence is not None else "n/a"
    msg = (
        f"{info['path'] or info['name']}\n"
        f"reason: {reason}  confidence: {conf_txt}\n"
        f"parent: {info['parent_name']} (pid {info['parent_pid']})"
    )
    print(f"[ALERT] {title}\n        {msg}")
    if _toaster is not None:
        try:
            _toaster.show_toast(title, msg, duration=8, threaded=True)
        except Exception:
            pass


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
    print("Watching for new processes. Ctrl+C to stop.\n")

    watcher = c.Win32_Process.watch_for("creation")

    while True:
        try:
            new_proc = watcher()
            info = get_process_info(c, new_proc)

            if is_known_safe(info):
                log_event(conn, info, risk="benign", reason="known_safe_skip",
                           confidence=None, classified=0)
                continue

            try:
                risk, reason, confidence = classify_process(info)
            except Exception as e:
                print(f"[classify error] {info['name']} (pid {info['pid']}): {e}")
                log_event(conn, info, risk="error", reason=str(e)[:200],
                           confidence=None, classified=0)
                continue

            log_event(conn, info, risk=risk, reason=reason,
                      confidence=confidence, classified=1)

            if risk in ("suspicious", "malicious"):
                alert(info, risk, reason, confidence)

        except KeyboardInterrupt:
            print("\nStopping.")
            break
        except Exception:
            # Keep the watcher alive through transient WMI hiccups.
            traceback.print_exc()
            time.sleep(1)


if __name__ == "__main__":
    main()
