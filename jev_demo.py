"""
Jev Operations Demo — prints all Jev classification results.

Runs a set of sample process launches through the Jev API and prints a
formatted report showing every field the model returns.

Requires: TYPESAFE_API_KEY environment variable (or set in .env).
"""

import json
import os
import sys
import time
from datetime import datetime, timezone

from dotenv import load_dotenv
import requests

load_dotenv()

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

TYPESAFE_API_KEY = os.environ.get("TYPESAFE_API_KEY")
TYPESAFE_API_URL = "https://api.typesafe.ai/v1/systemone"
JEV_MODEL = "jev-latest"

# Sample processes to classify — covers benign, suspicious, and malicious
SAMPLE_PROCESSES = [
    {
        "label": "Normal system process",
        "name": "svchost.exe",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "command_line": "svchost.exe -k netsvcs",
        "parent_name": "services.exe",
        "parent_pid": 500,
    },
    {
        "label": "Normal user app",
        "name": "notepad.exe",
        "path": "C:\\Program Files\\Notepad++\\notepad++.exe",
        "command_line": "notepad++.exe C:\\Users\\admin\\notes.txt",
        "parent_name": "explorer.exe",
        "parent_pid": 3000,
    },
    {
        "label": "PowerShell with encoded command",
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -enc aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q=",
        "parent_name": "cmd.exe",
        "parent_pid": 4500,
    },
    {
        "label": "System name in wrong path",
        "name": "svchost.exe",
        "path": "C:\\Users\\Temp\\svchost.exe",
        "command_line": "svchost.exe --hidden --port 4444",
        "parent_name": "wscript.exe",
        "parent_pid": 6000,
    },
    {
        "label": "Script interpreter from temp",
        "name": "wscript.exe",
        "path": "C:\\Users\\Public\\wscript.exe",
        "command_line": "wscript.exe C:\\Windows\\Temp\\payload.vbs",
        "parent_name": "mshta.exe",
        "parent_pid": 7000,
    },
    {
        "label": "Suspicious network tool",
        "name": "net.exe",
        "path": "C:\\Windows\\System32\\net.exe",
        "command_line": "net.exe user admin P@ssw0rd /add",
        "parent_name": "cmd.exe",
        "parent_pid": 8000,
    },
    {
        "label": "Encoded Office macro",
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -nop -w hidden -enc SQBmACgAJABlAG4AdgA6AEMAbwBuAHIAbwBsAFAAcgBvAHgA",
        "parent_name": "WINWORD.EXE",
        "parent_pid": 9000,
    },
    {
        "label": "Normal browser",
        "name": "chrome.exe",
        "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "command_line": "chrome.exe --type=renderer --field-trial-handle=1",
        "parent_name": "chrome.exe",
        "parent_pid": 10000,
    },
]


# --------------------------------------------------------------------------
# Jev API
# --------------------------------------------------------------------------

def classify(info):
    """Send a process to Jev for risk classification.
    Returns the full raw API response dict."""
    state = (
        f"A new process started on a Windows machine.\n"
        f"Process name: {info['name']}\n"
        f"Executable path: {info['path']}\n"
        f"Command line: {info['command_line']}\n"
        f"Parent process: {info['parent_name']} (pid {info['parent_pid']})\n"
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
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------
# Display helpers
# --------------------------------------------------------------------------

RISK_COLORS = {
    "benign":    "\033[92m",   # green
    "suspicious": "\033[93m",  # yellow
    "malicious": "\033[91m",   # red
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def risk_badge(risk):
    color = RISK_COLORS.get(risk, "")
    return f"{color}{risk.upper():>10}{RESET}"


def print_section(title):
    width = 70
    print()
    print(f"{BOLD}{'=' * width}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{'=' * width}")


def print_process(info, result, elapsed):
    risk = result["answers"]["risk"]["choice"]
    reason = result["answers"]["reason"]["choice"]
    conf = result["answers"]["risk"].get("confidence")
    conf_txt = f"{conf:.0%}" if conf is not None else "n/a"

    print(f"\n  {BOLD}{info['label']}{RESET}")
    print(f"  {DIM}{'-' * 50}{RESET}")
    print(f"  Process     : {info['name']}")
    print(f"  Path        : {info['path']}")
    print(f"  Command     : {info['command_line']}")
    print(f"  Parent      : {info['parent_name']} (pid {info['parent_pid']})")
    print(f"  {DIM}--- Jev Response ---{RESET}")
    print(f"  Risk        : {risk_badge(risk)}   confidence: {conf_txt}")
    print(f"  Reason      : {reason}")
    print(f"  Time        : {elapsed:.2f}s")


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    if not TYPESAFE_API_KEY:
        print("ERROR: set the TYPESAFE_API_KEY environment variable first.")
        sys.exit(1)

    print_section("Jev Process Classification Demo")
    print(f"  Model      : {JEV_MODEL}")
    print(f"  API        : {TYPESAFE_API_URL}")
    print(f"  Processes  : {len(SAMPLE_PROCESSES)}")

    results = []
    for i, proc in enumerate(SAMPLE_PROCESSES, 1):
        print(f"\n  [{i}/{len(SAMPLE_PROCESSES)}] Classifying: {proc['label']}...")
        t0 = time.time()
        try:
            resp = classify(proc)
            elapsed = time.time() - t0
            print_process(proc, resp, elapsed)
            results.append({"info": proc, "response": resp, "elapsed": elapsed, "error": None})
        except Exception as e:
            elapsed = time.time() - t0
            print(f"  \033[91mERROR: {e}\033[0m ({elapsed:.2f}s)")
            results.append({"info": proc, "response": None, "elapsed": elapsed, "error": str(e)})

    # Summary table
    print_section("Summary")

    header = f"  {'#':>2}  {'Process':<25} {'Risk':>10}  {'Reason':<30} {'Conf':>5}  {'Time':>5}"
    print(f"{BOLD}{header}{RESET}")
    print(f"  {'-' * 85}")

    for i, r in enumerate(results, 1):
        proc = r["info"]
        if r["error"]:
            print(f"  {i:>2}  {proc['name']:<25} {'ERROR':>10}  {r['error'][:30]:<30} {'':>5}  {r['elapsed']:.1f}s")
        else:
            ans = r["response"]["answers"]
            risk = ans["risk"]["choice"]
            reason = ans["reason"]["choice"]
            conf = ans["risk"].get("confidence")
            conf_txt = f"{conf:.0%}" if conf is not None else "-"
            print(f"  {i:>2}  {proc['name']:<25} {risk_badge(risk)}  {reason:<30} {conf_txt:>5}  {r['elapsed']:.1f}s")

    # Dump full JSON responses
    print_section("Full API Responses (JSON)")

    for i, r in enumerate(results, 1):
        proc = r["info"]
        print(f"\n  --- #{i}: {proc['label']} ---")
        if r["error"]:
            print(f"  Error: {r['error']}")
        else:
            print(json.dumps(r["response"], indent=4))

    print(f"\n{'=' * 70}")
    print(f"  Done. {len(results)} processes classified.\n")


if __name__ == "__main__":
    main()
