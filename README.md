# Jev Guard
# Windows Process Monitor (Jev-powered)

Watches for new processes on Windows in real time, sends each one to
TypeSafe's Jev model for a fast risk classification, logs everything to a
local SQLite database, and shows a live dashboard. Log/alert only — it never
kills a process or blocks anything.

## Setup

1. **Run on Windows**, with admin privileges (WMI process-creation events
   require it). This will not run on Linux/macOS.

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Get an API key from https://console.typesafe.ai/ and set it:
   ```
   setx TYPESAFE_API_KEY "your-key-here"
   ```
   (open a new terminal after `setx`, or use `$env:TYPESAFE_API_KEY="..."` for
   the current PowerShell session only)

## Run

Open **one terminal as Administrator** and run:

```
python dashboard.py
```

This automatically starts `monitor.py` in the background. Open
http://127.0.0.1:8787 in a browser — the dashboard live-refreshes every 5s.
Press **Ctrl+C** to stop both the dashboard and the monitor.

### Standalone monitor

If you prefer to run the monitor separately (e.g. without the dashboard):

```
python monitor.py
```

## Dashboard

The dashboard is a single-page interactive UI with:

- **Stats cards** — live counts for total events, alerts, suspicious,
  malicious, benign, and classified processes
- **Risk filter buttons** — click to show only Alerts / Malicious /
  Suspicious / Benign / Errors
- **Search** — live search across process name, path, and command line
- **Dark theme** with color-coded risk badges and hover highlights

Data is served via JSON API endpoints (`/api/stats`, `/api/events`) so
filtering and search are instant client-side.

## Jev Demo

To test the Jev classification API against sample processes without running
the full monitor:

```
python jev_demo.py
```

This sends 8 sample process launches (benign, suspicious, malicious) to the
Jev API and prints a formatted report with risk badges, confidence scores,
reasons, and full JSON responses.

## How it decides what's suspicious

Every new process is described (name, path, command line, parent process)
and sent to Jev with two questions:
- `risk`: benign / suspicious / malicious
- `reason`: normal_operation / unusual_location / spoofed_system_name /
  script_or_interpreter_abuse / persistence_mechanism / unknown

A small allowlist skips classification for common system processes
(`svchost.exe`, `explorer.exe`, etc.) **only** when they're running from
their expected `System32`/`SysWOW64` path — malware commonly spoofs these
exact names from other folders, so name alone never skips a check.

## Tuning it for your environment

This is a starting point, not a finished detector. Things worth adding:

- **Expand the allowlist** with your own known-good software (browsers, IDEs,
  build tools) so you're not paying for/alerting on things you already trust.
- **Add signal beyond process metadata**: digital signature verification
  (`Get-AuthenticodeSignature` via a subprocess call), network connections the
  process opens, or file writes it makes right after launch.
- **Tune the criteria text** in `classify_process()` — Jev's accuracy depends
  on how well the `criteria` descriptions match what you actually want
  flagged. If you're seeing false positives/negatives, adjust the wording
  first before adding more code.
- **Persist a baseline** of what's "normal" for this specific machine (e.g.
  processes seen in the first week) and feed that context into the `state`
  string, so Jev can factor in what's typical here vs. universally suspicious.
- **Rate limiting**: on a busy machine, process creation can spike (e.g.
  during software installs). Consider batching or debouncing if you hit
  API rate limits.

## Cost

Jev is priced at ~$0.04 per million input tokens with free output tokens, and
each classification call here is roughly 100-200 tokens of state, so even a
few thousand process launches a day costs a fraction of a cent.