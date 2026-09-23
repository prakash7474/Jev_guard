# Windows Process Monitor (Jev-powered)

Watches for new processes on Windows in real time, sends each one to
TypeSafe's Jev model for a fast risk classification, logs everything to a
local SQLite database, and shows a live dashboard. By default it only logs
and alerts — killing a process is always explicit: either `AUTO_BLOCK=1`
for very-high-confidence verdicts, or you clicking **Block** in the
dashboard.

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

   Alternatively, put the key in a `.env` file in this folder
   (`TYPESAFE_API_KEY=your-key-here`) — `monitor.py` and `jev_demo.py` load it
   automatically at startup, so no `setx` step is needed.

## Run

Open two terminals (both as Administrator for the monitor):

```
python monitor.py
```
```
python dashboard.py
```

Then open http://127.0.0.1:8787 in a browser. It auto-refreshes every 5s.

An `events.db` created by an older version of the project is migrated
automatically the first time the monitor or dashboard opens it — new
columns are added in place and existing history is kept.

## Tests

`test_monitor.py` covers the whole auto-block path — the confidence math,
the protected list, and real WMI termination. Run it either way:

```
python test_monitor.py
```
```
pytest test_monitor.py
```

15 tests, about 15 seconds. What it proves:

- **≥ 90% + `AUTO_BLOCK=1` really kills**: `resolve_action()` — the exact
  function `monitor.main()` runs — terminates a live process at exactly
  90% and at 91%, and leaves an 89% one alone as `pending`.
- **Protected names are never killed**, even at 99% confidence.
- **End-to-end**: the real `monitor.main()` watch loop runs in a driver
  subprocess (auto-block on, isolated temp database, Jev stubbed to return
  malicious @ 95% for one uniquely marked process) and must classify and
  terminate that process on its own, logging `action_taken='blocked'`.

The tests only ever terminate sleeping Python subprocesses they spawn
themselves, write end-to-end data to a temporary database (your real
`events.db` is untouched), and patch `AUTO_BLOCK` only in-process — your
environment is not modified. Expect a single desktop toast during the
end-to-end run: that's the victim being alerted.

## How blocking works

Every new process gets three answers from Jev: `risk`, `reason`, and a
suggested `action` (allow / monitor / block). What happens next depends on
confidence:

- **Very high confidence** (≥90%) `malicious` + `block`, **and**
  `AUTO_BLOCK=1` is set: terminated immediately, no confirmation needed.
- **Anything else Jev suggests blocking**: queued as "pending" — you get a
  toast notification and an entry in the dashboard's **Pending approval**
  section with **Block** / **Dismiss** buttons. Clicking one writes your
  decision to the database; `monitor.py` picks it up (checked roughly once
  a second) and either terminates the process or marks it dismissed.
- **Protected processes** (`NEVER_BLOCK_NAMES` — svchost, lsass, explorer,
  etc.) are never auto-blocked no matter what Jev says or how confident it
  is. If Jev flags one as malicious it still goes to pending approval, but
  you'd be blocking it yourself, deliberately, with full knowledge of the
  risk.
- **Toast threshold**: desktop notifications only fire when the result is
  `suspicious`/`malicious` **and** confidence is above 60%
  (`ALERT_CONFIDENCE_THRESHOLD` in `monitor.py`). Anything below that is
  still logged to the database and shown in the dashboard, just without a
  pop-up.

`AUTO_BLOCK` is off by default — with it off, *everything* Jev suggests
blocking goes to pending approval, so nothing gets killed without you
clicking a button. Turn it on with:
```
setx AUTO_BLOCK "1"
```

## How it decides what's suspicious

Every new process is described (name, path, command line, parent process)
and sent to Jev with three questions:
- `risk`: benign / suspicious / malicious
- `reason`: normal_operation / unusual_location / spoofed_system_name /
  script_or_interpreter_abuse / persistence_mechanism / unknown
- `action`: allow / monitor / block (drives the blocking behavior above)

A small allowlist skips classification for common system processes
(`svchost.exe`, `explorer.exe`, etc.) **only** when they're running from
their expected `System32`/`SysWOW64` path — malware commonly spoofs these
exact names from other folders, so name alone never skips a check.

## Tuning it for your environment

This is a starting point, not a finished detector. Things worth adding:

- **Windows toast action buttons**: right now the toast just opens the
  dashboard on click; `win10toast_click` doesn't support multiple buttons
  with separate callbacks. For true in-toast Block/Dismiss buttons you'd
  need a Windows Runtime toast library (e.g. `windows-toasts`) with
  `ToastActivatedEventArgs`. The `WNDPROC ... TypeError` noise it prints on
  newer Python/Windows comes from the same library's message pump —
  harmless, and another reason to switch.

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
