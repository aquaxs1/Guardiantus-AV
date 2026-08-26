<div align="center">

<img src="guardiantus/ui/static/img/logo.svg" width="110" alt="Guardiantus AV">

# Guardiantus AV

**Real-time protection, deep scanning, quarantine and update management — in one dependency-free package.**

[![Python](https://img.shields.io/badge/python-3.9%2B-black)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-black)](LICENSE)
[![Tests](https://github.com/aquaxs1/Guardiantus-AV/actions/workflows/ci.yml/badge.svg)](https://github.com/aquaxs1/Guardiantus-AV/actions/workflows/ci.yml)

</div>

---

## What it is

Guardiantus AV is a complete endpoint-protection suite: a multi-layer detection
engine, on-access real-time protection, a restorable quarantine vault, a
third-party patch checker, a scheduler, a full CLI, and a local web dashboard
in white / black / grey.

The engine, the CLI and the dashboard run on **the Python standard library
alone**. Optional packages make it faster and stronger, and it degrades
gracefully without them — nothing silently stops working.

## Features

**Detection engine**
- **Hash signatures** — MD5 / SHA-1 / SHA-256 of known-bad files. Zero false positives.
- **Pattern signatures** — byte fragments that survive repacking and cover whole families.
- **YARA rules** — 13 bundled rules for reverse shells, ransomware, stealers, injectors, miners and macro droppers. Uses `yara-python` when installed, and a built-in interpreter when it is not.
- **Heuristics** — ransom-note text, double extensions, right-to-left-override filenames, executables masquerading as documents, reverse shells, encoded PowerShell and shadow-copy deletion. Entropy, packing, embedded base64 and process-injection API chains count as corroboration only: an alarm always needs at least one construct specific to malware, so a log file full of URLs or a Windows API-set DLL cannot add up to a detection on its own.
- **Archive inspection** — ZIP members are scanned in memory, with zip-bomb and path-traversal detection.

**Protection**
- **Real-time protection** — event-driven via `watchdog` (inotify / FSEvents / Win32), with a stdlib polling fallback so it works on a bare Python install.
- **Quarantine vault** — confirmed threats are moved out of reach and stored inert; every entry restores byte-for-byte, and restoring also tells the engine to leave that file alone from then on. Heuristic suspicions are reported rather than moved: the detection panel then offers to quarantine or allow them, and everything you have allowed is listed under Settings so you can put a file back in scope.
- **Scan types** — quick (high-risk locations), full (every mounted drive), custom paths, and single files. Pausable, resumable, cancellable, with live progress.

**Maintenance**
- **Program updates** — finds outdated software across apt, dnf, pacman, flatpak, snap, Homebrew, winget, Chocolatey and pip, and can apply updates one at a time. Unpatched software is how most machines get compromised.
- **Signature updates** — verified against a manifest digest and validated before install, so a bad download can never corrupt a working database.
- **Scheduler** — cron-style recurring scans and update checks.

**Interfaces**
- **Local dashboard** — a monochrome web UI with light and dark themes, guarded by a per-run session token, Host/Origin validation and a strict CSP.
- **CLI** — every feature is scriptable, with `--json` on every command.

## Install

```bash
git clone https://github.com/aquaxs1/Guardiantus-AV.git
cd Guardiantus-AV
pip install -e .
```

Recommended extras:

```bash
pip install -e ".[full]"     # watchdog + yara-python
pip install -e ".[realtime]" # event-driven real-time protection only
pip install -e ".[yara]"     # native YARA only
```

Or run it straight from the checkout with no install at all:

```bash
python -m guardiantus status
```

## Quick start

```bash
guardiantus status              # protection overview
guardiantus quick               # scan the high-risk locations
guardiantus protect start       # turn on real-time protection
guardiantus dashboard           # open the web UI
```

## The dashboard

```bash
guardiantus dashboard
```

It binds to `127.0.0.1:8787`, prints a URL containing a fresh session token,
and opens your browser. Eight sections: Dashboard, Scan, Protection,
Quarantine, Updates, Schedule, Activity and Settings.

Change host and port with `--host` / `--port`, or persist them:

```bash
guardiantus config set service.port 9000
```

## CLI reference

| Command | What it does |
|---|---|
| `guardiantus status` | Protection status and recommended actions |
| `guardiantus quick` | Scan Downloads, Desktop, Documents, temp and autostart |
| `guardiantus full` | Scan every mounted drive |
| `guardiantus scan PATH...` | Scan specific files or folders |
| `guardiantus check FILE...` | Inspect single files without recording a scan session |
| `guardiantus protect start\|stop\|status` | Control real-time protection |
| `guardiantus quarantine list\|restore\|delete\|empty` | Manage the vault |
| `guardiantus allow list\|remove` | See or clear the files you have vouched for |
| `guardiantus update signatures` | Refresh the signature database |
| `guardiantus update programs` | Find outdated software |
| `guardiantus schedule list\|enable\|disable\|run` | Manage scheduled tasks |
| `guardiantus events` | Read the activity log |
| `guardiantus config show\|set\|path` | Read and write configuration |
| `guardiantus dashboard` | Run the web dashboard |
| `guardiantus info` | Engine and platform details |

Scanning commands exit `0` when clean, `1` when a threat was found and `2` on
error — so they drop straight into CI and cron:

```bash
guardiantus --json scan ./upload | jq '.threats[].name'
```

Scans quarantine what a signature or a YARA rule identifies. Heuristic
suspicions are reported and left where they are, since a heuristic is an
inference rather than an identification. Override either behaviour per run with
`--no-quarantine` (report everything) or globally:

```bash
guardiantus config set scanning.auto_quarantine false        # never move anything
guardiantus config set scanning.quarantine_suspicious true   # move suspicions too
```

Guardiantus never scans its own installation directory, its data directory or
the vault: the signature database is a list of malware strings and the YARA
rules spell out the patterns they hunt for, so scanning them would "detect" the
scanner every time.

## Verify it is working

Two harmless self-test files. Neither is malware; both exist so you can confirm
each detection layer is live.

```bash
# Hash-signature layer
printf 'GUARDIANTUS-AV-SIGNATURE-SELFTEST-FILE-DO-NOT-REMOVE\n' > probe.txt
guardiantus check probe.txt    # → Guardiantus.SelfTest.HashProbe

# YARA layer
printf 'GUARDIANTUS-AV-YARA-SELFTEST-MARKER\n' > probe.yara.txt
guardiantus check probe.yara.txt
```

The industry-standard [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
is also detected, as `EICAR-Test-File`.

## Configuration

Everything lives in one JSON file. Find it with `guardiantus config path`:

| Platform | Location |
|---|---|
| Linux | `~/.local/share/guardiantus/` |
| macOS | `~/Library/Application Support/Guardiantus/` |
| Windows | `%PROGRAMDATA%\Guardiantus\` |

Override with `GUARDIANTUS_HOME` for a portable or containerised install.
A full uninstall is deleting that one directory.

Notable settings:

| Key | Default | Meaning |
|---|---|---|
| `scanning.heuristic_threshold` | `60` | Lower is more aggressive |
| `scanning.auto_quarantine` | `true` | Quarantine what scans identify |
| `scanning.quarantine_suspicious` | `false` | Also move heuristic-only hits |
| `scanning.trusted_hashes` | `[]` | Digests of restored or allowed files, never flagged again |
| `scanning.worker_threads` | `0` | 0 picks a number from your CPU count |
| `scanning.excluded_paths` | `[]` | Never scanned |
| `realtime.action` | `quarantine` | `quarantine` or `report` |
| `realtime.watch_paths` | `[]` | Empty means per-platform defaults |
| `updates.signature_url` | `""` | Signature feed manifest |
| `quarantine.retention_days` | `90` | Vault entries expire after this |

## Signature feeds

Point `updates.signature_url` at a JSON manifest:

```json
{
  "version": "2026.08.20",
  "sets": [
    { "name": "base", "url": "https://example.com/base.json", "sha256": "…" }
  ]
}
```

Each set is downloaded to a temporary file, checked against the manifest
digest, parsed and validated, and only then moved into place.

A signature set is plain JSON, so you can write your own:

```json
{
  "name": "my-rules",
  "version": "2026.08.20",
  "hashes":   [{ "sha256": "…", "name": "Trojan.Custom.A", "severity": "high" }],
  "patterns": [{ "name": "Custom.Marker", "ascii": "BAD-STRING", "severity": "high" }]
}
```

Drop it in `<data-dir>/signatures/`, or add one hash at a time:

```bash
guardiantus check suspicious.bin --json | jq -r '.results[0].sha256'
```

Custom YARA rules go in `<data-dir>/rules/` as `.yar` files. The `meta` block
understands `threat_name`, `severity`, `score` and `description`.

## Security design

Local security software is itself an attack surface, so:

- The dashboard binds to loopback only, and every `/api/*` call needs a
  per-run session token that never touches disk in world-readable form.
- **Host and Origin headers are validated**, which blocks DNS-rebinding — the
  attack where a web page you visit drives your local API. Without that check,
  any site could quarantine your files.
- A strict CSP with no inline scripts or styles, plus `nosniff`, `DENY` framing
  and `no-referrer`.
- Static file serving resolves and re-checks every path against the asset root,
  so `../` cannot escape it.
- Package upgrades run with a fixed argument vector and no shell, and package
  identifiers are validated against a strict pattern before being passed on.
- Program upgrades are **never** implicit — `programs_auto_install` is off and
  the code path requires an explicit call.
- Quarantined payloads are stored obfuscated so a parked sample cannot execute
  and does not trip other on-access scanners. This is containment, not
  encryption: it is reversible by design so a false positive can be undone.

## How it compares

Guardiantus is an honest, auditable, self-hosted scanner — not a commercial AV
with a threat-intelligence team behind it. Concretely, what it does **not**
have: a kernel driver, a cloud reputation service, a curated feed of millions
of live signatures, or behavioural sandboxing of running processes. It ships
with a small baseline signature set and expects you to point it at a feed for
real-world coverage.

What it does give you: a real multi-layer engine you can read end to end,
detections you can explain, and no telemetry.

## Development

```bash
pip install -e ".[dev,full]"
pytest                  # 108 tests
ruff check .
```

Layout:

```
guardiantus/
├── core/           engine — hashing, signatures, heuristics, YARA,
│                   scanner, quarantine, realtime, scheduler, db
├── updater/        signature feed + third-party program updates
├── service/        JSON API and the stdlib HTTP host
├── ui/             dashboard: templates and static assets
├── data/           bundled signature sets and YARA rules
├── application.py  the facade the CLI and API share
└── cli.py          command line interface
```

The engine has no dependency on the service layer, so it embeds cleanly:

```python
from guardiantus.core.scanner import FileScanner

result = FileScanner().scan_file("suspicious.bin")
if result.is_threat:
    print(result.primary_name, result.severity.value)
    for detection in result.detections:
        print(" ", detection.source.value, detection.description)
```

## License

MIT — see [LICENSE](LICENSE).
