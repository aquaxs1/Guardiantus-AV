# Architecture

## Layering

```
                    ┌──────────────┐   ┌──────────────┐
                    │     CLI      │   │  Dashboard   │
                    │  cli.py      │   │  ui/ + JS    │
                    └──────┬───────┘   └──────┬───────┘
                           │                  │
                           │           ┌──────┴───────┐
                           │           │  service/    │
                           │           │  api.py      │
                           │           │  server.py   │
                           │           └──────┬───────┘
                           └────────┬─────────┘
                                    │
                          ┌─────────┴──────────┐
                          │  application.py    │  facade
                          └─────────┬──────────┘
              ┌────────────┬────────┴─────┬────────────┐
              │            │              │            │
        ┌─────┴─────┐ ┌────┴─────┐ ┌──────┴─────┐ ┌────┴──────┐
        │  core/    │ │ updater/ │ │  config.py │ │  paths.py │
        │  engine   │ │ updates  │ │            │ │           │
        └───────────┘ └──────────┘ └────────────┘ └───────────┘
```

Dependencies point downward only. `core/` never imports `service/`, so the
engine embeds in other programs without dragging in an HTTP server. Both
front ends go through `Application`, which is why the CLI and the dashboard
can never disagree about protection status.

## Detection pipeline

`FileScanner.scan_file()` runs the cheap layers first and stops early where it
can:

1. **Policy** — symlink and exclusion checks, plus Guardiantus's own
   installation, data directory and vault. Skipped files cost nothing.
2. **Hashing** — one streaming pass produces MD5, SHA-1 and SHA-256.
3. **Allow-list** — digests the user restored from quarantine stop here, clean.
4. **Hash signatures** — a dict lookup. Exact, zero false positives.
5. **Deep read** — the first 4 MiB into memory. Files over
   `scanning.max_file_size_mb` stop here, hashed but not inspected.
6. **Pattern signatures** — byte fragments, optionally anchored to a magic value.
7. **YARA** — `yara-python` if present, otherwise the built-in interpreter.
8. **Heuristics** — scored rules summed against `scanning.heuristic_threshold`.
9. **Archives** — ZIP members scanned from memory, recursing into step 6.

Steps 7 and 8 are skipped for Windows API-set forwarder DLLs, whose contents
are the names of every Win32 function they re-export; those are judged on
signatures alone.

Heuristic findings are split in two. *Primary* findings are constructs
specific to malware — an encoded PowerShell command, a reverse shell,
`vssadmin delete shadows`, an executable wearing a `.pdf` name. *Supporting*
findings are properties malware often has and ordinary files have too — high
entropy, an embedded base64 blob, hardcoded URLs, an import of
`VirtualAllocEx`. A detection needs at least one primary finding; supporting
ones only add weight to it, and can never raise an alarm by themselves.

Findings are then deduplicated by `(name, source)` and folded into one verdict:

| Verdict | When |
|---|---|
| `malicious` | A signature or YARA rule matched, or a critical-severity finding |
| `suspicious` | Heuristics only |
| `clean` | Nothing fired |
| `skipped` | Policy excluded it |
| `error` | It could not be read |

The distinction matters: a signature hit names a specific family, while a
heuristic hit is an inference. The UI ranks signature and YARA names above
heuristic ones for exactly that reason.

## Why the YARA fallback fails closed

When `yara-python` is missing, a small interpreter handles the subset the
bundled rules use: text/hex/regex strings, `N of them`, `N of ($a*)`, and
boolean combinations of string identifiers. Conditions it cannot parse are
**skipped rather than guessed at**, and the boolean evaluator is a hand-written
recursive-descent parser rather than `eval`. A missing optional dependency can
therefore reduce coverage, but it can never manufacture a false positive.

## Real-time protection

Two backends feed one debounced queue, so the decision logic exists once:

- **watchdog** — inotify / FSEvents / ReadDirectoryChangesW. Immediate.
- **poll** — walks the watched trees on an interval, comparing mtimes.

A worker thread drains the queue. Before scanning it checks whether the file's
size is still changing and re-queues if so, which avoids scanning half-written
downloads. Files with in-progress suffixes (`.part`, `.crdownload`, …) are
ignored outright.

## Concurrency

- `ScanJob` submits work to a bounded pool, keeping only `workers × 4` futures
  in flight. `Executor.map` would materialise one future per file, which on a
  full-disk scan means millions of objects.
- Pause is a `threading.Event` the workers wait on; cancel is a second event
  checked between files.
- One SQLite connection guarded by an `RLock`, in WAL mode so the dashboard
  reads while a scan writes.
- Event-log and metadata writes are best effort: a scan thread finishing after
  shutdown logs into a closed database, and losing that line beats crashing
  the worker.

## Dashboard security

The dashboard drives an API that can quarantine files and install packages, so
it is treated as a real attack surface:

| Control | Attack it stops |
|---|---|
| Loopback bind | Remote access |
| Per-run session token | Local processes without the token |
| Host header validation | **DNS rebinding** — a visited web page driving the local API |
| Origin validation | Cross-origin requests |
| Strict CSP, no inline script or style | XSS via injected content |
| Resolve-and-recheck static paths | `../` directory traversal |
| Fixed argv, no shell, validated package ids | Command injection through package names |

The CSP forbidding inline styles is why the client sets the progress-bar width
through the CSSOM instead of a `style` attribute.

## Data layout

Everything lives under one directory (`GUARDIANTUS_HOME`, else the platform
default), so uninstalling is one `rm -rf`:

```
config.json            settings
guardiantus.db         events, scans, detections, quarantine index
quarantine/
  vault.key            per-install key, mode 0600
  <uuid>.qtn           obfuscated payload
signatures/            downloaded and user signature sets
rules/                 user YARA rules
logs/                  application log
run/session.token      dashboard token, mode 0600
```

## Extending it

**A new detection layer** — add a module under `core/`, return
`list[Detection]`, and call it from `FileScanner._inspect_buffer`.

**A new package manager** — subclass `PackageManager` in `updater/programs.py`
with `outdated()`, `upgrade()` and `upgrade_all()`, then add it to
`platform_managers()`. It shows up in the CLI and the dashboard automatically.

**A new API endpoint** — decorate a `(app, request) -> (status, payload)`
function with `@route`. Handlers are plain functions, so they unit-test without
an HTTP server in the loop.
