# Packaging the desktop executable

Builds a double-click binary (`guardiantus.exe` / `guardiantus`) that starts
the local dashboard exactly the way `guardiantus dashboard` does. This is
separate from `pip install`, which remains the primary install path — this is
for people who want something they can just double-click.

## How it fits together

| File | Purpose |
|---|---|
| `launcher.py` | The actual entry point. Starts the dashboard, opens the browser, keeps the console window open so it doesn't flash-close on Windows. |
| `guardiantus.spec` | PyInstaller build spec. Bundles the UI assets and the base signature/rule set as data files. |
| `make_icons.py` | Renders the shield mark to `.ico` / `.icns` / `.png` with Pillow — no SVG rasterizer dependency. |
| `icons/` | Generated icons, committed so CI doesn't need to regenerate them on every OS. |

## Why a separate entry point

The CLI (`guardiantus/cli.py`) expects arguments. Someone who double-clicks
an icon does not want an argument parser — they want the app to start. So
`launcher.py` skips argument parsing entirely and just runs the dashboard.

## The frozen-path problem

Under a normal install, `guardiantus/paths.py` finds bundled data (the UI,
the base signature set, the YARA rules) relative to `__file__`. Under
PyInstaller, Python modules are loaded from an embedded archive rather than
loose files on disk, so `__file__` doesn't point anywhere real. `paths.py`
detects `sys.frozen` and looks in the unpacked bundle directory
(`sys._MEIPASS` for a onefile build) instead. The spec's `datas` list mirrors
the package layout there (`guardiantus/ui/...`, `guardiantus/data/...`) so the
two agree.

This was tested, not assumed: a local Linux onefile build was run and its
dashboard, signature loading and a real detection were verified over HTTP
before this was trusted for the actual Windows/macOS release builds.

## Building locally

```bash
pip install -e ".[full,build]"
pyinstaller packaging/guardiantus.spec --noconfirm
./dist/guardiantus        # or dist\guardiantus.exe on Windows
```

## Regenerating the icons

Only needed if the logo changes.

```bash
pip install pillow icnsutil
python packaging/make_icons.py
```

## CI release builds

`.github/workflows/release.yml` builds this spec on `windows-latest`,
`macos-13` (Intel), `macos-14` (Apple Silicon) and `ubuntu-latest`, and
publishes the results to a GitHub Release with SHA-256 checksums. `watchdog`
and `yara-python` are installed best-effort per runner; if a platform lacks a
prebuilt wheel the build still succeeds and that binary falls back to the
polling watcher / built-in YARA interpreter, the same graceful degradation
the pip install already has.

Trigger it by pushing a tag (`git tag v1.0.1 && git push origin v1.0.1`) or
manually via **Actions → Build & release binaries → Run workflow**.

These builds are **not code-signed**. Windows SmartScreen and macOS
Gatekeeper will both warn on first launch — expected for an open-source
project without a paid signing certificate. The download page explains how
to proceed past each warning.
