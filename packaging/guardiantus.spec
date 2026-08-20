# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller build spec for the Guardiantus AV desktop launcher.

Build with:

    pyinstaller packaging/guardiantus.spec --noconfirm

Produces a single-file, double-click executable that starts the local
dashboard exactly the way ``guardiantus dashboard`` does. Run from the repo
root (or pass --distpath/--workpath) so the relative paths below resolve.

Data files are collected explicitly rather than via a hooks file: the app
has no plugin system and no dynamic imports outside the standard library, so
there is nothing else PyInstaller needs to be told about.
"""

import sys
from pathlib import Path

block_cipher = None

REPO_ROOT = Path(SPECPATH).resolve().parent
PKG = REPO_ROOT / "guardiantus"
ICONS = REPO_ROOT / "packaging" / "icons"

# (source, destination-inside-bundle) -- destination mirrors the package
# layout so guardiantus.paths._package_root() finds them at <bundle>/guardiantus/...
datas = [
    (str(PKG / "ui" / "templates"), "guardiantus/ui/templates"),
    (str(PKG / "ui" / "static"), "guardiantus/ui/static"),
    (str(PKG / "data" / "signatures"), "guardiantus/data/signatures"),
    (str(PKG / "data" / "rules"), "guardiantus/data/rules"),
]

icon = None
if sys.platform == "win32":
    candidate = ICONS / "guardiantus.ico"
    icon = str(candidate) if candidate.is_file() else None
elif sys.platform == "darwin":
    candidate = ICONS / "guardiantus.icns"
    icon = str(candidate) if candidate.is_file() else None

a = Analysis(
    [str(REPO_ROOT / "packaging" / "launcher.py")],
    pathex=[str(REPO_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "guardiantus.core",
        "guardiantus.service.api",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Optional accelerators: only bundled if actually installed in the
        # build environment. Absence must not be an error -- the whole point
        # of this project is that it runs without them.
    ],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="guardiantus",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # UPX-packed binaries are themselves a heuristic red flag.
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # keeps the window open; see packaging/launcher.py
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=icon,
)
