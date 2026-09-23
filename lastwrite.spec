# PyInstaller spec — builds a single-file standalone lastwrite.exe.
#
#   pip install -e ".[exe]"
#   pyinstaller lastwrite.spec
#   dist/lastwrite.exe --help
#
# The result needs no Python install on the target machine. It still requires
# Administrator privileges at runtime to start the ETW kernel session.
#
# UNSIGNED: this build is not code-signed. Windows SmartScreen will show a
# "Windows protected your PC" warning on first run. Sign it (signtool, with a
# code-signing cert) before handing dist/lastwrite.exe to anyone outside the
# dev team, or distribute via `pip install lastwrite` instead.

# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ["lastwrite/__main__.py"],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=["lastwrite.cli"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "_pytest"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="lastwrite",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
