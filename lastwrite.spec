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
# "Windows protected your PC" warning on first run. Before public release:
#   1. Sign with Azure Trusted Signing or signtool + EV cert:
#        signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 dist\lastwrite.exe
#   2. Publish dist\lastwrite.exe.sha256 alongside the exe.
# Until then, distribute via `pip install lastwrite` or hand the exe only to
# beta testers with the checksum.

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
    # upx=False on purpose: UPX packing triggers antivirus false positives,
    # which is fatal for a security tool's reputation.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    # Request elevation at launch: ETW kernel capture requires admin.
    # Keeps behavior identical to `lastwrite` from an elevated terminal,
    # instead of failing deep inside logman with access-denied.
    uac_admin=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
