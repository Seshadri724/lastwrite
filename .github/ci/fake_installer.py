"""Stand-in installer for the live-capture CI job. Only ever run on a disposable runner.

good: writes only under C:\\Program Files\\LwAcme
bad:  also drops an exe in %TEMP% and a shortcut in the all-users Startup folder
"""

import os
import sys
from pathlib import Path

mode = sys.argv[1]
root = Path(r"C:\Program Files\LwAcme")
root.mkdir(parents=True, exist_ok=True)
(root / "acme.exe").write_bytes(b"MZ" + b"\0" * 50_000)
(root / "config.ini").write_text("[acme]\n")

if mode == "bad":
    Path(os.environ["TEMP"], "lw-update.exe").write_bytes(b"MZ" + b"\0" * 9_000)
    Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\lw-agent.lnk").write_bytes(b"\0" * 900)
