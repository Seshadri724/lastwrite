# Contributing to lastwrite

Thanks for helping make file I/O forensics suck less.

## Dev setup

```powershell
cd lastwrite
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Running the checks

```powershell
ruff check .          # lint
pytest                # tests (no admin needed — they use --from-etl fixtures)
pytest --cov=lastwrite
```

The test suite never starts a real ETW trace, so it runs anywhere — including
CI on a non-elevated runner. Tests feed recorded `tracerpt` CSV fixtures
through the parser/analyzer/CLI. If you change capture behaviour, add a fixture
under `examples/` and a replay test rather than requiring admin in CI.

## Manual end-to-end test (needs Windows + admin)

```powershell
# From an elevated terminal:
python -m lastwrite --since 10s            # capture everything for 10s
python -m lastwrite --pid 1234 --since 30s
```

## Building artifacts

```powershell
python -m build                  # sdist + wheel into dist/
pip install -e ".[exe]"
pyinstaller lastwrite.spec       # standalone dist/lastwrite.exe
```

## Releasing

1. Bump `version` in `pyproject.toml` and `__init__.py`.
2. Move `Unreleased` notes into a dated section in `CHANGELOG.md`.
3. Commit, then tag: `git tag vX.Y.Z && git push --tags`.
4. The `Release` workflow builds the wheel/sdist + `.exe`, publishes to PyPI
   via trusted publishing, and attaches binaries to the GitHub Release.

## Code style

- Standard library first; the only runtime dependency is `rich`.
- Keep modules small and single-purpose (collector / parser / analyzer /
  render). New output formats go in `render.py`; new capture sources in
  `collector.py`.
- Parsing must stay tolerant: `tracerpt` column layouts vary across Windows
  builds, so prefer best-effort extraction over strict schemas.
