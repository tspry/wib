from __future__ import annotations

import re
from importlib import metadata as _md
from pathlib import Path

PYPROJECT_VERSION_PATTERN = re.compile(
    r"\[project\].*?^version\s*=\s*\"([^\"]+)\"", re.DOTALL | re.MULTILINE
)


def _read_pyproject_version() -> str | None:
    here = Path(__file__).resolve()
    for parent in here.parents:
        pp = parent / "pyproject.toml"
        if pp.is_file():
            try:
                text = pp.read_text(encoding="utf-8")
            except OSError:
                return None
            m = PYPROJECT_VERSION_PATTERN.search(text)
            if m:
                return m.group(1)
            break
    return None


def _detect_version() -> str:
    # Prefer installed distribution version; fall back to pyproject when running from source.
    try:
        return _md.version("wib-osint")
    except _md.PackageNotFoundError:
        pv = _read_pyproject_version()
        if pv:
            return f"{pv}+local"
        return "0.0.0+local"


__version__ = _detect_version()

__all__ = ["__version__"]
