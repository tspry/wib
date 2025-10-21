from __future__ import annotations

from pathlib import Path

try:
    from importlib.metadata import PackageNotFoundError, version
except Exception:  # pragma: no cover - very old Python
    PackageNotFoundError = Exception  # type: ignore[assignment]

    def version(distribution_name: str) -> str:  # type: ignore[misc]
        return "0.0.0"


try:  # Python 3.11+
    import tomllib as _tomllib  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - optional
    _tomllib = None  # type: ignore[assignment]


def _detect_version() -> str:
    # Prefer installed distribution version
    try:
        return version("wib-osint")
    except PackageNotFoundError:
        # Likely running from source; try reading pyproject.toml
        pass
    except Exception:
        pass

    if _tomllib is not None:
        here = Path(__file__).resolve()
        for parent in here.parents:
            pp = parent / "pyproject.toml"
            if pp.is_file():
                try:
                    with open(pp, "rb") as f:
                        data = _tomllib.load(f)  # type: ignore[arg-type]
                    v = data.get("project", {}).get("version")
                    if isinstance(v, str) and v:
                        # Mark as a local source build
                        return f"{v}+local"
                except Exception:
                    break
                break
    # Ultimate fallback
    return "0.0.0+local"


__version__ = _detect_version()

__all__ = ["__version__"]
