from __future__ import annotations

import argparse
import os
import shlex
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .. import __version__


class OutputFormat(str, Enum):
    rich = "rich"
    json = "json"
    yaml = "yaml"
    md = "md"


class GeoService(str, Enum):
    ipwhois = "ipwhois"
    ip2location = "ip2location"
    ipinfo = "ipinfo"


@dataclass
class Keys:
    VT_API_KEY: str | None = None
    IP2WHOIS_API_KEY: str | None = None
    IP2LOCATION_API_KEY: str | None = None
    IPINFO_API_KEY: str | None = None
    SHODAN_API_KEY: str | None = None
    GREYNOISE_API_KEY: str | None = None
    ABUSEIPDB_API_KEY: str | None = None
    URLHAUS_API_KEY: str | None = None


@dataclass
class AppConfig:
    output: OutputFormat = OutputFormat.rich
    out_file: str | None = None
    entities: list[str] | None = None
    all_optional: bool = False
    one_column: bool = False
    no_color: bool = False
    timeout: float = 10.0
    no_virustotal: bool = False
    max_resolutions: int = 10
    geo_service: GeoService = GeoService.ipwhois
    verbosity: int = 0  # -v/-q counts
    keys: Keys = field(default_factory=Keys)
    show_dns: bool = False


def _load_envfile() -> dict[str, str]:
    envfile = os.environ.get("WIB_ENV_FILE") or os.path.join(Path.home(), ".env.wib")
    result: dict[str, str] = {}
    try:
        with open(envfile, encoding="utf-8") as f:
            for raw_line in f:
                s = raw_line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" in s:
                    k, v = s.split("=", 1)
                    result[k.strip()] = v.strip()
    except FileNotFoundError:
        pass
    return result


def _merge_env(envfile_vars: dict[str, str]) -> None:
    # process env wins per requirements
    for k, v in envfile_vars.items():
        os.environ.setdefault(k, v)


def _parse_args(argv: Iterable[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="wib", description="Passive OSINT lookups for IPs and domains")
    p.add_argument("entities", nargs="*", help="IPs or domains/FQDNs (defanged ok)")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument(
        "-A",
        "--all",
        dest="all_optional",
        action="store_true",
        help="Enable all optional enrichments for which keys are configured",
    )
    p.add_argument(
        "--geo-service",
        choices=[g.value for g in GeoService],
        default=os.environ.get("GEOLOCATION_SERVICE", GeoService.ipwhois.value),
    )
    p.add_argument("--max-resolutions", type=int, default=10)
    p.add_argument("--one-column", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--no-virustotal", action="store_true")
    p.add_argument("--dns", dest="show_dns", action="store_true", help="Resolve DNS records")
    p.add_argument(
        "--output", choices=[f.value for f in OutputFormat], default=OutputFormat.rich.value
    )
    p.add_argument("--out-file", dest="out_file")
    p.add_argument("-v", action="count", default=0)
    p.add_argument("-q", action="count", default=0)
    return p.parse_args(list(argv))


def _collect_keys() -> Keys:
    return Keys(
        VT_API_KEY=os.environ.get("VT_API_KEY"),
        IP2WHOIS_API_KEY=os.environ.get("IP2WHOIS_API_KEY"),
        IP2LOCATION_API_KEY=os.environ.get("IP2LOCATION_API_KEY"),
        IPINFO_API_KEY=os.environ.get("IPINFO_API_KEY"),
        SHODAN_API_KEY=os.environ.get("SHODAN_API_KEY"),
        GREYNOISE_API_KEY=os.environ.get("GREYNOISE_API_KEY"),
        ABUSEIPDB_API_KEY=os.environ.get("ABUSEIPDB_API_KEY"),
        URLHAUS_API_KEY=os.environ.get("URLHAUS_API_KEY"),
    )


def load_config(argv: Iterable[str] | None = None) -> AppConfig:
    argv = list(argv) if argv is not None else []
    # Merge WIB_DEFAULTS before argv
    defaults = os.environ.get("WIB_DEFAULTS", "")
    default_args = shlex.split(defaults)
    merged = [*default_args, *argv]

    # load env file then merge into process env
    envfile_vars = _load_envfile()
    _merge_env(envfile_vars)

    ns = _parse_args(merged)
    verbosity = int(ns.v) - int(ns.q)
    cfg = AppConfig(
        output=OutputFormat(ns.output),
        out_file=ns.out_file,
        entities=list(ns.entities) if ns.entities else [],
        all_optional=bool(ns.all_optional),
        one_column=bool(ns.one_column),
        no_color=bool(ns.no_color),
        timeout=float(ns.timeout),
        no_virustotal=bool(ns.no_virustotal),
        max_resolutions=int(ns.max_resolutions),
        geo_service=GeoService(ns.geo_service),
        verbosity=verbosity,
        keys=_collect_keys(),
        show_dns=bool(ns.show_dns),
    )
    return cfg
