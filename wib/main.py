from __future__ import annotations

import asyncio
import importlib
import json
import os
import sys
from typing import Any

from .config import AppConfig, OutputFormat, load_config
from .handlers import DomainHandler, IpAddressHandler
from .models.common import DomainData, IpData
from .ui import render_domain, render_ip
from .utils import UserVisibleError, normalize_host_input

# Optional YAML support without static import errors
yaml: Any | None
try:  # pragma: no cover - trivial
    yaml = importlib.import_module("yaml")
except Exception:  # pragma: no cover
    yaml = None


async def _process_entity(entity: str, cfg: AppConfig) -> tuple[str, IpData | DomainData]:
    kind, value = normalize_host_input(entity)
    if kind == "ip":
        ip_handler = IpAddressHandler(timeout=cfg.timeout)
        try:
            data: IpData | DomainData = await ip_handler.fetch(value)
        finally:
            await ip_handler.aclose()
        return kind, data
    else:
        dom_handler = DomainHandler(
            timeout=cfg.timeout, ip2whois_key=os.getenv("IP2WHOIS_API_KEY") or None
        )
        try:
            data = await dom_handler.fetch(value, include_dns=cfg.show_dns)
        finally:
            await dom_handler.aclose()
        return kind, data


def _render(kind: str, data: IpData | DomainData, cfg: AppConfig) -> None:
    if kind == "ip" and isinstance(data, IpData):
        render_ip(data, one_column=cfg.one_column, no_color=cfg.no_color)
    elif kind == "domain" and isinstance(data, DomainData):
        render_domain(data, one_column=cfg.one_column, no_color=cfg.no_color)
    else:  # pragma: no cover - defensive
        raise UserVisibleError("Unexpected data type for rendering")


def _to_machine(kind: str, data: IpData | DomainData, fmt: OutputFormat) -> str:
    obj: dict[str, Any] = {"kind": kind, "data": data.model_dump()}
    if fmt == OutputFormat.json:
        return json.dumps(obj, indent=2, default=str)
    if fmt == OutputFormat.yaml:
        return (
            json.dumps(obj, indent=2, default=str)
            if yaml is None
            else yaml.safe_dump(obj, sort_keys=False)
        )
    # Markdown
    if kind == "ip" and isinstance(data, IpData):
        lines = [f"# IP {data.ip}"]
        if data.geo:
            g = data.geo
            lines += [
                "## Geo",
                f"- ASN: {g.asn}",
                f"- Org: {g.org}",
                f"- ISP: {g.isp}",
                f"- Country: {g.country}",
                f"- Region: {g.region}",
                f"- City: {g.city}",
                f"- Lat,Lon: {g.lat},{g.lon}",
            ]
        return "\n".join(lines)
    if kind == "domain" and isinstance(data, DomainData):
        lines = [f"# Domain {data.domain}"]
        if data.whois:
            w = data.whois
            lines += [
                "## Whois",
                f"- Registrar: {w.registrar}",
                f"- Nameservers: {', '.join(w.nameservers or [])}",
                f"- DNSSEC: {w.dnssec}",
                f"- Created: {w.created}",
                f"- Updated: {w.updated}",
                f"- Expires: {w.expires}",
            ]
        return "\n".join(lines)
    return json.dumps({"kind": kind, "data": data.model_dump()}, default=str)


async def _collect_results(cfg: AppConfig) -> list[tuple[str, IpData | DomainData]]:
    results: list[tuple[str, IpData | DomainData]] = []
    for e in cfg.entities or []:
        results.append(await _process_entity(e, cfg))
    return results


def _emit_output(cfg: AppConfig, results: list[tuple[str, IpData | DomainData]]) -> None:
    if cfg.output == OutputFormat.rich:
        for k, d in results:
            _render(k, d, cfg)
        return
    if cfg.output in (OutputFormat.json, OutputFormat.yaml):
        obj: Any
        if len(results) > 1:
            obj = [{"kind": k, "data": d.model_dump()} for k, d in results]
        else:
            k, d = results[0]
            obj = {"kind": k, "data": d.model_dump()}
        if cfg.output == OutputFormat.json or yaml is None:
            text = json.dumps(obj, indent=2, default=str)
        else:
            text = yaml.safe_dump(obj, sort_keys=False)
    else:
        chunks: list[str] = []
        for k, d in results:
            chunks.append(_to_machine(k, d, OutputFormat.md))
        text = "\n\n---\n\n".join(chunks)
    if cfg.out_file:
        with open(cfg.out_file, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    cfg = load_config(args)
    if not cfg.entities:
        raise UserVisibleError("Provide at least one IP or domain")
    try:
        results = asyncio.run(_collect_results(cfg))
    except UserVisibleError as e:
        print(e.message)
        return 2
    _emit_output(cfg, results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
