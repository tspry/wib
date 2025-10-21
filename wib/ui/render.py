from __future__ import annotations

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

from ..models.common import DomainData, DomainDns, IpData


def _ip_panel(data: IpData) -> Panel:
    table = Table.grid(padding=1)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    if data.geo:
        g = data.geo
        rows = [
            ("IP", g.ip),
            ("ASN", g.asn or "-"),
            ("Org", g.org or "-"),
            ("ISP", g.isp or "-"),
            ("Country", g.country or "-"),
            ("Region", g.region or "-"),
            ("City", g.city or "-"),
            ("Lat,Lon", f"{g.lat},{g.lon}" if g.lat is not None and g.lon is not None else "-"),
            ("Reverse", g.domain or "-"),
        ]
        for k, v in rows:
            table.add_row(k, str(v))
    else:
        table.add_row("Note", "No geolocation data available")
    return Panel(table, title="IPWhois", box=box.ROUNDED)


def _whois_panel(d: DomainData) -> Panel:
    table = Table.grid(padding=1)
    table.add_column("Field", style="bold cyan")
    table.add_column("Value")
    if d.whois:
        w = d.whois
        rows = [
            ("Domain", w.domain),
            ("Registrar", w.registrar or "-"),
            ("Nameservers", ", ".join(w.nameservers or []) or "-"),
            ("DNSSEC", "yes" if w.dnssec else "no" if w.dnssec is not None else "-"),
            ("Created", w.created.isoformat() if w.created else "-"),
            ("Updated", w.updated.isoformat() if w.updated else "-"),
            ("Expires", w.expires.isoformat() if w.expires else "-"),
        ]
        for k, v in rows:
            table.add_row(k, str(v))
    else:
        table.add_row("Note", "No whois available")
    return Panel(table, title="Whois", box=box.ROUNDED)


def _dns_panel(dns: DomainDns) -> Panel:
    table = Table.grid(padding=1)
    table.add_column("Record", style="bold cyan")
    table.add_column("Value")
    rows: list[tuple[str, str]] = []
    if dns.a:
        rows.append(("A", ", ".join(dns.a)))
    if dns.aaaa:
        rows.append(("AAAA", ", ".join(dns.aaaa)))
    if dns.cname:
        rows.append(("CNAME", ", ".join(dns.cname)))
    if dns.ns:
        rows.append(("NS", ", ".join(dns.ns)))
    if dns.mx:
        rows.append(("MX", ", ".join(f"{mx.preference} {mx.exchange}" for mx in dns.mx)))
    if dns.txt:
        rows.append(("TXT", " | ".join(dns.txt)))
    for k, v in rows:
        table.add_row(k, v)
    return Panel(table, title="DNS", box=box.ROUNDED)


def render_ip(data: IpData, *, one_column: bool, no_color: bool = False) -> None:
    console = Console(color_system=None if no_color else "auto")
    layout = Layout()
    layout.split_row(Layout(name="left"), Layout(name="right"))
    left_panels = [_ip_panel(data)]
    panels = left_panels
    for p in panels:
        console.print(p)


def render_domain(data: DomainData, *, one_column: bool, no_color: bool = False) -> None:
    console = Console(color_system=None if no_color else "auto")
    layout = Layout()
    layout.split_row(Layout(name="left"), Layout(name="right"))
    left_panels = [_whois_panel(data)]
    if data.dns:
        left_panels.append(_dns_panel(data.dns))
    panels = left_panels
    for p in panels:
        console.print(p)
