from __future__ import annotations

from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table

from ..models.common import DomainData, IpData


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
        table.add_row("Note", "No RDAP whois available")
    return Panel(table, title="RDAP Whois", box=box.ROUNDED)


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
    panels = left_panels
    for p in panels:
        console.print(p)
