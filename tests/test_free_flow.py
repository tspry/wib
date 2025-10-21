import json
from typing import Any

import respx
from httpx import Response

from wib.main import main


@respx.mock
def test_ip_free_flow(monkeypatch: Any, capsys: Any) -> None:
    # Mock ipwho.is
    respx.get("https://ipwho.is/1.1.1.1").mock(
        return_value=Response(
            200,
            json={
                "success": True,
                "ip": "1.1.1.1",
                "connection": {"asn": "AS13335", "isp": "Cloudflare"},
                "country": "United States",
                "region": "CA",
                "city": "Los Angeles",
                "latitude": 34.05,
                "longitude": -118.24,
                "org": "Cloudflare, Inc.",
                "domain": "one.one.one.one",
            },
        )
    )

    rc = main(["1.1.1.1", "--output", "json"])
    captured = capsys.readouterr().out
    assert rc == 0
    data = json.loads(captured)
    assert data["kind"] == "ip" or isinstance(data, list)


@respx.mock
def test_domain_free_flow(monkeypatch: Any, capsys: Any) -> None:
    # Mock rdap
    respx.get("https://rdap.org/domain/example.com").mock(
        return_value=Response(
            200,
            json={
                "ldhName": "example.com",
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-13T04:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2020-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2030-08-13T04:00:00Z"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": [
                            "vcard",
                            [["fn", {}, "text", "Example Registrar"]],
                        ],
                    }
                ],
                "nameservers": [
                    {"ldhName": "a.iana-servers.net"},
                    {"ldhName": "b.iana-servers.net"},
                ],
                "secureDNS": {"zoneSigned": True},
            },
        )
    )

    rc = main(["example.com", "--output", "json"])
    captured = capsys.readouterr().out
    assert rc == 0
    data = json.loads(captured)
    assert data["kind"] == "domain" or isinstance(data, list)
