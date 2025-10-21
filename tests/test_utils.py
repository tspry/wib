import pytest

from wib.utils import normalize_host_input


@pytest.mark.parametrize(
    "raw, kind, value",
    [
        ("1.1.1.1", "ip", "1.1.1.1"),
        ("[2606:4700:4700::1111]", "ip", "2606:4700:4700::1111"),
        ("api[.]google[.]com", "domain", "api.google.com"),
        ("https://example.com/path", "domain", "example.com"),
    ],
)
def test_normalize_host_input(raw: str, kind: str, value: str) -> None:
    got_kind, got_value = normalize_host_input(raw)
    assert got_kind == kind
    assert got_value == value
