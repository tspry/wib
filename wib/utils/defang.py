import re

DEFANG_REPLACEMENTS = [
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
]


def refang(value: str) -> str:
    s = value.strip()
    for patt, repl in DEFANG_REPLACEMENTS:
        s = patt.sub(repl, s)
    return s


def defang(value: str) -> str:
    # Simple defang: replace . with [.] in hostnames/IPs; leave scheme/path alone
    # Not perfect but sufficient for copying to chats safely
    return value.replace(".", "[.]")
