# wib

Passive OSINT lookups for IPs and domains with a clean terminal UI.

- Free by default: IPWhois (ipwho.is) for IPs; RDAP for domains.
- Optional enrichments when API keys provided (VirusTotal, IP2Whois, IPinfo, etc.).
- Pretty Rich panels or machine-readable JSON/YAML/Markdown output.

## Install (dev)

Windows-friendly steps (PowerShell or zsh on Windows):

```sh
python -m venv .venv
. .venv/Scripts/activate
pip install -U pip
pip install -e ".[dev]"
```

Note for zsh: square brackets are glob characters. Always quote extras (".[dev]") or escape them (\.\[dev\]) to avoid "no matches found".

## Usage

```sh
wib 1.1.1.1
wib google.com
wib api[.]google[.]com -A
python -m wib.main google.com --output json
```

Global flags:

- -A/--all: enable all optional enrichments for which keys are configured
- --geo-service [ipwhois|ip2location|ipinfo]
- --max-resolutions N (for VT)
- --one-column, --no-color
- --timeout <seconds>
- --no-virustotal
- --output [rich|json|yaml|md], --out-file <path>

Environment:

- WIB_DEFAULTS: space-separated default flags merged before argv
- Optional env file: ~/.env.wib (process env wins)
- Keys (all optional): VT_API_KEY, IP2WHOIS_API_KEY, IP2LOCATION_API_KEY, IPINFO_API_KEY, SHODAN_API_KEY, GREYNOISE_API_KEY, ABUSEIPDB_API_KEY, URLHAUS_API_KEY
- GEOLOCATION_SERVICE mirrors --geo-service

## Tests

```sh
python -m pytest -q
```

## Dev tasks

```sh
ruff check .
black .
mypy .
pytest -q
bandit -r wib
```

License: MIT
