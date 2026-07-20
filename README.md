# Python Netgear Switch Interface Library

Query and control all your Netgear switches — SNMP (managed), NSDP and HTTP
web-UI (Plus) — behind one model-driven Python API and the `ngsw` CLI.

Status: **early development.** See `docs/superpowers/specs/` for the design and
`docs/superpowers/plans/` for the implementation plans.

## Installation

### pip / uv (PyPI)

```sh
pip install python-netgear-switch-library
# or: uv add python-netgear-switch-library
```

Optional extras: `[async]` (pysnmp), `[http]` (httpx). The synchronous SNMP
transport shells out to the **net-snmp command-line tools**, a system package
(not a Python dependency):

```sh
sudo apt install snmp   # provides snmpget/snmpbulkwalk/snmpset
```

### Debian / Ubuntu (apt)

Signed `.deb` packages for Debian **trixie** and **sid** are published to a
GitHub Pages apt repository. Pick the line matching your suite:

```sh
sudo install -d -m0755 /etc/apt/keyrings
curl -fsSL https://mithro.github.io/python-netgear-switch-library/netgear-switch.gpg \
  | sudo tee /etc/apt/keyrings/netgear-switch.gpg > /dev/null

# trixie:
echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/python-netgear-switch-library/trixie/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list
# sid:
echo "deb [signed-by=/etc/apt/keyrings/netgear-switch.gpg] https://mithro.github.io/python-netgear-switch-library/sid/ ./" \
  | sudo tee /etc/apt/sources.list.d/netgear-switch.list

sudo apt update
sudo apt install python3-netgear-switch-library
```

This installs the `netgear_switch` library and the `ngsw` CLI, and pulls in the
`snmp` net-snmp CLI tools automatically.

Either way, once installed run `ngsw --help` to see available commands.

### Versioning

This project is a **rolling release**: the version is derived from git
(`0.0.postN` / `X.Y.postN`), and every merge to `main` publishes a new version
to PyPI and the apt repo. There are no tags or manual version bumps.

## Development

```sh
uv sync --all-extras
uv run pytest
uv run ruff check
```

## License

Apache-2.0.
