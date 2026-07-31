# Python Netgear Switch Interface Library

Query and control all your Netgear switches — SNMP (managed), NSDP and HTTP
web-UI (Plus) — behind one model-driven Python API and the `ngsw` CLI.

**Documentation: <https://python-netgear-switch-library.readthedocs.io/>** — API
reference, the complete `ngsw` CLI reference, the virtual-switch guide (how to
test your own tools against a mock), and generated
[model × protocol and model × functionality support tables](https://python-netgear-switch-library.readthedocs.io/en/latest/models/support.html).

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

## Mock switch daemons (`ngsw serve`)

The library ships in-repo virtual/mock switches. `ngsw serve` runs them as
standalone, long-lived daemons on real sockets, so an external tool or library
can point at a mock when real hardware is unavailable (CI, local development,
demos).

```sh
# Serve one model (ephemeral ports), or several, or every registered model:
ngsw serve --model gsm7228ps
ngsw serve --model gsm7228ps --model gs305ep
ngsw serve --all
```

For each switch that comes up it prints the model, bind host, the actual bound
port(s) (SNMP/NSDP over UDP, HTTP over TCP), and the SNMP community and HTTP
password it accepts, then blocks until interrupted (`Ctrl-C` / `SIGTERM`), at
which point every switch is stopped cleanly:

```text
[gsm7228ps] host=127.0.0.1
    SNMP udp/36540
    HTTP tcp/42629
    community='public' http_password='password'
serving 1 mock switch(es); press Ctrl-C to stop
```

Point any tool at the printed port. For example, with the mock above serving
SNMP on UDP `36540`:

```sh
snmpwalk -v2c -c public 127.0.0.1:36540 1.3.6.1.2.1.1
# ...or the library's own CLI against the same mock:
ngsw --host 127.0.0.1 --model gsm7228ps --community public ports   # + your transport wiring
```

Options:

- `--model KEY` — model to serve; repeatable. `--all` serves every registered
  model (see `ngsw models`).
- `--host IP` — bind address (default `127.0.0.1`). Pass `0.0.0.0` to expose the
  mock to other hosts on the network.
- `--community STR` / `--http-password STR` — credentials the mock accepts
  (defaults `public` / `password`).
- `--port N` / `--http-port N` — pin the SNMP/NSDP UDP port and the HTTP TCP
  port instead of using ephemeral ones. Because a pinned port is a single
  listener, these are only allowed when serving exactly one model; otherwise
  leave them unset and read the printed ephemeral ports.

Full details, including worked examples of testing an external tool against a
mock, are in the [virtual switch
guide](https://python-netgear-switch-library.readthedocs.io/en/latest/fake/).

## Development

```sh
uv sync --all-extras
uv run pytest
uv run ruff check
uv run mypy
```

Build the documentation (warnings are errors, as on Read the Docs):

```sh
uv sync --extra docs
make -C docs html
```

## License

Apache-2.0.
