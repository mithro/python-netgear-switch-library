# Python Netgear Switch Interface Library

Query and control all your Netgear switches — SNMP (managed), NSDP and HTTP
web-UI (Plus) — behind one model-driven Python API and the `ngsw` CLI.

Status: **early development.** See `docs/superpowers/specs/` for the design and
`docs/superpowers/plans/` for the implementation plans.

## Development

```sh
uv sync --all-extras
uv run pytest
uv run ruff check
```

## License

Apache-2.0.
