"""Sphinx extension: support tables generated from the library, not by hand.

Every table this module renders is a projection of
``src/netgear_switch/registry.py`` and ``src/netgear_switch/capabilities.py``,
read at build time. Nothing here restates a fact that lives in the code, so a
model gaining a backend, an endpoint spec losing a page, or a CLI spec flipping
its verification flag changes these pages in the same commit -- and a table can
never quietly disagree with what the library will actually do.

Directives
----------

``.. ngsw-model-table::``
    Every registered model: class, port counts, backends, verification status.

``.. ngsw-protocol-table::``
    Model x backend support grid (the "which protocols can I use?" table).

``.. ngsw-operation-table:: [reads|writes]``
    Operation x model grid; each cell names the backends that serve it.

``.. ngsw-model-support:: <model-key>``
    One model in full: operation x backend, with the reason for every refusal.

``.. ngsw-support-gaps::``
    Every operation a model supports on one backend but not another -- the
    backend-parity gaps, listed rather than buried.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from docutils.parsers.rst import directives
from sphinx.util.docutils import SphinxDirective

from netgear_switch.capabilities import (
    READ_OPERATIONS,
    WRITE_OPERATIONS,
    Support,
    backends_for,
    support,
)
from netgear_switch.registry import MODEL_ALIASES, MODELS, Backend, get_model

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from docutils import nodes
    from sphinx.application import Sphinx

#: Compact per-backend labels used inside grid cells. The CLI backends share a
#: label because they are one command surface reached over three transports
#: (see ``src/netgear_switch/registry.py``'s ``Backend``).
_ABBREV = {
    Backend.SNMP: "S",
    Backend.NSDP: "N",
    Backend.HTTP: "H",
    Backend.SSH: "C",
    Backend.TELNET: "C",
    Backend.CONSOLE: "C",
}

_YES = "✓"  # check mark
_NO = "—"  # em dash


def _rst_escape(text: str) -> str:
    """Neutralise inline reST markup in generated cell text."""
    for char in ("\\", "*", "`", "|", "_"):
        text = text.replace(char, "\\" + char)
    return text


def _list_table(
    title: str,
    header: Sequence[str],
    rows: Iterable[Sequence[str]],
    *,
    widths: str = "",
) -> str:
    """Render a reST ``list-table`` block."""
    out = [f".. list-table:: {title}" if title else ".. list-table::"]
    out.append("   :header-rows: 1")
    if widths:
        out.append(f"   :widths: {widths}")
    out.append("   :class: ngsw-support-table")
    out.append("")
    for row in (header, *rows):
        cells = list(row)
        out.append(f"   * - {cells[0]}")
        out.extend(f"     - {cell}" for cell in cells[1:])
    out.append("")
    return "\n".join(out)


class _GeneratedTable(SphinxDirective):
    """Base: build reST text, then parse it into nodes."""

    has_content = False

    def body(self) -> str:  # pragma: no cover - overridden
        raise NotImplementedError

    def run(self) -> list[nodes.Node]:
        return self.parse_text_to_nodes(self.body(), offset=self.lineno)


class ModelTable(_GeneratedTable):
    """Every registered model and its headline attributes."""

    def body(self) -> str:
        aliases: dict[str, list[str]] = {}
        for alias, canonical in MODEL_ALIASES.items():
            aliases.setdefault(canonical, []).append(alias)
        rows = []
        for key, model in MODELS.items():
            also = aliases.get(key)
            name = f"``{key}``"
            if also:
                name += " (also " + ", ".join(f"``{a}``" for a in sorted(also)) + ")"
            rows.append(
                [
                    name,
                    _rst_escape(model.display_name),
                    model.switch_class.value.replace("_", " "),
                    str(model.port_count),
                    str(model.poe_port_count),
                    ", ".join(b.name for b in backends_for(model)),
                    "live-verified" if model.verified else "**unverified**",
                ]
            )
        return _list_table(
            "",
            [
                "Key",
                "Model",
                "Class",
                "Ports",
                "PoE ports",
                "Backends",
                "Status",
            ],
            rows,
            widths="14 18 14 7 8 22 17",
        )


class ProtocolTable(_GeneratedTable):
    """Model x backend grid."""

    _COLUMNS = (
        Backend.SNMP,
        Backend.NSDP,
        Backend.HTTP,
        Backend.SSH,
        Backend.TELNET,
    )

    def body(self) -> str:
        rows = []
        for key, model in MODELS.items():
            cells = [_YES if b in model.backends else _NO for b in self._COLUMNS]
            rows.append([f"``{key}``", *cells])
        return _list_table(
            "",
            ["Model", *(b.name for b in self._COLUMNS)],
            rows,
            widths="26 12 12 12 12 12",
        )


class OperationTable(_GeneratedTable):
    """Operation x model grid; cells name the backends that serve the op."""

    optional_arguments = 1
    option_spec: ClassVar[dict[str, Any]] = {"kind": directives.unchanged}

    def _operations(self) -> tuple[Any, ...]:
        kind = (self.arguments[0] if self.arguments else "reads").lower()
        if kind.startswith("read"):
            return READ_OPERATIONS
        if kind.startswith("write"):
            return WRITE_OPERATIONS
        raise self.error(f"ngsw-operation-table: unknown kind {kind!r}")

    def body(self) -> str:
        keys = list(MODELS)
        rows = []
        for op in self._operations():
            cells = []
            for key in keys:
                letters = []
                for backend in backends_for(key):
                    if support(key, backend, op).supported:
                        letter = _ABBREV[backend]
                        if letter not in letters:
                            letters.append(letter)
                cells.append(" ".join(letters) if letters else _NO)
            rows.append([f"``{op.name}``", *cells])
        return _list_table("", ["Operation", *keys], rows)


class ModelSupportTable(_GeneratedTable):
    """One model in full: operation x backend, with every refusal explained."""

    required_arguments = 1

    def body(self) -> str:
        key = self.arguments[0]
        model = get_model(key)
        backends = backends_for(model)
        rows = []
        notes: list[str] = []
        seen: dict[str, int] = {}
        for op in (*READ_OPERATIONS, *WRITE_OPERATIONS):
            cells = []
            for backend in backends:
                cap = support(model, backend, op)
                if cap.supported:
                    cells.append(_YES)
                    continue
                reason = _rst_escape(cap.reason)
                index = seen.get(reason)
                if index is None:
                    index = len(notes) + 1
                    seen[reason] = index
                    notes.append(reason)
                marker = _NO if cap.support is Support.UNSUPPORTED else "?"
                # Citation labels, not numbered footnotes: several of these
                # tables share a page, and plain ``[1]`` labels would collide
                # across them. The model key makes each label unique.
                cells.append(f"{marker} [{model.key}-{index}]_")
            rows.append([f"``{op.name}``", op.summary, *cells])

        table = _list_table(
            "",
            ["Operation", "What it does", *(b.name for b in backends)],
            rows,
        )
        if not notes:
            return table
        citations = "\n".join(
            f".. [{model.key}-{i}] {text}" for i, text in enumerate(notes, 1)
        )
        return f"{table}\n{citations}\n"


class SupportGaps(_GeneratedTable):
    """Operations one backend of a model serves and another does not."""

    def body(self) -> str:
        rows = []
        for key in MODELS:
            backends = backends_for(key)
            if len(backends) < 2:
                continue
            for op in (*READ_OPERATIONS, *WRITE_OPERATIONS):
                if op.backends is not None:
                    continue  # fixed-backend ops are not a parity question
                caps = [support(key, b, op) for b in backends]
                yes = [c for c in caps if c.supported]
                no = [c for c in caps if not c.supported]
                if not yes or not no:
                    continue
                rows.append(
                    [
                        f"``{key}``",
                        f"``{op.name}``",
                        ", ".join(sorted({c.backend.name for c in yes})),
                        ", ".join(sorted({c.backend.name for c in no})),
                        _rst_escape(no[0].reason),
                    ]
                )
        if not rows:
            return "Every backend of every model serves the same operations.\n"
        return _list_table(
            "",
            ["Model", "Operation", "Served by", "Not served by", "Why"],
            rows,
            widths="12 16 12 14 46",
        )


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("ngsw-model-table", ModelTable)
    app.add_directive("ngsw-protocol-table", ProtocolTable)
    app.add_directive("ngsw-operation-table", OperationTable)
    app.add_directive("ngsw-model-support", ModelSupportTable)
    app.add_directive("ngsw-support-gaps", SupportGaps)
    return {"version": "1.0", "parallel_read_safe": True, "parallel_write_safe": True}
