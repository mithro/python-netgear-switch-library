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

from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar

from docutils.parsers.rst import directives
from sphinx.util import logging
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

logger = logging.getLogger(__name__)

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


def matrix_models() -> tuple[str, ...]:
    """The models the generated tables cover.

    A model registered from a specification sheet with **no device access**
    (``SwitchModel.verified is False``) is deliberately excluded. Listing one in
    a support matrix would assert per-model, per-backend behaviour that nobody
    has ever observed on that hardware -- the exact difference between a
    measurement and an inference this project refuses to blur. They are named in
    prose instead, so their existence is not hidden either.
    """
    return tuple(key for key, model in MODELS.items() if model.verified)


def unverified_models() -> tuple[str, ...]:
    """Registered models with no capture behind them, excluded from the tables."""
    return tuple(key for key, model in MODELS.items() if not model.verified)


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
        for key in matrix_models():
            model = MODELS[key]
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
        for key in matrix_models():
            model = MODELS[key]
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
        keys = list(matrix_models())
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
        for key in matrix_models():
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


_BACKEND_BY_NAME = {b.name: b for b in Backend}

#: CLI is one command surface over three transports, so a "CLI" column means
#: whichever of SSH/TELNET/CONSOLE a model actually registers.
_CLI = (Backend.SSH, Backend.TELNET, Backend.CONSOLE)


def _named_backends(name: str) -> tuple[Backend, ...]:
    key = name.strip().upper()
    if key == "CLI":
        return _CLI
    try:
        return (_BACKEND_BY_NAME[key],)
    except KeyError:
        raise ValueError(f"unknown backend: {name!r}") from None


def _models_with(backends: tuple[Backend, ...]) -> tuple[str, ...]:
    return tuple(
        key
        for key in matrix_models()
        if any(b in MODELS[key].backends for b in backends)
    )


class BackendModelTable(_GeneratedTable):
    """Which models expose one backend, and how they are reached."""

    required_arguments = 1

    def body(self) -> str:
        backends = _named_backends(self.arguments[0])
        rows = []
        for key in _models_with(backends):
            model = MODELS[key]
            reached = ", ".join(
                b.name for b in backends_for(model) if b in backends
            )
            rows.append(
                [
                    # Absolute doc path: this table is included from
                    # docs/protocols/, so a relative target would resolve there.
                    f":doc:`{key} </models/{key}>`",
                    _rst_escape(model.display_name),
                    model.switch_class.value.replace("_", " "),
                    str(model.port_count),
                    reached,
                ]
            )
        if not rows:
            return "No registered model exposes this backend.\n"
        return _list_table(
            "",
            ["Model", "Product", "Class", "Ports", "Reached over"],
            rows,
            widths="16 24 18 10 32",
        )


class BackendOperationTable(_GeneratedTable):
    """Operation x model grid for ONE backend: what it can do, where."""

    required_arguments = 1

    def body(self) -> str:
        backends = _named_backends(self.arguments[0])
        keys = _models_with(backends)
        if not keys:
            return "No registered model exposes this backend.\n"
        rows = []
        notes: list[str] = []
        seen: dict[str, int] = {}
        label = self.arguments[0].strip().upper()
        for op in (*READ_OPERATIONS, *WRITE_OPERATIONS):
            cells = []
            for key in keys:
                backend = next(
                    (b for b in backends_for(key) if b in backends), None
                )
                if backend is None:  # pragma: no cover - filtered by _models_with
                    cells.append(_NO)
                    continue
                cap = support(key, backend, op)
                if cap.supported:
                    cells.append(_YES)
                    continue
                reason = _rst_escape(cap.reason)
                index = seen.get(reason)
                if index is None:
                    index = len(notes) + 1
                    seen[reason] = index
                    notes.append(reason)
                cells.append(f"{_NO} [{label}-{index}]_")
            # The facade class is documented under its defining module, so a
            # `netgear_switch.SyncSwitch.x` target does not resolve and would
            # render as plain text rather than a link.
            rows.append(
                [f":py:meth:`~netgear_switch.sync_api.SyncSwitch.{op.name}`", *cells]
            )
        table = _list_table("", ["Operation", *keys], rows)
        if not notes:
            return table
        citations = "\n".join(
            f".. [{label}-{i}] {text}" for i, text in enumerate(notes, 1)
        )
        return f"{table}\n{citations}\n"


class ModelFacts(_GeneratedTable):
    """The registry record for one model, as a field list."""

    required_arguments = 1

    def body(self) -> str:
        model = get_model(self.arguments[0])
        aliases = sorted(k for k, v in MODEL_ALIASES.items() if v == model.key)
        vendor = model.snmp_vendor_base or "none (standard MIBs only)"
        dialect = {
            "qbridge": "Q-BRIDGE static PortLists (read-modify-write)",
            "fastpath_switchport": "FASTPATH vendor switchport table",
        }.get(model.snmp_vlan_write, model.snmp_vlan_write)
        rows = [
            ["Registry key", f"``{model.key}``"],
            ["Product name", _rst_escape(model.display_name)],
            ["Class", model.switch_class.value.replace("_", " ")],
            ["Ports", str(model.port_count)],
            ["PoE (PSE) ports", str(model.poe_port_count)],
            [
                "Backends",
                ", ".join(f"``{b.name}``" for b in backends_for(model)),
            ],
            ["SNMP vendor subtree", f"``{vendor}``"],
        ]
        if Backend.SNMP in model.backends:
            rows.append(["VLAN write dialect", dialect])
            if model.snmp_vlan_split_membership_writes:
                rows.append(
                    [
                        "VLAN write quirk",
                        "egress and untagged PortLists must travel in "
                        "SEPARATE PDUs, egress first",
                    ]
                )
        if aliases:
            rows.append(
                ["Aliases", ", ".join(f"``{a}``" for a in aliases)]
            )
        rows.append(
            [
                "MAC/FDB table",
                "yes" if model.has_mac_table else "no",
            ]
        )
        return _list_table("", ["Field", "Value"], rows, widths="30 70")


class ModelPhoto(_GeneratedTable):
    """Render a photo of the switch, if one has been added to the repository.

    Photos live at ``docs/_static/models/<key>.<ext>``. Nothing is emitted when
    the file is absent -- a missing photo must not render as a broken image --
    and every gap is reported once at the end of the build.
    """

    required_arguments = 1
    option_spec: ClassVar[dict[str, Any]] = {"alt": directives.unchanged}

    _EXTENSIONS = (".jpg", ".jpeg", ".png", ".webp")

    def body(self) -> str:
        key = self.arguments[0]
        model = get_model(key)
        static = Path(str(self.env.srcdir)) / "_static" / "models"
        for ext in self._EXTENSIONS:
            if (static / f"{key}{ext}").is_file():
                alt = self.options.get("alt", f"{model.display_name} switch")
                return (
                    f".. figure:: /_static/models/{key}{ext}\n"
                    f"   :alt: {alt}\n"
                    "   :align: center\n"
                    "   :class: ngsw-model-photo\n\n"
                    f"   {_rst_escape(model.display_name)}\n"
                )
        MISSING_PHOTOS.add(key)
        return ""


#: Models whose photo slot was empty during this build; reported at the end.
MISSING_PHOTOS: set[str] = set()


class UnverifiedNote(_GeneratedTable):
    """Name the models the tables leave out, and say why."""

    def body(self) -> str:
        keys = unverified_models()
        if not keys:
            return ""
        listed = ", ".join(f"``{k}`` ({MODELS[k].display_name})" for k in keys)
        return (
            ".. note::\n\n"
            f"   The registry also carries {listed}, which the tables above "
            "deliberately leave out.\n"
            "   No device of either kind has ever been reachable from this "
            "project, so there is no\n"
            "   capture, no live run, and nothing measured to report. They are "
            "registered only so a\n"
            "   caller can construct a facade for them; treat every one of "
            "their fields as a\n"
            "   specification-sheet guess until a real capture exists.\n"
        )


def _report_missing_photos(app: Sphinx, exception: Exception | None) -> None:
    """Say which model pages have no photo yet, rather than failing the build.

    A photo is content the repository may simply not have; the build must not
    break over it, but the gap should be visible instead of silently invisible.
    """
    if exception is not None or not MISSING_PHOTOS:
        return
    logger.info(
        "ngsw: no photo for %d model(s): %s "
        "(add docs/_static/models/<key>.jpg to fill the slot)",
        len(MISSING_PHOTOS),
        ", ".join(sorted(MISSING_PHOTOS)),
    )


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("ngsw-unverified-note", UnverifiedNote)
    app.add_directive("ngsw-model-table", ModelTable)
    app.add_directive("ngsw-protocol-table", ProtocolTable)
    app.add_directive("ngsw-operation-table", OperationTable)
    app.add_directive("ngsw-model-support", ModelSupportTable)
    app.add_directive("ngsw-model-facts", ModelFacts)
    app.add_directive("ngsw-model-photo", ModelPhoto)
    app.add_directive("ngsw-backend-models", BackendModelTable)
    app.add_directive("ngsw-backend-operations", BackendOperationTable)
    app.add_directive("ngsw-support-gaps", SupportGaps)
    app.connect("build-finished", _report_missing_photos)
    return {"version": "1.0", "parallel_read_safe": True, "parallel_write_safe": True}
