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

from docutils import nodes
from docutils.parsers.rst import directives
from sphinx.transforms.post_transforms import SphinxPostTransform
from sphinx.util import logging
from sphinx.util.docutils import SphinxDirective
from sphinx.util.nodes import make_refnode

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


#: The page documenting each backend. SSH, TELNET and CONSOLE are three
#: transports over one command surface, so all three land on the CLI page.
_BACKEND_PAGES = {
    Backend.SNMP: "protocols/snmp",
    Backend.NSDP: "protocols/nsdp",
    Backend.HTTP: "protocols/http",
    Backend.SSH: "protocols/cli",
    Backend.TELNET: "protocols/cli",
    Backend.CONSOLE: "protocols/cli",
}

#: Literal text -> the page that documents it. Everything a generated table or a
#: docstring can name: every model key, every alias, every backend name, and
#: ``CLI`` for the command surface as a whole.
_LINKABLE: dict[str, str] = {
    **{key: f"models/{key}" for key in MODELS},
    **{alias: f"models/{key}" for alias, key in MODEL_ALIASES.items()},
    **{backend.name: page for backend, page in _BACKEND_PAGES.items()},
    "CLI": "protocols/cli",
}


class ReferenceLinks(SphinxPostTransform):
    """Link every inline literal that names something this documentation defines.

    Three kinds of name are resolved, in order: a switch model key or alias, a
    backend name, and any Python object autodoc has documented (matched on its
    full dotted path, so there is no ambiguity to guess at).

    Doing this in a post-transform rather than at each use is what makes the
    linking total, and it exists because per-use linking kept missing cases:

    * The generated tables wrote a model key as a bare literal in three of the
      seven builders, so ``docs/models/index.rst`` listed eight model keys and
      linked none of them, while the protocol pages linked theirs.
    * ``conf.py`` sets ``default_role = "literal"``, so every single-backtick
      name renders as text. The module lists at the bottom of each protocol
      page are written that way -- ```netgear_switch.http_read``` -- and were
      silently not links, even though the class names beside them, written with
      an explicit role, were.

    Neither failure could be caught by ``nitpicky``: an unresolved *reference*
    fails the build, but a literal that should have been a reference is
    indistinguishable from ordinary text. Only linking them automatically
    closes that gap.

    Matching is exact and confined to inline literals, so prose about "the HTTP
    backend" is untouched while ``` ``HTTP`` ``` becomes a link.
    """

    # After filelinks' post-transform (400), whose repository links are already
    # `reference` nodes by this point and are skipped below.
    default_priority = 410

    #: The facade a bare operation name should resolve to when several classes
    #: define it. ``get_vlans`` is documented on nine classes -- both facades and
    #: every reader -- and the one a reader of prose means is the public
    #: synchronous entry point.
    _PREFERRED_OWNER = "netgear_switch.sync_api.SyncSwitch."

    def _short_index(self) -> dict[str, list[str]]:
        """Last path component -> the full names that end with it."""
        objects = self.env.domaindata.get("py", {}).get("objects", {})
        index: dict[str, list[str]] = {}
        for name, entry in objects.items():
            if getattr(entry, "aliased", False):
                continue  # a duplicate of the canonical entry
            index.setdefault(name.rsplit(".", 1)[-1], []).append(name)
        return index

    def _python_target(self, text: str) -> tuple[str, str] | None:
        """``(docname, node_id)`` for a documented Python object, if any.

        An exact dotted path always wins. A bare name is resolved only when it
        is shaped like an API name -- CamelCase, SCREAMING_CASE or containing an
        underscore -- and resolves unambiguously, or to the preferred facade.

        The shape test is what keeps the linking honest. ``port``, ``name``,
        ``host`` and ``model`` are all documented dataclass fields *and* ordinary
        words that appear as literals throughout these docstrings; linking every
        occurrence to one arbitrary dataclass would be worse than not linking.
        """
        objects = self.env.domaindata.get("py", {}).get("objects", {})
        entry = objects.get(text)
        if entry is not None:
            return entry.docname, entry.node_id
        if not ("_" in text or (text[:1].isupper() and text.isalnum())):
            return None
        candidates = self._short_index().get(text)
        if not candidates:
            return None
        if len(candidates) > 1:
            preferred = [c for c in candidates if c.startswith(self._PREFERRED_OWNER)]
            if len(preferred) != 1:
                return None
            candidates = preferred
        entry = objects[candidates[0]]
        return entry.docname, entry.node_id

    def run(self, **kwargs: Any) -> None:
        counts = self.env.domaindata.setdefault("ngsw_reflinks", {"linked": 0})
        for node in list(self.document.findall(nodes.literal)):
            if isinstance(node.parent, nodes.reference):
                continue  # already a link (a resolved xref, or filelinks')
            if "xref" in node["classes"]:
                continue  # an unresolved cross-reference, not a plain literal
            text = node.astext().strip()

            docname = _LINKABLE.get(text)
            if docname is not None and docname in self.env.found_docs:
                node_id = ""
            else:
                found = self._python_target(text)
                if found is None:
                    continue
                docname, node_id = found

            # A page linking to itself is noise; an anchor on the same page is
            # not -- it jumps to the definition.
            if docname == self.env.docname and not node_id:
                continue
            link = make_refnode(
                self.app.builder,
                self.env.docname,
                docname,
                node_id or None,
                node.deepcopy(),
            )
            link["classes"].append("ngsw-ref")
            node.replace_self(link)
            counts["linked"] += 1


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
    classes: Sequence[str] = (),
) -> str:
    """Render a reST ``list-table`` block.

    No ``:widths:`` is emitted, deliberately. ``docs/_static/ngsw.css`` gives
    these tables ``white-space: nowrap`` inside a horizontally scrolling box,
    so the browser's own table layout sizes every column to its content --
    which is always right, and cannot go stale the way a hand-picked
    percentage does when a model name or a backend list changes.

    ``classes`` adds CSS classes beyond ``ngsw-support-table``. Only a table
    whose last column holds prose wants ``ngsw-reason-table``.
    """
    out = [f".. list-table:: {title}" if title else ".. list-table::"]
    out.append("   :header-rows: 1")
    out.append("   :class: " + " ".join(("ngsw-support-table", *classes)))
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
                    ", ".join(f"``{b.name}``" for b in backends_for(model)),
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
            ["Model", *(f"``{b.name}``" for b in self._COLUMNS)],
            rows,
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
            ["Operation", "What it does", *(f"``{b.name}``" for b in backends)],
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
            classes=("ngsw-reason-table",),
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
                f"``{b.name}``" for b in backends_for(model) if b in backends
            )
            rows.append(
                [
                    f"``{key}``",
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
                backend = next((b for b in backends_for(key) if b in backends), None)
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
            rows.append(["Aliases", ", ".join(f"``{a}``" for a in aliases)])
        rows.append(
            [
                "MAC/FDB table",
                "yes" if model.has_mac_table else "no",
            ]
        )
        return _list_table("", ["Field", "Value"], rows)


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


class ModelDiagram(_GeneratedTable):
    """A schematic port map for one model, drawn from the registry.

    Not a photograph and not a faceplate: it shows the ports *as this library
    addresses them*, which is the thing a caller actually needs when deciding
    what to pass as ``port=``. Generated from ``port_count`` and
    ``poe_port_count``, so it cannot drift from the registry -- and so it never
    asserts a physical arrangement nobody measured.
    """

    required_arguments = 1

    _COLS = 26
    _BOX = 26
    _GAP = 4

    def body(self) -> str:
        model = get_model(self.arguments[0])
        total, poe = model.port_count, model.poe_port_count
        step = self._BOX + self._GAP
        rows = (total + self._COLS - 1) // self._COLS
        width = min(total, self._COLS) * step + self._GAP
        height = rows * step + self._GAP + 22

        parts = [
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
            f'role="img" aria-label="Port map: {total} ports, {poe} with PoE" '
            'style="max-width:100%;height:auto">'
        ]
        for index in range(total):
            port = index + 1
            col, row = index % self._COLS, index // self._COLS
            x = self._GAP + col * step
            y = self._GAP + row * step
            # PoE ports come first on every model in this registry; anything
            # beyond that count is drawn as a plain (usually uplink) port.
            fill = "#2b6cb0" if port <= poe else "#a0aec0"
            parts.append(
                f'<rect x="{x}" y="{y}" width="{self._BOX}" height="{self._BOX}" '
                f'rx="3" fill="{fill}"/>'
                f'<text x="{x + self._BOX / 2}" y="{y + self._BOX / 2 + 4}" '
                'font-size="10" text-anchor="middle" fill="#fff" '
                f'font-family="monospace">{port}</text>'
            )
        legend_y = rows * step + self._GAP + 14
        parts.append(
            f'<rect x="4" y="{legend_y - 9}" width="11" height="11" rx="2" '
            'fill="#2b6cb0"/>'
            f'<text x="20" y="{legend_y}" font-size="11" fill="currentColor">'
            f"PoE ({poe})</text>"
            f'<rect x="86" y="{legend_y - 9}" width="11" height="11" rx="2" '
            'fill="#a0aec0"/>'
            f'<text x="102" y="{legend_y}" font-size="11" fill="currentColor">'
            f"no PoE ({total - poe})</text>"
        )
        parts.append("</svg>")
        svg = "".join(parts)
        return (
            ".. raw:: html\n\n"
            f'   <figure class="ngsw-port-map">{svg}'
            "<figcaption>Port map as the library addresses these ports — "
            "schematic, not a faceplate layout.</figcaption></figure>\n"
        )


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


def _report_reference_links(app: Sphinx, exception: Exception | None) -> None:
    if exception is not None:
        return
    linked = app.env.domaindata.get("ngsw_reflinks", {}).get("linked", 0)
    logger.info("ngsw: linked %d model/backend/API reference(s)", linked)


def setup(app: Sphinx) -> dict[str, Any]:
    app.add_directive("ngsw-unverified-note", UnverifiedNote)
    app.add_directive("ngsw-model-table", ModelTable)
    app.add_directive("ngsw-protocol-table", ProtocolTable)
    app.add_directive("ngsw-operation-table", OperationTable)
    app.add_directive("ngsw-model-support", ModelSupportTable)
    app.add_directive("ngsw-model-facts", ModelFacts)
    app.add_directive("ngsw-model-photo", ModelPhoto)
    app.add_directive("ngsw-model-diagram", ModelDiagram)
    app.add_directive("ngsw-backend-models", BackendModelTable)
    app.add_directive("ngsw-backend-operations", BackendOperationTable)
    app.add_directive("ngsw-support-gaps", SupportGaps)
    app.add_post_transform(ReferenceLinks)
    app.connect("build-finished", _report_missing_photos)
    app.connect("build-finished", _report_reference_links)
    return {"version": "1.0", "parallel_read_safe": True, "parallel_write_safe": True}
