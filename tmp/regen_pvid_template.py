"""Regenerate web_gs110emx_templates.PVID_{PREFIX,ROW,SUFFIX} from the capture.

Source: tests/fixtures/http/gs110emx_fw1028_pvid.html (gs110emx1 10.1.5.25,
firmware 1.0.2.8, 2026-10-14). Only the dynamic values become placeholders.
"""

import pathlib
import re

real = pathlib.Path("tests/fixtures/http/gs110emx_fw1028_pvid.html").read_text()
page = real.replace("GAMBITTOKEN", "__GAMBIT__")
row_re = re.compile(
    r'\t\t       <tr class="portID">\n.*?<td class="def" sel="text">(\d+)\n.*?'
    r'<input type="hidden" value="(\d+)">\n.*?'
    r'<td class="def" sel="input">(\d+)</td>\n\t\t         \n',
    re.S,
)
rows = list(row_re.finditer(page))
assert len(rows) == 10, len(rows)
assert all(a.end() == b.start() for a, b in zip(rows, rows[1:], strict=False))
prefix, suffix = page[: rows[0].start()], page[rows[-1].end() :]
first = rows[0]
row = (
    page[first.start() : first.start(1)]
    + "__PORT__"
    + page[first.end(1) : first.start(2)]
    + "__PORT__"
    + page[first.end(2) : first.start(3)]
    + "__PVID__"
    + page[first.end(3) : first.end()]
)
suffix, n = re.subn(r'(id="errMsg" value=")(")', r"\g<1>__ERRMSG__\g<2>", suffix)
assert n == 1
# The rebuilt page must be the capture, byte for byte.
rebuilt = prefix + "".join(
    row.replace("__PORT__", m.group(1)).replace("__PVID__", m.group(3)) for m in rows
) + suffix.replace("__ERRMSG__", "")
assert rebuilt == page

path = pathlib.Path("src/netgear_switch/virtual/web_gs110emx_templates.py")
lines = path.read_text().split("\n")
for name, value in (("PVID_PREFIX", prefix), ("PVID_ROW", row), ("PVID_SUFFIX", suffix)):
    (idx,) = [i for i, ln in enumerate(lines) if ln.startswith(f"{name} = ")]
    lines[idx] = f"{name} = {value!r}"
path.write_text("\n".join(lines))
print("PVID templates regenerated; rebuilt page == capture")
