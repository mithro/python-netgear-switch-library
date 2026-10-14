"""Regenerate web_gs110emx_templates.VLANMEM_PAGE from the real capture.

Source: tests/fixtures/http/gs110emx_fw1028_vlanmembership_vlan4.html
(gs110emx1 10.1.5.25, firmware 1.0.2.8, 2026-10-14). Only the dynamic values
are swapped for placeholders; every other byte is the device's.
"""

import pathlib
import re

real = pathlib.Path(
    "tests/fixtures/http/gs110emx_fw1028_vlanmembership_vlan4.html"
).read_text()


def swap(pattern: str, repl: str, text: str) -> str:
    out, n = re.subn(pattern, repl, text, flags=re.S)
    assert n == 1, (pattern, n)
    return out


page = real.replace("GAMBITTOKEN", "__GAMBIT__")
page = swap(r'(?:<option value = "\d+">\d+ </option>\n)+', "__VLAN_OPTIONS__", page)
page = swap(r'(name="vlanIdSel" value=")\d+(")', r"\g<1>__VLAN_SHOWN__\g<2>", page)
page = swap(
    r"(?:<div class='portMember margin'><span class='portword'>\d+</span>"
    r"<div class='panels'><div class='portImage \w+'></div></div></div>\n)+",
    "__PORT_IMAGES__",
    page,
)
page = swap(r'(id="hiddenMem" value=")\d+(")', r"\g<1>__HIDDENMEM__\g<2>", page)
page = swap(r'(id="errMsg" value=")(")', r"\g<1>__ERRMSG__\g<2>", page)

path = pathlib.Path("src/netgear_switch/virtual/web_gs110emx_templates.py")
lines = path.read_text().split("\n")
(idx,) = [i for i, ln in enumerate(lines) if ln.startswith("VLANMEM_PAGE = ")]
lines[idx] = f"VLANMEM_PAGE = {page!r}"
path.write_text("\n".join(lines))
print(f"VLANMEM_PAGE regenerated: {len(page)} chars")
for marker in re.findall(r"__[A-Z_]+__", page):
    print("  ", marker)
