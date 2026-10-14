"""Give the mock's GS110EMX login page its error slot and add the bounce page.

Checks the result against the real captures (10.1.5.25, firmware 1.0.2.8,
2026-10-14): the login page as served with the session table full, and the
298-byte page any request with an unknown token gets.
"""

import pathlib
import re
import sys

sys.path.insert(0, "src")
from netgear_switch.virtual import web_gs110emx_templates as t  # noqa: E402

fix = pathlib.Path("tests/fixtures/http")
full = (fix / "gs110emx_fw1028_login_sessions_full.html").read_text()
lost = (fix / "gs110emx_fw1028_session_lost.html").read_text()

slot = '<p id="login_err_msg" style="margin:0;"></p>'
assert t.LOGIN.count(slot) == 1
login = t.LOGIN.replace(slot, '<p id="login_err_msg" style="margin:0;">__LOGIN_ERR__</p>')
rand = re.search(r"id='rand' value=\"(\d+)\"", full).group(1)
said = "Maximum number of sessions reached... Try After Some Time"
rendered = login.replace("__RAND__", rand).replace("__LOGIN_ERR__", said)
print("login page with the table full == capture:", rendered == full)
if rendered != full:
    for i, (a, b) in enumerate(zip(rendered, full, strict=False)):
        if a != b:
            print("  first difference at", i, repr(rendered[i - 40 : i + 40]))
            print("                 capture", repr(full[i - 40 : i + 40]))
            break
    print("  lengths", len(rendered), len(full))

path = pathlib.Path("src/netgear_switch/virtual/web_gs110emx_templates.py")
lines = path.read_text().split("\n")
(idx,) = [i for i, ln in enumerate(lines) if ln.startswith("LOGIN = ")]
lines[idx] = f"LOGIN = {login!r}"
(ridx,) = [i for i, ln in enumerate(lines) if ln.startswith("REDIRECT = ")]
lines.insert(ridx + 1, "")
lines.insert(ridx + 2, f"SESSION_LOST = {lost!r}")
path.write_text("\n".join(lines))
print("templates updated")
