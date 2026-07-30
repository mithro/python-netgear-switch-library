# python-netgear-switch-library — working agreement

These are **non-negotiable design principles** for this library. They override
convenience, they override "it works on my switch", and they override any
temptation to declare something unsupported. Each one is written here because it
was violated in practice — the concrete example is included so the rule is not
abstract.

Anything that contradicts a principle below needs an explicit, recorded decision
from the repository owner. "I couldn't get it working" is not such a decision.

---

## 1. Fail fast and loud. Never paper over a problem.

If an operation cannot be performed as asked, **raise** — immediately, with the
detail needed to debug it (which backend, which OID/URL/command, what the device
answered). Never substitute a different behaviour to make a call appear to
succeed.

**Specifically forbidden: switching protocol/backend mid-operation.** A caller
who asks for SNMP gets SNMP or an error. Silently retrying over HTTP is not
robustness, it is data loss disguised as success.

*Why this exists:* `SyncSwitch._read`/`_write` used to loop over
`SNMP > NSDP > HTTP` and silently return the next backend's answer when one
raised `UnsupportedCapabilityError`. That fallback concealed a real defect for
months — `HttpReader.get_vlans()` returns no untagged ports at all on the managed
switches, and nobody saw it because SNMP quietly answered in its place. Worse,
every past "HTTP verified" claim became untrustworthy, because the HTTP path may
never have run. On a write it is worse still: an operator who deliberately
restricts SNMP write access could have their change pushed over another protocol
without being told.

Corollaries:
- Verification must drive one backend **directly**. A cross-backend comparison is
  only evidence if each backend answered on its own merits.
- A degraded or partial result is a failure. Do not return `[]`, `None` or a
  silently-truncated value where the caller asked a question you could not answer.
- Errors must name the thing that failed. `commitFailed` on which OID, with which
  value, for which model.

## 2. Backends must have feature parity.

Every backend a model supports (SNMP / NSDP / HTTP / CLI) must offer the **same
functionality**. The point of having several is that the *caller* chooses — for
example when SNMP writes are locked down, or when the web UI is the only thing
reachable through a firewall. That choice only exists if the backends are
equivalent.

A backend missing an operation is a **missing implementation**, to be built. It
is not a device limitation until proven otherwise (see principle 4). Only the
repository owner may exempt a specific backend/operation, and the exemption must
be recorded in the code with the reason.

*Why this exists:* `vlan_membership_path=None  # vlanStatus carries the egress
list inline` was left on every managed switch, so HTTP could neither report
tagged/untagged membership nor write membership at all — while the same file
already had the working `/iss/specific/vlanMembership.html` path for a sibling
model. Likewise there was no CLI write backend whatsoever, even though the
FASTPATH command sequences work (they were driven by hand on an M4300 to prove
it).

## 3. Every switch model, not just the one in front of you.

A feature is not done when it works on one switch. It is done when it works on
**every** registered model, verified against every reachable one. All models have
feature parity unless the repository owner explicitly exempts one, with the reason
recorded in the registry entry.

When you implement or fix something, enumerate the models it applies to and check
each. Firmware differs between SKUs of the *same* family — do not extrapolate.

*Why this exists:* the M4300-16X was marked `snmp_vlan_write="fastpath_switchport"`
purely by inference from the M4300-24X ("same firmware family"). It runs different
firmware (12.0.19.15 vs 12.0.13.8) and actually **accepts** the Q-BRIDGE writes the
-24X refuses. The inference was wrong and would have stayed wrong.

## 4. A failure is something you did wrong.

Not flaky hardware. Not "the switch is slow". Not a timeout that will pass. Before
you even consider blaming the device, answer all of these:

- **Have you actually debugged it,** or just observed it fail? What does the device
  say when you ask it directly (its CLI, its web UI, its own config dump)?
- **Is another setting required first?** Some writes are gated by other state.
- **Are you sending the wrong details?** Wrong community, username, password,
  port, value type, encoding, field width, or **ordering** of operations.
- **Did you try every mechanism the device exposes,** or only the first one you
  thought of?

Only after that, and only with captured device output quoted as proof, may a
limitation be recorded — and it must name the firmware version it applies to.

*Why this exists,* three times over in one session:
- "The S3300's SNMP agent is dead / timing out." It was not. The switch has no
  `private` community (`show snmpcommunity` lists `pib` and `public`, both
  Read/Write). An agent **silently drops** an unauthorized request, so a wrong
  write community looks exactly like an unreachable host. Reads worked the whole
  time. Wrong credential, blamed on hardware.
- "The M4300 refuses VLAN writes." It does not. One OID was tried; the switch's
  own vendor switchport table accepts membership writes. Never enumerating what
  the device published, blamed on firmware.
- "The S3300 forces untagged membership." It does not. Setting the egress bit
  auto-untags the port, and that side effect beats an untagged varbind in the
  **same PDU**; two PDUs, egress first, work perfectly. Wrong ordering, blamed on
  firmware.

## 5. The fake must behave like the real hardware. When it differs, fix the fake.

The virtual switch (`src/netgear_switch/virtual/`) exists so this library can be
tested honestly without hardware. That only works if it is a **faithful** model of
the real devices — including their refusals, their quirks and their ordering
requirements, not just their happy paths.

Therefore:
- When live hardware behaves differently from the mock, **the mock is wrong** and
  must be corrected to match the device. Never adjust a test's expectation to
  match a mock you already know is unfaithful, and never "fix" a divergence by
  making the real-hardware path lenient.
- The mock must reproduce **rejections** as faithfully as successes: the right SMI
  error-status (`commitFailed` vs `notWritable` vs `wrongValue`), the same
  preconditions, the same side effects, the same ordering sensitivity.
- The mock must be an **independent** source of truth. If it derives a value using
  the same formula as the code under test, it can only ever agree with that code
  and proves nothing. Seed measured device values instead of computing them.
- Every behaviour learned from hardware gets encoded in the mock **and** pinned by
  a test in the same change, with a comment naming the host and firmware it was
  observed on. A finding that is not in the mock will be regressed later.

*Why this exists:* the VLAN PortList-width defect went unnoticed because the mock
emitted the bitmap using `vlan_bitmap_width(model)` — the exact same wrong formula
the buggy writer used — so mock and code agreed with each other while both
disagreed with every real switch (whose widths are 79 / 131 / 45 bytes, none of
them derivable from the port count). The round trip was green and meaningless.

---

## Practical rules that follow

- **Ground everything in real devices.** Fixtures come from captured
  traffic/pages, never from imagination or from a MIB's ideal semantics.
- **Diff the device, don't guess the MIB.** To learn how something is configured:
  capture a full walk to a file, change the setting through the switch's own
  UI/CLI, walk again, diff. That is how the vendor switchport table was found with
  no MIB file available.
- **Never leave a device changed.** Record the exact prior state, use throwaway
  VLAN ids and ports that are link-down and undescribed, restore, and prove the
  restore by re-reading. Never persist config (`write memory`) during testing.
- **Say what you actually verified.** Distinguish "live-verified on host X,
  firmware Y" from "assumed". Never round an inference up to a fact.

---

## If you are a dispatched subagent

The five principles above bind you exactly as they bind the main session. In
particular:

- **Never declare an operation unsupported to finish your task.** If you cannot
  implement something, say so plainly in your report — naming the model, backend
  and operation — and leave no `raise UnsupportedCapabilityError` behind that
  lacks captured device output as proof. An honest "not done, here's why" is
  wanted; a false "the hardware can't" is not.
- **Implement across all backends and all models,** or state precisely which
  combinations remain. Do not extrapolate one SKU's behaviour to its siblings.
- **Verify by driving one backend directly**, never through a facade that might
  substitute another — otherwise your PASS may be a different protocol answering.
- **Encode what you learn from hardware into the virtual switch, plus a test**,
  naming the host and firmware version in a comment. A finding that lives only in
  your report will be regressed by the next change.

### Live-hardware rules (absolute)

- Credentials come from `sudo -n .venv/bin/gdoc2netcfg password --type password -q
  <host>` run from `/opt/gdoc2netcfg`. **Never print a credential.**
- Use throwaway VLAN ids in the 4001-4008 range, coordinated so concurrent agents
  do not collide.
- Touch only a port that is **link-down** AND whose description is empty or
  `'empty'`. Never a described production port.
- **Record the exact prior state, restore it, and prove the restore by
  re-reading.** Never `write memory` / save configuration.

### Running things on this machine

It OOMs easily: `PYTHONPATH=src .venv/bin/python -m pytest <specific file> -q
--no-cov`, one pytest process at a time, never the full suite. `uv run ruff check
src/ tests/` and `uv run mypy` must both be clean. Never use `2>/dev/null` (a hook
blocks it). Prefer Python over involved shell.
