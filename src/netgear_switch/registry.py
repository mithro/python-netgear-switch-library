"""Declarative registry of known Netgear switch models."""

from __future__ import annotations

import enum
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING

from .errors import UnknownModelError

if TYPE_CHECKING:
    from collections.abc import Mapping

_FM = "1.3.6.1.4.1.4526.10"   # Fully Managed vendor subtree (M4300, GSM7252PS)
_SMP = "1.3.6.1.4.1.4526.11"  # Smart Managed Pro vendor subtree (S3300/GSM7228PS)


class Backend(enum.Enum):
    SNMP = "snmp"
    NSDP = "nsdp"
    HTTP = "http"


class SwitchClass(enum.Enum):
    FULLY_MANAGED = "fully_managed"
    SMART_MANAGED_PRO = "smart_managed_pro"
    PLUS = "plus"


@dataclass(frozen=True)
class SwitchModel:
    key: str
    display_name: str
    switch_class: SwitchClass
    port_count: int
    poe_port_count: int
    backends: frozenset[Backend]
    snmp_vendor_base: str | None

    @property
    def has_mac_table(self) -> bool:
        # MAC/FDB table is only reachable via SNMP (managed switches).
        return Backend.SNMP in self.backends


def _model(
    key: str,
    display_name: str,
    switch_class: SwitchClass,
    port_count: int,
    poe_port_count: int,
    backends: set[Backend],
    snmp_vendor_base: str | None,
) -> SwitchModel:
    return SwitchModel(
        key=key,
        display_name=display_name,
        switch_class=switch_class,
        port_count=port_count,
        poe_port_count=poe_port_count,
        backends=frozenset(backends),
        snmp_vendor_base=snmp_vendor_base,
    )


_MODELS: dict[str, SwitchModel] = {
    m.key: m
    for m in (
        _model(
            "m4300-24x",
            "M4300-24X (XSM4324CS)",
            SwitchClass.FULLY_MANAGED,
            28,
            0,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "m4300-16x",
            "M4300-16X (XSM4316)",
            SwitchClass.FULLY_MANAGED,
            16,
            16,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "gsm7252ps",
            "GSM7252PS",
            SwitchClass.FULLY_MANAGED,
            52,
            48,
            {Backend.SNMP},
            _FM,
        ),
        _model(
            "gsm7228ps",
            "GSM7228PS (S3300)",
            SwitchClass.SMART_MANAGED_PRO,
            52,
            48,
            {Backend.SNMP, Backend.HTTP},
            _SMP,
        ),
        _model(
            "gs110emx",
            "GS110EMX",
            SwitchClass.PLUS,
            10,
            0,
            {Backend.NSDP, Backend.HTTP},
            None,
        ),
        _model(
            "gs305ep",
            "GS305EP",
            SwitchClass.PLUS,
            5,
            4,
            {Backend.NSDP, Backend.HTTP},
            None,
        ),
    )
}

MODELS: Mapping[str, SwitchModel] = MappingProxyType(_MODELS)


def get_model(key: str) -> SwitchModel:
    try:
        return _MODELS[key]
    except KeyError:
        raise UnknownModelError(f"unknown switch model: {key!r}") from None
