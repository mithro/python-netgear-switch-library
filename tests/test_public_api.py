def test_public_types_importable_from_top_level():
    import netgear_switch as ns

    for name in ns.__all__:
        assert hasattr(ns, name), name
    # spot-check a few are the real objects
    assert ns.get_model("gsm7252ps").has_mac_table is True
    assert ns.PoEDetect.DELIVERING.value == "delivering"


def test_facades_exported_from_top_level():
    import netgear_switch as ns

    assert "SyncSwitch" in ns.__all__
    assert "AsyncSwitch" in ns.__all__
    assert ns.SyncSwitch is not None
    assert ns.AsyncSwitch is not None
    # Constructible from a model without touching the network.
    sw = ns.SyncSwitch(ns.get_model("gsm7252ps"), "host", snmp_community="public")
    assert sw.model.key == "gsm7252ps"
