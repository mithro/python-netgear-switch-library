def test_public_types_importable_from_top_level():
    import netgear_switch as ns

    for name in ns.__all__:
        assert hasattr(ns, name), name
    # spot-check a few are the real objects
    assert ns.get_model("gsm7252ps").has_mac_table is True
    assert ns.PoEDetect.DELIVERING.value == "delivering"
