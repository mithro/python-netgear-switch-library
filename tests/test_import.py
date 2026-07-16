def test_package_imports_and_has_version():
    import netgear_switch

    assert isinstance(netgear_switch.__version__, str)
    assert netgear_switch.__version__
