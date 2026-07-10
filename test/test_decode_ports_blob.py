"""Unit tests for ModuleBuilder._decode_ports_blob.

A genuinely pure staticmethod (topology XML string -> L5X <Ports> string), so
it tests with synthetic blobs and no ACD.  Pins the port-topology rules the
five newest commits landed (eeed1a1..58a0c37) ahead of the P5 extraction of
the module domain into its own module.
"""

from acd.l5x.elements import ModuleBuilder

decode = ModuleBuilder._decode_ports_blob


def test_ethernet_expansion_and_bus_size_kept():
    out = decode(
        '<in><Port Id="1" Type="EN" Addr="192.168.1.1">'
        '<Bus Max="17" Size="4"/></Port></in>'
    )
    # EN -> Ethernet, Addr -> Address, Ups absent => Upstream true,
    # Bus Size kept but Max dropped.
    assert out == (
        '<Ports>\n'
        '<Port Id="1" Address="192.168.1.1" Type="Ethernet" Upstream="true">\n'
        '<Bus Size="4"/>\n</Port>\n'
        '</Ports>\n'
    )


def test_upstream_false_lowercased_and_downstream_bridge_empty_bus():
    out = decode('<in><Port Id="2" Type="EN" Ups="False"/></in>')
    assert out == (
        '<Ports>\n'
        '<Port Id="2" Type="Ethernet" Upstream="false">\n<Bus/>\n</Port>\n'
        '</Ports>\n'
    )


def test_bus_without_size_emits_empty_bus():
    out = decode('<in><Port Id="1" Type="ICP"><Bus Max="10"/></Port></in>')
    assert '<Bus/>' in out and 'Size' not in out


def test_ports_sorted_ascending_by_id():
    out = decode(
        '<in><Port Id="3" Type="ICP"/>'
        '<Port Id="1" Type="EN" Addr="0"><Bus Size="7"/></Port></in>'
    )
    assert out.index('Id="1"') < out.index('Id="3"')


def test_missing_id_bails_to_none():
    # A port with no Id uses a structure this decoder doesn't model; bail so the
    # caller falls back to the static catalog instead of emitting Id="None".
    assert decode('<in><Port Type="EN"/></in>') is None


def test_no_ports_returns_none():
    assert decode('<in></in>') is None


def test_safety_network_attribute_placement():
    sn = "16#0000_1111_2222_3333"
    out = decode('<in><Port Id="2" Type="EN" Addr="1.2.3.4"/></in>', {2: sn})
    assert f' SafetyNetwork="{sn}"' in out
    # SafetyNetwork follows Upstream in OEM ordering.
    assert out.index("Upstream=") < out.index("SafetyNetwork=")


def test_safety_network_absent_when_not_mapped():
    out = decode('<in><Port Id="2" Type="EN"/></in>', {2: ""})
    assert "SafetyNetwork" not in out


def test_compactlogix_embedded_cpu_gets_empty_bus():
    out = decode('<in><Port Id="1" Type="Cpt32E" Ups="False"/></in>')
    assert 'Type="CompactLogixL32EController"' in out
    assert '<Bus/>' in out


def test_address_omitted_when_absent():
    out = decode('<in><Port Id="1" Type="EN"/></in>')
    assert "Address=" not in out


def test_short_type_codes_expanded():
    for code, full in [("DN", "DeviceNet"), ("CN", "ControlNet"),
                       ("Cpt35EN", "CompactLogixL35Ethernet")]:
        out = decode(f'<in><Port Id="1" Type="{code}"/></in>')
        assert f'Type="{full}"' in out


def test_context_dependent_types_kept_verbatim():
    # PointIO / RhinoBP are correct on hundreds of ports and must NOT be expanded.
    out = decode('<in><Port Id="1" Type="PointIO"/></in>')
    assert 'Type="PointIO"' in out
