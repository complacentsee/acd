"""Unit tests for MESSAGE ConnectionPath module-route eligibility.

A module may name a ConnectionPath hop only when (a) its name is a plain
identifier -- partner/unresolved pseudo-modules never appear in a Logix path --
and (b) every segment of its parent chain was built from a real upstream-port
address. A chain that needed the slot fallback describes a module Logix leaves
numeric. A trusted slot-0 backplane route is nameable like any other (the
controller itself is not always in slot 0).
"""

from acd.l5x.messages import _msg_build_module_routes, _msg_resolve_cp


class _Mod:
    def __init__(self, name, parent, ppid=1, address=None, slot=0,
                 is_root=False):
        self.name = name
        self.parent_module = parent
        self.parent_mod_port_id = ppid
        self._slot = slot
        self._is_root = is_root
        self._address = address

    def _build_ports_xml(self):
        if self._address is None:
            return '<Ports><Port Id="1" Type="ICP" Upstream="true"/></Ports>'
        return ('<Ports><Port Id="1" Type="ICP" Address="%s" '
                'Upstream="true"/></Ports>' % self._address)


def test_trusted_slot0_route_names_the_hop():
    root = _Mod("Local", "Local", is_root=True)
    enet = _Mod("Enet_Bridge", "Local", ppid=1, address="0")
    nr, rc = _msg_build_module_routes([root, enet])
    assert nr == {"Enet_Bridge": b"\x01\x00"}
    cp, unsafe = _msg_resolve_cp(b"\x01\x00\x02\x05", nr, rc)
    assert cp == "Enet_Bridge, 2, 5" and not unsafe


def test_slot_fallback_chain_stays_numeric():
    root = _Mod("Local", "Local", is_root=True)
    ghost = _Mod("Ghost", "Local", ppid=1, address=None, slot=1)
    nr, rc = _msg_build_module_routes([root, ghost])
    assert "Ghost" not in nr
    cp, unsafe = _msg_resolve_cp(b"\x01\x01", nr, rc)
    assert cp == "1, 1" and not unsafe


def test_pseudo_module_names_are_excluded():
    root = _Mod("Local", "Local", is_root=True)
    partner = _Mod("@fcc730f7@:Partner", "Local", ppid=1, address="1")
    quest = _Mod("?", "Local", ppid=1, address="2")
    nr, _ = _msg_build_module_routes([root, partner, quest])
    assert nr == {}
