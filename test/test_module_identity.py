"""Unit tests for the ModuleIdentity blob grammar (kaitai).

The grammar decodes the fixed-offset fields of a module's identity blob
(extended attribute 0x001 of a cip-0x69 record, or the same bytes inline
behind the 44 02 00 00 marker / in comps_full). Real blobs truncate at
arbitrary points, so every field is size-guarded: a field the blob ends
before reads as None, mirroring the length guards of the hand decoders it
replaced. The IP string additionally clamps to the bytes that remain when
the blob ends mid-string, matching the old tolerant slice.
"""

import struct

from acd.generated.comps.module_identity import ModuleIdentity

IP = b"192.168.1.10\x00"


def _blob() -> bytearray:
    """A synthetic identity blob with distinct values at every decoded offset."""
    b = bytearray(640)
    struct.pack_into("<HHHH", b, 0, 0x0200, 1, 142, 1063)
    b[0x08] = 0x85          # major 5 + bit-7 flag
    b[0x09] = 3             # minor
    b[0x0A] = 0x1F          # ekey mask
    b[0x14] = 0x05          # flags: major-fault + inhibited
    struct.pack_into("<I", b, 0x16, 0xDEAD)   # parent_modid
    struct.pack_into("<H", b, 0x1A, 2)        # parent_port
    struct.pack_into("<I", b, 0x1C, 7)        # slot
    struct.pack_into("<I", b, 0x20, 0x111)    # config_ref
    struct.pack_into("<I", b, 0x24, 0x222)    # data_link
    struct.pack_into("<I", b, 0x2C, 0x333)    # modid
    struct.pack_into("<H", b, 0x30, len(IP))
    b[0x32:0x32 + len(IP)] = IP
    b[305:311] = bytes.fromhex("aabbccddee40")  # safety network number
    struct.pack_into("<H", b, 556, 0x77)      # config_script_cid
    struct.pack_into("<I", b, 624, 0x888)     # config_data_oid
    return b


def test_full_blob_decodes_every_field():
    m = ModuleIdentity.from_bytes(bytes(_blob()))
    assert (m.class_word, m.vendor, m.product_type, m.product_code) == (
        0x0200, 1, 142, 1063)
    assert (m.major_raw, m.minor, m.ekey_mask, m.flags) == (0x85, 3, 0x1F, 0x05)
    assert (m.parent_modid, m.parent_port, m.slot) == (0xDEAD, 2, 7)
    assert (m.config_ref, m.data_link, m.modid) == (0x111, 0x222, 0x333)
    assert m.ip_len == len(IP) and m.ip_raw == IP
    assert m.safety_network == bytes.fromhex("aabbccddee40")
    assert m.config_script_cid == 0x77
    assert m.config_data_oid == 0x888


def test_truncated_at_0x30_keeps_modid_drops_the_rest():
    # 0x30 is the minimum the >= 0x30 identity gates admit: everything
    # through modid is present, everything after is absent.
    m = ModuleIdentity.from_bytes(bytes(_blob()[:0x30]))
    assert m.modid == 0x333 and m.slot == 7
    assert m.ip_len is None and m.ip_raw is None
    assert m.safety_network is None
    assert m.config_script_cid is None and m.config_data_oid is None


def test_truncation_mid_ip_clamps_like_the_old_slice():
    m = ModuleIdentity.from_bytes(bytes(_blob()[:0x32 + 4]))
    assert m.ip_len == len(IP)
    assert m.ip_raw == IP[:4]


def test_zero_ip_len_reads_as_absent():
    b = _blob()
    struct.pack_into("<H", b, 0x30, 0)
    assert ModuleIdentity.from_bytes(bytes(b[:0x40])).ip_raw is None


def test_tiny_and_empty_blobs_read_all_none():
    for raw in (b"", b"\x01"):
        m = ModuleIdentity.from_bytes(raw)
        assert m.class_word is None and m.vendor is None
        assert m.flags is None and m.modid is None and m.ip_raw is None


def test_boundary_guards_are_exact():
    b = bytes(_blob())
    # One byte short of each late field's guard -> None; at the guard -> value.
    assert ModuleIdentity.from_bytes(b[:310]).safety_network is None
    assert ModuleIdentity.from_bytes(b[:311]).safety_network is not None
    assert ModuleIdentity.from_bytes(b[:557]).config_script_cid is None
    assert ModuleIdentity.from_bytes(b[:558]).config_script_cid == 0x77
    assert ModuleIdentity.from_bytes(b[:627]).config_data_oid is None
    assert ModuleIdentity.from_bytes(b[:628]).config_data_oid == 0x888
    # The ip_len guard is strictly-greater-than-0x32 (there must be at least
    # one string byte), mirroring the old `len(e1) > 0x32` condition.
    assert ModuleIdentity.from_bytes(b[:0x32]).ip_len is None
    assert ModuleIdentity.from_bytes(b[:0x33]).ip_len == len(IP)
