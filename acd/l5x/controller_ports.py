# Controller-level communication port elements: <CommPorts>, <EthernetPorts>
# and <EthernetNetwork>.
#
# Every attribute value is READ from the backing RxControllerCollection child
# comp record (SerialPort + ASCII + DF1, EthernetPort1/2, EthernetNetwork)
# through CompsRecord.record_attrs -- the body-direct, source-protection-aware
# ext-attr table -- never emitted as a constant. Presence gates are LIVE comp
# existence: an FDFD-only relic (CompsRecord.dead_oids) is a deleted component
# Studio never exports, so it is treated as absent rather than emitted from
# its stale record (0-FP/0-FN over the 116-project reference pool). The one OEM
# attribute with no in-record source (SerialPort Channel, reference-invariant
# "0") is omitted rather than fabricated. Unrecognised enum codes or
# short/absent payloads degrade to omitting the element (the pre-existing
# missing-element residual) instead of guessing.

import struct
from sqlite3 import Cursor
from typing import Dict, Optional, Union

from acd.record.comps import CompsRecord

# Decoded enum maps carry only reference-verified codes (plus both boolean
# states); an unseen code raises KeyError and the element degrades to "".
_PARITY = {0: "No Parity"}
_STOP_BITS = {1: "1 Stop Bit", 2: "2 Stop Bits"}
_COM_DRIVER = {0xA2: "DF1", 0xA3: "ASCII"}
_CONTROL_LINE = {0: "No Handshake", 1: "Full Duplex"}
_BOOL = {0: "false", 1: "true"}
_ERROR_DETECTION = {0: "BCC Error", 1: "CRC Error"}
_EMBEDDED_RESPONSE = {0: "Autodetect"}
_DF1_MODE = {0: "Pt to Pt"}
_POLLING_MODE = {1: "Message Based (slave can initiate messages)"}
_MASTER_MSG_TRANSMIT = {0: "Between station polls"}

# The EthernetPort config block sits at offset 106 of the record's 0x1
# ext-attr value (verified at that one location across all 127 readable
# records pool-wide, including the source-protected ones after decrypt):
#   +0 u32 gate (1 = config block present)  +4 u8 flags (bit1 = autonegotiate)
#   +6 u8 port-enabled                       +7 u8 label length, ASCII @ +8.
_EP_BLOCK = 106


def _rcc_child(cur: Cursor, controller_oid: int, name: str,
               short_header: bool) -> Optional[int]:
    """object_id of the named LIVE RxControllerCollection child comp, or None.

    A deleted controller child survives in Comps.Dat as an FDFD-only relic
    (comps_family.fafa_seen=0); emitting from its stale record would invent
    config the project no longer has (ACDTestsEmptyRedundant's deleted
    EthernetPort1, oid 1493048019, is the pinned case), so a dead oid is
    treated as absent."""
    rcc = cur.execute(
        "SELECT object_id FROM comps WHERE parent_id=? AND "
        "comp_name='RxControllerCollection'", (controller_oid,)).fetchone()
    if not rcc:
        return None
    row = cur.execute(
        "SELECT object_id FROM comps WHERE parent_id=? AND comp_name=?",
        (rcc[0], name)).fetchone()
    if not row or row[0] in CompsRecord.dead_oids(cur, short_header):
        return None
    return row[0]


def _attrs(cur: Cursor, controller_oid: int, name: str,
           short_header: bool) -> Optional[Dict[int, bytes]]:
    oid = _rcc_child(cur, controller_oid, name, short_header)
    if oid is None:
        return None
    # Body-direct read of comps.record (D11), valid since the P6.9 C5 flip made
    # comps.record == full[148:] for BOTH long-header families. The FDFD@148
    # decode keeps its own pin in test_fdfd_grammar.py; the oracle fixtures pin
    # both liveness directions (WithAOI live port byte-exact, EmptyRedundant
    # relic suppressed).
    return CompsRecord.record_attrs(cur, oid, short_header)


def build_comm_ports(cur: Cursor, controller_oid: int,
                     short_header: bool) -> str:
    """<CommPorts> with the serial channel config, or "" when the controller
    has no SerialPort comp (or its records don't decode)."""
    try:
        sp = _attrs(cur, controller_oid, "SerialPort", short_header)
        if sp is None:
            return ""
        asc = _attrs(cur, controller_oid, "ASCII", short_header) or {}
        df1 = _attrs(cur, controller_oid, "DF1", short_header) or {}
        p, a, d = sp.get(0x1, b""), asc.get(0x1, b""), df1.get(0x1, b"")
        # The DF1 poll/station *File attrs live in their own sub-records.
        subs = [df1.get(i) for i in (0x65, 0x66, 0x67, 0x68)]
        if (len(p) < 22 or len(a) < 58 or len(d) < 124
                or any(s is None or len(s) < 4 for s in subs)):
            return ""

        def na_file(raw: bytes) -> str:
            val = struct.unpack("<I", raw[:4])[0]
            return "&lt;NA&gt;" if val == 0xFFFFFFFF else str(val)

        # OEM Channel="0" has no in-record source (reference-invariant) and is
        # deliberately omitted here.
        serial = (
            f'BaudRate="{struct.unpack_from("<I", p, 2)[0] * 256}"'
            f' Parity="{_PARITY[p[9]]}"'
            f' DataBits="{p[6]} Bits of Data"'
            f' StopBits="{_STOP_BITS[p[7]]}"'
            f' ComDriverId="{_COM_DRIVER[p[8]]}"'
            f' RTSOffDelay="{struct.unpack_from("<H", p, 10)[0]}"'
            f' RTSSendDelay="{struct.unpack_from("<H", p, 12)[0]}"'
            f' ControlLine="{_CONTROL_LINE[p[14]]}"'
            f' RemoteModeChangeFlag="{_BOOL[p[15]]}"'
            f' ModeChangeAttentionChar="{p[18]}"'
            f' SystemModeCharacter="{p[19]}"'
            f' UserModeCharacter="{p[20]}"'
            f' DCDWaitDelay="{p[21]}"'
        )
        # ASCII/DF1 read their TAIL config copy -- the leading copy holds
        # uninitialised bytes on a subset of projects.
        ascii_el = (
            f'<ASCII XONXOFFEnable="{_BOOL[a[47]]}" DeleteMode="{a[48]}" '
            f'EchoMode="{a[49]}" '
            f'TerminationChars="{struct.unpack_from("<H", a, 51)[0]}" '
            f'AppendChars="{struct.unpack_from("<H", a, 54)[0]}" '
            f'BufferSize="{struct.unpack_from("<H", a, 56)[0]}"/>'
        )
        df1_el = (
            f'<DF1 DuplicateDetection="{_BOOL[d[78]]}"'
            f' ErrorDetection="{_ERROR_DETECTION[d[79]]}"'
            f' EmbeddedResponseEnable="{_EMBEDDED_RESPONSE[d[80]]}"'
            f' DF1Mode="{_DF1_MODE[d[81]]}"'
            f' ACKTimeout="{struct.unpack_from("<H", d, 82)[0]}"'
            f' NAKReceiveLimit="{d[88]}"'
            f' ENQTransmitLimit="{d[89]}"'
            f' TransmitRetries="{d[90]}"'
            f' StationAddress="{d[91]}"'
            f' ReplyMessageWait="{d[93]}"'
            f' PollingMode="{_POLLING_MODE[d[97]]}"'
            f' MasterMessageTransmit="{_MASTER_MSG_TRANSMIT[d[98]]}"'
            f' NormalPollNodeFile="{na_file(subs[0])}"'
            f' NormalPollGroupSize="{struct.unpack_from("<H", d, 99)[0]}"'
            f' PriorityPollNodeFile="{na_file(subs[1])}"'
            f' ActiveStationFile="{na_file(subs[2])}"'
            f' SlavePollTimeout="{struct.unpack_from("<H", d, 113)[0]}"'
            f' EOTSuppression="{d[117]}"'
            f' MaxStationAddress="{d[118]}"'
            f' TokenHoldFactor="{d[119]}"'
            f' EnableStoreFwd="{_BOOL[d[122]]}"'
            f' StoreFwdFile="{na_file(subs[3])}"/>'
        )
        return (f'<CommPorts><SerialPort {serial}>'
                f'{ascii_el}{df1_el}</SerialPort></CommPorts>')
    except Exception:
        return ""


def build_ethernet_ports(cur: Cursor, controller_oid: int, short_header: bool,
                         major_rev: Union[str, None]) -> str:
    """<EthernetPorts> with one <EthernetPort> per EthernetPortN comp, or ""
    when the controller has none. The attribute form follows the controller
    firmware major revision (the emitted MajorRev): <=24 uses
    AutoNegotiateEnabled, newer uses Label (25..27 unobserved; the boundary
    inside that gap is a free choice)."""
    try:
        try:
            ane_form = int(major_rev) <= 24
        except (TypeError, ValueError):
            ane_form = False
        has_ip2 = _rcc_child(
            cur, controller_oid, "InternetProtocol2", short_header) is not None
        ports = []
        for n in (1, 2):
            attrs = _attrs(
                cur, controller_oid, f"EthernetPort{n}", short_header)
            if attrs is None:
                continue
            v = attrs.get(0x1, b"")
            blk = v[_EP_BLOCK:] if len(v) >= _EP_BLOCK + 8 else None
            enabled = label = auto_neg = None
            if blk is not None:
                enabled = _BOOL.get(blk[6])
                auto_neg = "true" if blk[4] & 0x02 else "false"
                if struct.unpack_from("<I", blk, 0)[0] == 1 and blk[4] == 0x02:
                    ln = blk[7]
                    if ln and len(blk) >= 8 + ln:
                        label = blk[8:8 + ln].decode("ascii", errors="replace")
            if label is None:
                # No stored label: the reference defaults to the port number,
                # "A"-prefixed on the dual-IP (InternetProtocol2) generation.
                label = f"A{n}" if has_ip2 else str(n)
            attrs_out = f'Port="{n}"'
            if ane_form:
                if enabled is not None:
                    attrs_out += f' PortEnabled="{enabled}"'
                if auto_neg is not None:
                    attrs_out += f' AutoNegotiateEnabled="{auto_neg}"'
            else:
                attrs_out += f' Label="{label}"'
                if enabled is not None:
                    attrs_out += f' PortEnabled="{enabled}"'
            ports.append(f'<EthernetPort {attrs_out}/>')
        if not ports:
            return ""
        return f'<EthernetPorts>{"".join(ports)}</EthernetPorts>'
    except Exception:
        return ""


def build_ethernet_network(cur: Cursor, controller_oid: int,
                           short_header: bool) -> str:
    """<EthernetNetwork> (the CIP DLR ring supervisor config), or "" when the
    controller has no EthernetNetwork comp. The five attributes are the packed
    DLR config struct (BOOL, USINT, UDINT, UDINT, UINT) at bytes 3..14 of the
    record's 0x1 ext-attr value, anchored by the BeaconInterval/BeaconTimeout
    u32 pair."""
    try:
        attrs = _attrs(cur, controller_oid, "EthernetNetwork", short_header)
        if attrs is None:
            return ""
        v = attrs.get(0x1, b"")
        if len(v) < 15:
            return ""
        return (
            f'<EthernetNetwork SupervisorModeEnabled="{_BOOL[v[3]]}" '
            f'SupervisorPrecedence="{v[4]}" '
            f'BeaconInterval="{struct.unpack_from("<I", v, 5)[0]}" '
            f'BeaconTimeout="{struct.unpack_from("<I", v, 9)[0]}" '
            f'VLANID="{struct.unpack_from("<H", v, 13)[0]}"/>'
        )
    except Exception:
        return ""
