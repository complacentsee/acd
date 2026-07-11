# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class MemberDescriptor(KaitaiStruct):
    """Datatype member descriptor: extended attribute 0x6E + i (one per member,
    in member order) of a datatype record (cip-0x6c). Nominally 168 (0xA8)
    bytes but routinely truncated, so every field is size-guarded and reads
    as absent (None) when the blob ends before it; call sites keep their own
    degradation rules (skip the member / degraded member / legacy 0x74
    ExternalAccess fallback).
    
    The same layout serves V24+ long-header projects (whose members also
    exist as child comps records; the descriptor carries the field data) and
    V10..V21 short-header projects (whose members exist ONLY inline as these
    attributes, with the member name at offset 0).
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(MemberDescriptor, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        pass


    def _fetch_instances(self):
        pass
        _ = self.bit_number
        if hasattr(self, '_m_bit_number'):
            pass

        _ = self.data_type_id
        if hasattr(self, '_m_data_type_id'):
            pass

        _ = self.dimension
        if hasattr(self, '_m_dimension'):
            pass

        _ = self.external_access_byte
        if hasattr(self, '_m_external_access_byte'):
            pass

        _ = self.hidden
        if hasattr(self, '_m_hidden'):
            pass

        _ = self.host_ordinal
        if hasattr(self, '_m_host_ordinal'):
            pass

        _ = self.legacy_access_word
        if hasattr(self, '_m_legacy_access_word'):
            pass

        _ = self.name_raw
        if hasattr(self, '_m_name_raw'):
            pass

        _ = self.offset
        if hasattr(self, '_m_offset'):
            pass

        _ = self.radix
        if hasattr(self, '_m_radix'):
            pass

        _ = self.target_key
        if hasattr(self, '_m_target_key'):
            pass


    @property
    def bit_number(self):
        """Bit index within the backing word (BIT overlay members)."""
        if hasattr(self, '_m_bit_number'):
            return self._m_bit_number

        if self._io.size() >= 104:
            pass
            _pos = self._io.pos()
            self._io.seek(100)
            self._m_bit_number = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_bit_number', None)

    @property
    def data_type_id(self):
        """comps object_id of the member's data type."""
        if hasattr(self, '_m_data_type_id'):
            return self._m_data_type_id

        if self._io.size() >= 92:
            pass
            _pos = self._io.pos()
            self._io.seek(88)
            self._m_data_type_id = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_data_type_id', None)

    @property
    def dimension(self):
        """Array dimension (0 = scalar). Raw value: some non-array scalar
        members of predefined types carry garbage here (e.g. 0x20000 /
        0xFFFC0000), which call sites clamp to 0; a BIT overlay reuses the
        slot for a bit offset and forces dimension 0.
        """
        if hasattr(self, '_m_dimension'):
            return self._m_dimension

        if self._io.size() >= 96:
            pass
            _pos = self._io.pos()
            self._io.seek(92)
            self._m_dimension = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_dimension', None)

    @property
    def external_access_byte(self):
        """ExternalAccess: 0 = Read/Write, 2 = Read Only, 3 = None."""
        if hasattr(self, '_m_external_access_byte'):
            return self._m_external_access_byte

        if self._io.size() >= 161:
            pass
            _pos = self._io.pos()
            self._io.seek(160)
            self._m_external_access_byte = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_external_access_byte', None)

    @property
    def hidden(self):
        """Nonzero = hidden member (e.g. a bit-backing SINT host word)."""
        if hasattr(self, '_m_hidden'):
            return self._m_hidden

        if self._io.size() >= 116:
            pass
            _pos = self._io.pos()
            self._io.seek(112)
            self._m_hidden = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_hidden', None)

    @property
    def host_ordinal(self):
        """0x800 marks a real standalone BOOL / backing member; any other value
        on a BOOL member marks a BIT overlay. For ProductDefined/IO types it
        is the member-collection ordinal of the host word the bit overlays;
        for user types 1 selects the exact-offset lookup, else the
        preceding-hidden-backing fallback.
        """
        if hasattr(self, '_m_host_ordinal'):
            return self._m_host_ordinal

        if self._io.size() >= 108:
            pass
            _pos = self._io.pos()
            self._io.seek(104)
            self._m_host_ordinal = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_host_ordinal', None)

    @property
    def legacy_access_word(self):
        """Legacy ExternalAccess enum slot -- uniformly 1 on records that carry
        the real byte at 0xA0; used only as the fallback when the descriptor
        is too short to hold 0xA0. Its presence (size >= 0x78) doubles as
        the completeness gate of the old fixed-offset readers.
        """
        if hasattr(self, '_m_legacy_access_word'):
            return self._m_legacy_access_word

        if self._io.size() >= 120:
            pass
            _pos = self._io.pos()
            self._io.seek(116)
            self._m_legacy_access_word = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_legacy_access_word', None)

    @property
    def name_raw(self):
        """NUL-terminated UTF-16LE member name, meaningful on short-header
        inline members only (long-header members are named by their comps
        record). The field spans 0..0x53; decoding (first-NUL stop, lenient
        on malformed pairs) stays in Python (_decode_utf16z).
        """
        if hasattr(self, '_m_name_raw'):
            return self._m_name_raw

        if self._io.size() >= 2:
            pass
            _pos = self._io.pos()
            self._io.seek(0)
            self._m_name_raw = self._io.read_bytes((self._io.size() if self._io.size() < 84 else 84))
            self._io.seek(_pos)

        return getattr(self, '_m_name_raw', None)

    @property
    def offset(self):
        """Byte offset of the member's data within the datatype; keys the
        offset->name map BIT members resolve their backing field through.
        """
        if hasattr(self, '_m_offset'):
            return self._m_offset

        if self._io.size() >= 100:
            pass
            _pos = self._io.pos()
            self._io.seek(96)
            self._m_offset = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_offset', None)

    @property
    def radix(self):
        """Display radix enum (see radix_enum)."""
        if hasattr(self, '_m_radix'):
            return self._m_radix

        if self._io.size() >= 88:
            pass
            _pos = self._io.pos()
            self._io.seek(84)
            self._m_radix = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_radix', None)

    @property
    def target_key(self):
        """Byte offset of the backing field a BIT overlay targets; 0xFFFFFFFF
        when absent (real BOOLs and the host_ordinal patterns).
        """
        if hasattr(self, '_m_target_key'):
            return self._m_target_key

        if self._io.size() >= 112:
            pass
            _pos = self._io.pos()
            self._io.seek(108)
            self._m_target_key = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_target_key', None)


