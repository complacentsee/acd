# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class ShortComps(KaitaiStruct):
    """V10..V21 "short" comps record layout, shared by the FAFA (0xFAFA primary)
    and FDFD (0xFDFD secondary) families -- the short header is identical for
    both. RSLogix5000 V21-and-earlier store comps with a header 4 bytes
    SHORTER than V24+ (the long header inserts a zero u32 at payload offset
    12, pushing object_id/parent_id/record_name +4); the FafaComps/FdfdComps
    grammars use the long offsets. Which family a project uses is a
    project-level property, not a per-record one, so the discriminator
    (acd.record.comps.record_uses_short_header) stays in Python.
    
    All positions are within the full stream payload
    (dat_record.record.record_buffer, = len_record-6, untruncated).
    
    record_buffer deliberately reads from offset 94 to END OF STREAM rather
    than trusting the u32 record length at payload offset 0: that field is
    the primary-record length only and undercounts records carrying appended
    sub-blobs, which would truncate large datatype/tag bodies (the same
    truncation bug the long-header grammars still carry). Body offset 94 is
    where the 14-byte RxGeneric prelude begins (proven on short-header pool
    files: @94 parses 661/661 component bodies with the correct cip
    distribution; the name window overlaps it because short names terminate
    well before offset 94 in practice -- the window is scanned only to the
    first NUL).
    
    A name window that is truncated, unterminated within its 82 bytes, or
    not valid UTF-16 makes record_name raise; the caller falls back to the
    lenient hand decode (acd.record.comps.CompsRecord._decode_utf16z), which
    tolerates all three.
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(ShortComps, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        pass


    def _fetch_instances(self):
        pass
        _ = self.object_id
        if hasattr(self, '_m_object_id'):
            pass

        _ = self.parent_id
        if hasattr(self, '_m_parent_id'):
            pass

        _ = self.record_buffer
        if hasattr(self, '_m_record_buffer'):
            pass

        _ = self.record_name
        if hasattr(self, '_m_record_name'):
            pass
            self._m_record_name._fetch_instances()

        _ = self.record_type
        if hasattr(self, '_m_record_type'):
            pass

        _ = self.seq_number
        if hasattr(self, '_m_seq_number'):
            pass


    class StrzUtf16(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(ShortComps.StrzUtf16, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.value = (self._io.read_bytes(2 * (len(self.code_units) - 1))).decode(u"UTF-16LE")
            self.term = self._io.read_u2le()
            if not self.term == 0:
                raise kaitaistruct.ValidationNotEqualError(0, self.term, self._io, u"/types/strz_utf_16/seq/1")


        def _fetch_instances(self):
            pass
            _ = self.code_units
            if hasattr(self, '_m_code_units'):
                pass
                for i in range(len(self._m_code_units)):
                    pass



        @property
        def code_units(self):
            if hasattr(self, '_m_code_units'):
                return self._m_code_units

            _pos = self._io.pos()
            self._io.seek(self._io.pos())
            self._m_code_units = []
            i = 0
            while True:
                _ = self._io.read_u2le()
                self._m_code_units.append(_)
                if _ == 0:
                    break
                i += 1
            self._io.seek(_pos)
            return getattr(self, '_m_code_units', None)


    @property
    def object_id(self):
        """self_lcg / CompUId (the long header has a zero u32 here instead)."""
        if hasattr(self, '_m_object_id'):
            return self._m_object_id

        _pos = self._io.pos()
        self._io.seek(12)
        self._m_object_id = self._io.read_u4le()
        self._io.seek(_pos)
        return getattr(self, '_m_object_id', None)

    @property
    def parent_id(self):
        if hasattr(self, '_m_parent_id'):
            return self._m_parent_id

        _pos = self._io.pos()
        self._io.seek(16)
        self._m_parent_id = self._io.read_u4le()
        self._io.seek(_pos)
        return getattr(self, '_m_parent_id', None)

    @property
    def record_buffer(self):
        """RxGeneric body (14B prelude + 60B main_record + ext-attr tail)."""
        if hasattr(self, '_m_record_buffer'):
            return self._m_record_buffer

        _pos = self._io.pos()
        self._io.seek(94)
        self._m_record_buffer = self._io.read_bytes_full()
        self._io.seek(_pos)
        return getattr(self, '_m_record_buffer', None)

    @property
    def record_name(self):
        """NUL-terminated UTF-16LE name, scanned within an 82-byte window."""
        if hasattr(self, '_m_record_name'):
            return self._m_record_name

        _pos = self._io.pos()
        self._io.seek(20)
        self._raw__m_record_name = self._io.read_bytes(82)
        _io__raw__m_record_name = KaitaiStream(BytesIO(self._raw__m_record_name))
        self._m_record_name = ShortComps.StrzUtf16(_io__raw__m_record_name, self, self._root)
        self._io.seek(_pos)
        return getattr(self, '_m_record_name', None)

    @property
    def record_type(self):
        """256 = component, 0 = collection (same position as the long header)."""
        if hasattr(self, '_m_record_type'):
            return self._m_record_type

        _pos = self._io.pos()
        self._io.seek(10)
        self._m_record_type = self._io.read_u2le()
        self._io.seek(_pos)
        return getattr(self, '_m_record_type', None)

    @property
    def seq_number(self):
        """Per-collection ordinal (cosmetic for export)."""
        if hasattr(self, '_m_seq_number'):
            return self._m_seq_number

        _pos = self._io.pos()
        self._io.seek(8)
        self._m_seq_number = self._io.read_u2le()
        self._io.seek(_pos)
        return getattr(self, '_m_seq_number', None)


