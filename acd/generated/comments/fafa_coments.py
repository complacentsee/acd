# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class FafaComents(KaitaiStruct):
    def __init__(self, _io, _parent=None, _root=None):
        super(FafaComents, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        self.record_length = self._io.read_u4le()
        self._raw_header = self._io.read_bytes(10)
        _io__raw_header = KaitaiStream(BytesIO(self._raw_header))
        self.header = FafaComents.Header(_io__raw_header, self, self._root)
        _on = self.header.record_type
        if _on == 1:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.AsciiRecord(_io__raw_body, self, self._root)
        elif _on == 12:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.RawRecord(_io__raw_body, self, self._root)
        elif _on == 13:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.Utf16Record(12, _io__raw_body, self, self._root)
        elif _on == 14:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.Utf16Record(12, _io__raw_body, self, self._root)
        elif _on == 2:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.AsciiRecord(_io__raw_body, self, self._root)
        elif _on == 23:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.ControllerRecord(_io__raw_body, self, self._root)
        elif _on == 25:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.ControllerRecord(_io__raw_body, self, self._root)
        elif _on == 3:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.Utf16Record(12, _io__raw_body, self, self._root)
        elif _on == 4:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.Utf16Record(12, _io__raw_body, self, self._root)
        else:
            pass
            self._raw_body = self._io.read_bytes(self.record_length - 10)
            _io__raw_body = KaitaiStream(BytesIO(self._raw_body))
            self.body = FafaComents.Utf16Record(12, _io__raw_body, self, self._root)


    def _fetch_instances(self):
        pass
        self.header._fetch_instances()
        _on = self.header.record_type
        if _on == 1:
            pass
            self.body._fetch_instances()
        elif _on == 12:
            pass
            self.body._fetch_instances()
        elif _on == 13:
            pass
            self.body._fetch_instances()
        elif _on == 14:
            pass
            self.body._fetch_instances()
        elif _on == 2:
            pass
            self.body._fetch_instances()
        elif _on == 23:
            pass
            self.body._fetch_instances()
        elif _on == 25:
            pass
            self.body._fetch_instances()
        elif _on == 3:
            pass
            self.body._fetch_instances()
        elif _on == 4:
            pass
            self.body._fetch_instances()
        else:
            pass
            self.body._fetch_instances()
        _ = self.lookup_id
        if hasattr(self, '_m_lookup_id'):
            pass

        _ = self.sub_record_type
        if hasattr(self, '_m_sub_record_type'):
            pass


    class AsciiRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.AsciiRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.unknown_1 = self._io.read_bytes(13)
            self.object_id = self._io.read_u4le()
            self.unknown_2 = self._io.read_bytes(13)
            self.record_string = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")


        def _fetch_instances(self):
            pass


    class AsciiRecord4(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.AsciiRecord4, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.unknown_1 = self._io.read_bytes(8)
            self.object_id = self._io.read_u4le()
            self.unknown_2 = self._io.read_bytes(24)
            self.record_string = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")


        def _fetch_instances(self):
            pass


    class ControllerRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.ControllerRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.unknown_1 = self._io.read_bytes(8)
            self.object_id = self._io.read_u4le()
            self.unknown_2 = self._io.read_bytes(4)
            self.tag_reference = FafaComents.StrzUtf16(self._io, self, self._root)
            self.unknown_3 = self._io.read_bytes(12)
            self.record_string = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")


        def _fetch_instances(self):
            pass
            self.tag_reference._fetch_instances()


    class Header(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.Header, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            pass


        def _fetch_instances(self):
            pass
            _ = self.parent
            if hasattr(self, '_m_parent'):
                pass

            _ = self.record_type
            if hasattr(self, '_m_record_type'):
                pass

            _ = self.seq_number
            if hasattr(self, '_m_seq_number'):
                pass

            _ = self.sub_record_length
            if hasattr(self, '_m_sub_record_length'):
                pass


        @property
        def parent(self):
            if hasattr(self, '_m_parent'):
                return self._m_parent

            _pos = self._io.pos()
            self._io.seek(6)
            self._m_parent = self._io.read_u4le()
            self._io.seek(_pos)
            return getattr(self, '_m_parent', None)

        @property
        def record_type(self):
            if hasattr(self, '_m_record_type'):
                return self._m_record_type

            _pos = self._io.pos()
            self._io.seek(2)
            self._m_record_type = self._io.read_u2le()
            self._io.seek(_pos)
            return getattr(self, '_m_record_type', None)

        @property
        def seq_number(self):
            if hasattr(self, '_m_seq_number'):
                return self._m_seq_number

            _pos = self._io.pos()
            self._io.seek(0)
            self._m_seq_number = self._io.read_u2le()
            self._io.seek(_pos)
            return getattr(self, '_m_seq_number', None)

        @property
        def sub_record_length(self):
            if hasattr(self, '_m_sub_record_length'):
                return self._m_sub_record_length

            _pos = self._io.pos()
            self._io.seek(4)
            self._m_sub_record_length = self._io.read_u2le()
            self._io.seek(_pos)
            return getattr(self, '_m_sub_record_length', None)


    class RawRecord(KaitaiStruct):
        """UDI metadata (record_type 12, e.g. the AOI RevisionNote): kept as raw
        bytes -- the body layout ([8B unknown][u32 id][u32 flags][UTF-16LE
        NUL-terminated UDI type][NUL padding][NUL-terminated ASCII text]) is
        parsed by acd.record.comments._parse_udi_body.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.RawRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.data = self._io.read_bytes_full()


        def _fetch_instances(self):
            pass


    class ShortDescRecord(KaitaiStruct):
        """V10..V21 short-header own-description body (record_type 1/2): the
        component's own Description in UTF-16LE (the V24+ ascii_record decodes
        UTF-8, which mangles these). Decoded by the tolerant hand walker
        acd.record.comments._parse_short_desc_body; declared here to document
        the layout. The text starts at the odd body offset 15.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.ShortDescRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.member_ref = self._io.read_u4le()
            self.rung_content = self._io.read_u4le()
            self.object_id_region = self._io.read_bytes(7)
            self.record_string = FafaComents.StrzUtf16(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            self.record_string._fetch_instances()


    class ShortOperandRecord(KaitaiStruct):
        """V10..V21 short-header operand comment body (record_type is an ordinal
        3..36 within the parent group, not an enum). Not wired into the body
        switch -- short-vs-long is decided per project, and the tolerant hand
        walker acd.record.comments._parse_short_operand_body (with its
        structural validation gates) decodes these; declared here to document
        the layout. The operand and comment text are UTF-16LE NUL-terminated,
        starting at the odd offset 13.
        """
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.ShortOperandRecord, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self._read()

        def _read(self):
            self.zero_prefix = self._io.read_bytes(6)
            if not self.zero_prefix == b"\x00\x00\x00\x00\x00\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x00\x00\x00\x00\x00\x00", self.zero_prefix, self._io, u"/types/short_operand_record/seq/0")
            self.member_key = self._io.read_u2le()
            self.object_id = self._io.read_u4le()
            self.pad = self._io.read_bytes(1)
            if not self.pad == b"\x00":
                raise kaitaistruct.ValidationNotEqualError(b"\x00", self.pad, self._io, u"/types/short_operand_record/seq/3")
            self.operand = FafaComents.StrzUtf16(self._io, self, self._root)
            self.record_string = FafaComents.StrzUtf16(self._io, self, self._root)


        def _fetch_instances(self):
            pass
            self.operand._fetch_instances()
            self.record_string._fetch_instances()


    class StrzUtf16(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            super(FafaComents.StrzUtf16, self).__init__(_io)
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


    class Utf16Record(KaitaiStruct):
        def __init__(self, len_unknown_3, _io, _parent=None, _root=None):
            super(FafaComents.Utf16Record, self).__init__(_io)
            self._parent = _parent
            self._root = _root
            self.len_unknown_3 = len_unknown_3
            self._read()

        def _read(self):
            self.unknown_1 = self._io.read_bytes(8)
            self.object_id = self._io.read_u4le()
            self.unknown_2 = self._io.read_bytes(4)
            self.tag_reference = FafaComents.StrzUtf16(self._io, self, self._root)
            self.unknown_3 = self._io.read_bytes(self.len_unknown_3)
            self.record_string = (self._io.read_bytes_term(0, False, True, True)).decode(u"UTF-8")


        def _fetch_instances(self):
            pass
            self.tag_reference._fetch_instances()


    @property
    def lookup_id(self):
        if hasattr(self, '_m_lookup_id'):
            return self._m_lookup_id

        _pos = self._io.pos()
        self._io.seek(27)
        self._m_lookup_id = self._io.read_u2le()
        self._io.seek(_pos)
        return getattr(self, '_m_lookup_id', None)

    @property
    def sub_record_type(self):
        if hasattr(self, '_m_sub_record_type'):
            return self._m_sub_record_type

        _pos = self._io.pos()
        self._io.seek(41)
        self._m_sub_record_type = self._io.read_u2le()
        self._io.seek(_pos)
        return getattr(self, '_m_sub_record_type', None)


