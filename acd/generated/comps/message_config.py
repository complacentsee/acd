# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class MessageConfig(KaitaiStruct):
    """MESSAGE tag configuration struct: extended attribute 0x1 of the tag's
    cip-0x6a backing record (object_id == the tag's data_table_instance).
    354 bytes on every decodable pool record -- the renderer gates on that
    exact length before decoding (a different length marks a safety/variant
    config it deliberately does not emit). Fields are nevertheless
    size-guarded so a truncated buffer reads as absent rather than raising.
    
    The UTF-16 member references (LocalElement 0x65, DestinationTag 0x70,
    RemoteElement 0x67) are sibling attributes, not part of this struct.
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(MessageConfig, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        pass


    def _fetch_instances(self):
        pass
        _ = self.attribute_number
        if hasattr(self, '_m_attribute_number'):
            pass

        _ = self.connected_flag
        if hasattr(self, '_m_connected_flag'):
            pass

        _ = self.epath
        if hasattr(self, '_m_epath'):
            pass

        _ = self.family
        if hasattr(self, '_m_family'):
            pass

        _ = self.large_packet_flags
        if hasattr(self, '_m_large_packet_flags'):
            pass

        _ = self.object_type
        if hasattr(self, '_m_object_type'):
            pass

        _ = self.path_size
        if hasattr(self, '_m_path_size'):
            pass

        _ = self.requested_length
        if hasattr(self, '_m_requested_length'):
            pass

        _ = self.service_byte
        if hasattr(self, '_m_service_byte'):
            pass

        _ = self.service_code
        if hasattr(self, '_m_service_code'):
            pass

        _ = self.target_object
        if hasattr(self, '_m_target_object'):
            pass


    @property
    def attribute_number(self):
        if hasattr(self, '_m_attribute_number'):
            return self._m_attribute_number

        if self._io.size() >= 340:
            pass
            _pos = self._io.pos()
            self._io.seek(338)
            self._m_attribute_number = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_attribute_number', None)

    @property
    def connected_flag(self):
        """ConnectedFlag; 1 also enables CacheConnections on CIP families."""
        if hasattr(self, '_m_connected_flag'):
            return self._m_connected_flag

        if self._io.size() >= 144:
            pass
            _pos = self._io.pos()
            self._io.seek(143)
            self._m_connected_flag = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_connected_flag', None)

    @property
    def epath(self):
        """The ConnectionPath EPATH bytes, present only when the declared size is
        plausible (0 < size < 250) and fully contained -- the same rule the
        renderer applied; resolved against the module topology in Python.
        """
        if hasattr(self, '_m_epath'):
            return self._m_epath

        if  ((self._io.size() >= 146) and (self.path_size != 0) and (self.path_size < 250) and (146 + self.path_size <= self._io.size())) :
            pass
            _pos = self._io.pos()
            self._io.seek(146)
            self._m_epath = self._io.read_bytes(self.path_size)
            self._io.seek(_pos)

        return getattr(self, '_m_epath', None)

    @property
    def family(self):
        """MessageType family: 0 Unconfigured, 1 CIP Generic, 2 CIP Data Table,
        4 SLC, 6 PLC5, 7 Module Reconfigure.
        """
        if hasattr(self, '_m_family'):
            return self._m_family

        if self._io.size() >= 354:
            pass
            _pos = self._io.pos()
            self._io.seek(353)
            self._m_family = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_family', None)

    @property
    def large_packet_flags(self):
        """Bit 1 = LargePacketUsage (CIP Generic)."""
        if hasattr(self, '_m_large_packet_flags'):
            return self._m_large_packet_flags

        if self._io.size() >= 282:
            pass
            _pos = self._io.pos()
            self._io.seek(281)
            self._m_large_packet_flags = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_large_packet_flags', None)

    @property
    def object_type(self):
        if hasattr(self, '_m_object_type'):
            return self._m_object_type

        if self._io.size() >= 334:
            pass
            _pos = self._io.pos()
            self._io.seek(332)
            self._m_object_type = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_object_type', None)

    @property
    def path_size(self):
        """Byte length of the CIP ConnectionPath EPATH at 146."""
        if hasattr(self, '_m_path_size'):
            return self._m_path_size

        if self._io.size() >= 146:
            pass
            _pos = self._io.pos()
            self._io.seek(144)
            self._m_path_size = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_path_size', None)

    @property
    def requested_length(self):
        """RequestedLength (bytes)."""
        if hasattr(self, '_m_requested_length'):
            return self._m_requested_length

        if self._io.size() >= 141:
            pass
            _pos = self._io.pos()
            self._io.seek(139)
            self._m_requested_length = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_requested_length', None)

    @property
    def service_byte(self):
        """Low byte of service_code: the family sub-type discriminator (e.g.
        76/77 = CIP Data Table Read/Write under family 2).
        """
        if hasattr(self, '_m_service_byte'):
            return self._m_service_byte

        if self._io.size() >= 331:
            pass
            _pos = self._io.pos()
            self._io.seek(330)
            self._m_service_byte = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_service_byte', None)

    @property
    def service_code(self):
        """Full CIP ServiceCode (CIP Generic renders it as 16#xxxx)."""
        if hasattr(self, '_m_service_code'):
            return self._m_service_code

        if self._io.size() >= 332:
            pass
            _pos = self._io.pos()
            self._io.seek(330)
            self._m_service_code = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_service_code', None)

    @property
    def target_object(self):
        if hasattr(self, '_m_target_object'):
            return self._m_target_object

        if self._io.size() >= 338:
            pass
            _pos = self._io.pos()
            self._io.seek(334)
            self._m_target_object = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_target_object', None)


