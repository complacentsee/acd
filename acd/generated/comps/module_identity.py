# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild
# type: ignore

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 11):
    raise Exception("Incompatible Kaitai Struct Python API: 0.11 or later is required, but you have %s" % (kaitaistruct.__version__))

class ModuleIdentity(KaitaiStruct):
    """Module identity blob of a cip-0x69 module record: extended attribute 0x001,
    also found inline behind the u32 length marker 44 02 00 00 (0x244, the blob's
    nominal length) on records that do not surface the attribute, and in the
    untruncated comps_full copy when the comps `record` buffer is truncated
    before the attribute. All three sources carry the same layout.
    
    Real blobs are routinely shorter than the nominal 0x244 bytes, so every
    field is size-guarded and reads as absent (None) when the blob is truncated
    before it; callers keep their own fallbacks. Structures located by scanning
    rather than fixed offset -- the port->SNN table, the drive ADC word before
    the FF FF FF FF sentinel, the 20 6A config-script TLV, and the 44 02 00 00
    marker recovery itself -- stay in Python (see acd.l5x.module_builder).
    """
    def __init__(self, _io, _parent=None, _root=None):
        super(ModuleIdentity, self).__init__(_io)
        self._parent = _parent
        self._root = _root or self
        self._read()

    def _read(self):
        pass


    def _fetch_instances(self):
        pass
        _ = self.class_word
        if hasattr(self, '_m_class_word'):
            pass

        _ = self.config_data_oid
        if hasattr(self, '_m_config_data_oid'):
            pass

        _ = self.config_ref
        if hasattr(self, '_m_config_ref'):
            pass

        _ = self.config_script_cid
        if hasattr(self, '_m_config_script_cid'):
            pass

        _ = self.data_link
        if hasattr(self, '_m_data_link'):
            pass

        _ = self.ekey_mask
        if hasattr(self, '_m_ekey_mask'):
            pass

        _ = self.flags
        if hasattr(self, '_m_flags'):
            pass

        _ = self.ip_len
        if hasattr(self, '_m_ip_len'):
            pass

        _ = self.ip_raw
        if hasattr(self, '_m_ip_raw'):
            pass

        _ = self.major_raw
        if hasattr(self, '_m_major_raw'):
            pass

        _ = self.minor
        if hasattr(self, '_m_minor'):
            pass

        _ = self.modid
        if hasattr(self, '_m_modid'):
            pass

        _ = self.parent_modid
        if hasattr(self, '_m_parent_modid'):
            pass

        _ = self.parent_port
        if hasattr(self, '_m_parent_port'):
            pass

        _ = self.product_code
        if hasattr(self, '_m_product_code'):
            pass

        _ = self.product_type
        if hasattr(self, '_m_product_type'):
            pass

        _ = self.safety_network
        if hasattr(self, '_m_safety_network'):
            pass

        _ = self.slot
        if hasattr(self, '_m_slot'):
            pass

        _ = self.vendor
        if hasattr(self, '_m_vendor'):
            pass


    @property
    def class_word(self):
        """Identity class word; drives the <Communications> emit gate (structural
        bus/port classes never emit it). 0x0200/0x0201 = drive module (the
        drive ADC word applies).
        """
        if hasattr(self, '_m_class_word'):
            return self._m_class_word

        if self._io.size() >= 2:
            pass
            _pos = self._io.pos()
            self._io.seek(0)
            self._m_class_word = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_class_word', None)

    @property
    def config_data_oid(self):
        """Short-header ConfigData holder object id (fallback pointer)."""
        if hasattr(self, '_m_config_data_oid'):
            return self._m_config_data_oid

        if self._io.size() >= 628:
            pass
            _pos = self._io.pos()
            self._io.seek(624)
            self._m_config_data_oid = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_config_data_oid', None)

    @property
    def config_ref(self):
        """Long-header ConfigData holder link; resolves to the RxDataCollection
        holder whose main_record@0x28 equals it.
        """
        if hasattr(self, '_m_config_ref'):
            return self._m_config_ref

        if self._io.size() >= 36:
            pass
            _pos = self._io.pos()
            self._io.seek(32)
            self._m_config_ref = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_config_ref', None)

    @property
    def config_script_cid(self):
        """comment_id of the ConfigScript RxDataCollection holder (0 = none)."""
        if hasattr(self, '_m_config_script_cid'):
            return self._m_config_script_cid

        if self._io.size() >= 558:
            pass
            _pos = self._io.pos()
            self._io.seek(556)
            self._m_config_script_cid = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_config_script_cid', None)

    @property
    def data_link(self):
        """comment_id link (low u16) to the module's backing RxDataCollection
        child, which carries the port topology / <public> / <CF> payloads.
        """
        if hasattr(self, '_m_data_link'):
            return self._m_data_link

        if self._io.size() >= 40:
            pass
            _pos = self._io.pos()
            self._io.seek(36)
            self._m_data_link = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_data_link', None)

    @property
    def ekey_mask(self):
        """Electronic keying mask (0x1f = all identity fields keyed); 0 = keying
        disabled.
        """
        if hasattr(self, '_m_ekey_mask'):
            return self._m_ekey_mask

        if self._io.size() >= 11:
            pass
            _pos = self._io.pos()
            self._io.seek(10)
            self._m_ekey_mask = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_ekey_mask', None)

    @property
    def flags(self):
        """Module flag byte; bit 0 = ConfiguredAsMajorFault, bit 2 = Inhibited.
        """
        if hasattr(self, '_m_flags'):
            return self._m_flags

        if self._io.size() >= 21:
            pass
            _pos = self._io.pos()
            self._io.seek(20)
            self._m_flags = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_flags', None)

    @property
    def ip_len(self):
        """Byte length of the IP address string at 0x32 (0 = none stored)."""
        if hasattr(self, '_m_ip_len'):
            return self._m_ip_len

        if self._io.size() > 50:
            pass
            _pos = self._io.pos()
            self._io.seek(48)
            self._m_ip_len = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_ip_len', None)

    @property
    def ip_raw(self):
        """ASCII IP address (may carry trailing NULs; a truncated blob yields the
        bytes that remain). Stored only for modules with an Ethernet upstream;
        local backplane bridges keep it in RxDataCollection instead.
        """
        if hasattr(self, '_m_ip_raw'):
            return self._m_ip_raw

        if  ((self._io.size() > 50) and (self.ip_len != 0)) :
            pass
            _pos = self._io.pos()
            self._io.seek(50)
            self._m_ip_raw = self._io.read_bytes((self.ip_len if self.ip_len <= self._io.size() - 50 else self._io.size() - 50))
            self._io.seek(_pos)

        return getattr(self, '_m_ip_raw', None)

    @property
    def major_raw(self):
        """Firmware major revision in bits 0..6; bit 7 is a flag (set = a keyed
        module uses CompatibleModule rather than ExactMatch keying).
        """
        if hasattr(self, '_m_major_raw'):
            return self._m_major_raw

        if self._io.size() >= 9:
            pass
            _pos = self._io.pos()
            self._io.seek(8)
            self._m_major_raw = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_major_raw', None)

    @property
    def minor(self):
        """Firmware minor revision."""
        if hasattr(self, '_m_minor'):
            return self._m_minor

        if self._io.size() >= 10:
            pass
            _pos = self._io.pos()
            self._io.seek(9)
            self._m_minor = self._io.read_u1()
            self._io.seek(_pos)

        return getattr(self, '_m_minor', None)

    @property
    def modid(self):
        """The module's own modid, referenced by its children's parent_modid; 0 on
        an Ethernet-family rack adapter, whose real modid is the record-header
        comment_id.
        """
        if hasattr(self, '_m_modid'):
            return self._m_modid

        if self._io.size() >= 48:
            pass
            _pos = self._io.pos()
            self._io.seek(44)
            self._m_modid = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_modid', None)

    @property
    def parent_modid(self):
        """modid of the parent module (matches the parent's own modid field)."""
        if hasattr(self, '_m_parent_modid'):
            return self._m_parent_modid

        if self._io.size() >= 26:
            pass
            _pos = self._io.pos()
            self._io.seek(22)
            self._m_parent_modid = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_parent_modid', None)

    @property
    def parent_port(self):
        """Port id on the parent module this module connects through."""
        if hasattr(self, '_m_parent_port'):
            return self._m_parent_port

        if self._io.size() >= 28:
            pass
            _pos = self._io.pos()
            self._io.seek(26)
            self._m_parent_port = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_parent_port', None)

    @property
    def product_code(self):
        if hasattr(self, '_m_product_code'):
            return self._m_product_code

        if self._io.size() >= 8:
            pass
            _pos = self._io.pos()
            self._io.seek(6)
            self._m_product_code = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_product_code', None)

    @property
    def product_type(self):
        """CIP product type."""
        if hasattr(self, '_m_product_type'):
            return self._m_product_type

        if self._io.size() >= 6:
            pass
            _pos = self._io.pos()
            self._io.seek(4)
            self._m_product_type = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_product_type', None)

    @property
    def safety_network(self):
        """6-byte little-endian CIP Safety Network Number; valid only when its
        high byte ([5]) is nonzero (safety modules).
        """
        if hasattr(self, '_m_safety_network'):
            return self._m_safety_network

        if self._io.size() >= 311:
            pass
            _pos = self._io.pos()
            self._io.seek(305)
            self._m_safety_network = self._io.read_bytes(6)
            self._io.seek(_pos)

        return getattr(self, '_m_safety_network', None)

    @property
    def slot(self):
        """Slot / address on the parent port (0xFFFFFFFF on the root CPU)."""
        if hasattr(self, '_m_slot'):
            return self._m_slot

        if self._io.size() >= 32:
            pass
            _pos = self._io.pos()
            self._io.seek(28)
            self._m_slot = self._io.read_u4le()
            self._io.seek(_pos)

        return getattr(self, '_m_slot', None)

    @property
    def vendor(self):
        if hasattr(self, '_m_vendor'):
            return self._m_vendor

        if self._io.size() >= 4:
            pass
            _pos = self._io.pos()
            self._io.seek(2)
            self._m_vendor = self._io.read_u2le()
            self._io.seek(_pos)

        return getattr(self, '_m_vendor', None)


