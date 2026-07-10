meta:
  id: module_identity
  endian: le

doc: |
  Module identity blob of a cip-0x69 module record: extended attribute 0x001,
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

instances:
  class_word:
    pos: 0x00
    type: u2
    if: _io.size >= 0x02
    doc: |
      Identity class word; drives the <Communications> emit gate (structural
      bus/port classes never emit it). 0x0200/0x0201 = drive module (the
      drive ADC word applies).
  vendor:
    pos: 0x02
    type: u2
    if: _io.size >= 0x04
  product_type:
    pos: 0x04
    type: u2
    if: _io.size >= 0x06
    doc: CIP product type.
  product_code:
    pos: 0x06
    type: u2
    if: _io.size >= 0x08
  major_raw:
    pos: 0x08
    type: u1
    if: _io.size >= 0x09
    doc: |
      Firmware major revision in bits 0..6; bit 7 is a flag (set = a keyed
      module uses CompatibleModule rather than ExactMatch keying).
  minor:
    pos: 0x09
    type: u1
    if: _io.size >= 0x0a
    doc: Firmware minor revision.
  ekey_mask:
    pos: 0x0a
    type: u1
    if: _io.size >= 0x0b
    doc: |
      Electronic keying mask (0x1f = all identity fields keyed); 0 = keying
      disabled.
  flags:
    pos: 0x14
    type: u1
    if: _io.size >= 0x15
    doc: |
      Module flag byte; bit 0 = ConfiguredAsMajorFault, bit 2 = Inhibited.
  parent_modid:
    pos: 0x16
    type: u4
    if: _io.size >= 0x1a
    doc: modid of the parent module (matches the parent's own modid field).
  parent_port:
    pos: 0x1a
    type: u2
    if: _io.size >= 0x1c
    doc: Port id on the parent module this module connects through.
  slot:
    pos: 0x1c
    type: u4
    if: _io.size >= 0x20
    doc: Slot / address on the parent port (0xFFFFFFFF on the root CPU).
  config_ref:
    pos: 0x20
    type: u4
    if: _io.size >= 0x24
    doc: |
      Long-header ConfigData holder link; resolves to the RxDataCollection
      holder whose main_record@0x28 equals it.
  data_link:
    pos: 0x24
    type: u4
    if: _io.size >= 0x28
    doc: |
      comment_id link (low u16) to the module's backing RxDataCollection
      child, which carries the port topology / <public> / <CF> payloads.
  modid:
    pos: 0x2c
    type: u4
    if: _io.size >= 0x30
    doc: |
      The module's own modid, referenced by its children's parent_modid; 0 on
      an Ethernet-family rack adapter, whose real modid is the record-header
      comment_id.
  ip_len:
    pos: 0x30
    type: u2
    if: _io.size > 0x32
    doc: Byte length of the IP address string at 0x32 (0 = none stored).
  ip_raw:
    pos: 0x32
    size: '(ip_len <= _io.size - 0x32 ? ip_len : _io.size - 0x32)'
    if: _io.size > 0x32 and ip_len != 0
    doc: |
      ASCII IP address (may carry trailing NULs; a truncated blob yields the
      bytes that remain). Stored only for modules with an Ethernet upstream;
      local backplane bridges keep it in RxDataCollection instead.
  safety_network:
    pos: 305
    size: 6
    if: _io.size >= 311
    doc: |
      6-byte little-endian CIP Safety Network Number; valid only when its
      high byte ([5]) is nonzero (safety modules).
  config_script_cid:
    pos: 556
    type: u2
    if: _io.size >= 558
    doc: comment_id of the ConfigScript RxDataCollection holder (0 = none).
  config_data_oid:
    pos: 624
    type: u4
    if: _io.size >= 628
    doc: Short-header ConfigData holder object id (fallback pointer).
