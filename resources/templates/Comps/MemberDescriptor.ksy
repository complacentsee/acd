meta:
  id: member_descriptor
  endian: le

doc: |
  Datatype member descriptor: extended attribute 0x6E + i (one per member,
  in member order) of a datatype record (cip-0x6c). Nominally 168 (0xA8)
  bytes but routinely truncated, so every field is size-guarded and reads
  as absent (None) when the blob ends before it; call sites keep their own
  degradation rules (skip the member / degraded member / legacy 0x74
  ExternalAccess fallback).

  The same layout serves V24+ long-header projects (whose members also
  exist as child comps records; the descriptor carries the field data) and
  V10..V21 short-header projects (whose members exist ONLY inline as these
  attributes, with the member name at offset 0).

instances:
  name_raw:
    pos: 0
    size: '(_io.size < 0x54 ? _io.size : 0x54)'
    if: _io.size >= 2
    doc: |
      NUL-terminated UTF-16LE member name, meaningful on short-header
      inline members only (long-header members are named by their comps
      record). The field spans 0..0x53; decoding (first-NUL stop, lenient
      on malformed pairs) stays in Python (_decode_utf16z).
  radix:
    pos: 0x54
    type: u4
    if: _io.size >= 0x58
    doc: Display radix enum (see radix_enum).
  data_type_id:
    pos: 0x58
    type: u4
    if: _io.size >= 0x5c
    doc: comps object_id of the member's data type.
  dimension:
    pos: 0x5c
    type: u4
    if: _io.size >= 0x60
    doc: |
      Array dimension (0 = scalar). Raw value: some non-array scalar
      members of predefined types carry garbage here (e.g. 0x20000 /
      0xFFFC0000), which call sites clamp to 0; a BIT overlay reuses the
      slot for a bit offset and forces dimension 0.
  offset:
    pos: 0x60
    type: u4
    if: _io.size >= 0x64
    doc: |
      Byte offset of the member's data within the datatype; keys the
      offset->name map BIT members resolve their backing field through.
  bit_number:
    pos: 0x64
    type: u4
    if: _io.size >= 0x68
    doc: Bit index within the backing word (BIT overlay members).
  host_ordinal:
    pos: 0x68
    type: u4
    if: _io.size >= 0x6c
    doc: |
      0x800 marks a real standalone BOOL / backing member; any other value
      on a BOOL member marks a BIT overlay. For ProductDefined/IO types it
      is the member-collection ordinal of the host word the bit overlays;
      for user types 1 selects the exact-offset lookup, else the
      preceding-hidden-backing fallback.
  target_key:
    pos: 0x6c
    type: u4
    if: _io.size >= 0x70
    doc: |
      Byte offset of the backing field a BIT overlay targets; 0xFFFFFFFF
      when absent (real BOOLs and the host_ordinal patterns).
  hidden:
    pos: 0x70
    type: u4
    if: _io.size >= 0x74
    doc: Nonzero = hidden member (e.g. a bit-backing SINT host word).
  legacy_access_word:
    pos: 0x74
    type: u4
    if: _io.size >= 0x78
    doc: |
      Legacy ExternalAccess enum slot -- uniformly 1 on records that carry
      the real byte at 0xA0; used only as the fallback when the descriptor
      is too short to hold 0xA0. Its presence (size >= 0x78) doubles as
      the completeness gate of the old fixed-offset readers.
  external_access_byte:
    pos: 0xa0
    type: u1
    if: _io.size >= 0xa1
    doc: 'ExternalAccess: 0 = Read/Write, 2 = Read Only, 3 = None.'
