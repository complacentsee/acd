meta:
  id: short_comps
  endian: le

doc: |
  V10..V21 "short" comps record layout, shared by the FAFA (0xFAFA primary)
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

instances:
  seq_number:
    pos: 0x08
    type: u2
    doc: Per-collection ordinal (cosmetic for export).
  record_type:
    pos: 0x0a
    type: u2
    doc: 256 = component, 0 = collection (same position as the long header).
  object_id:
    pos: 0x0c
    type: u4
    doc: self_lcg / CompUId (the long header has a zero u32 here instead).
  parent_id:
    pos: 0x10
    type: u4
  record_name:
    pos: 0x14
    type: strz_utf_16
    size: 82
    doc: NUL-terminated UTF-16LE name, scanned within an 82-byte window.
  record_buffer:
    pos: 0x5e
    size-eos: true
    doc: RxGeneric body (14B prelude + 60B main_record + ext-attr tail).

types:
  strz_utf_16:
    seq:
      - id: value
        size: 2 * (code_units.size - 1)
        type: str
        encoding: UTF-16LE
      - id: term
        type: u2
        valid: 0
    instances:
      code_units:
        pos: _io.pos
        type: u2
        repeat: until
        repeat-until: _ == 0
