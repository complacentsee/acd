meta:
  id: fafa_coments
  endian: le
  tags:
    - version: 33
instances:
  lookup_id:
    pos: 0x1B
    type: u2
  sub_record_type:
    pos: 0x29
    type: u2

seq:
  - id: record_length
    type: u4
  - id: header
    type: header
    size: 0x0A
  # Long-header (V24+) record bodies. record_type 1/2 are own-description
  # records; 3/4/13/14 are the classic operand-comment types; 12 is UDI
  # metadata (kept raw -- its body has its own layout, parsed in Python);
  # 23/25 are controller records. Every OTHER record_type observed in the
  # corpus (5/6/7/8 member/bit/array-element comments and higher ordinals)
  # shares the utf_16_record operand layout, so it is the switch default.
  # The default parses eagerly: a truncated/unterminated body raises at
  # from_bytes, and the tolerant hand walkers in acd.record.comments
  # (_parse_long_operand_body plus the operand validation gates) remain
  # the decoders of record -- the grammar formalizes the layout.
  #
  # V10..V21 short-header records share this HEADER but not these bodies;
  # their layouts are declared below (short_operand_record /
  # short_desc_record) for reference and are deliberately not wired into
  # the switch: short-vs-long is an external, project-level discriminator
  # (acd.record.comps.record_uses_short_header), not a record_type.
  - id: body
    size: record_length - 0x0A
    type:
      switch-on: header.record_type
      cases:
        0x01: ascii_record
        0x02: ascii_record
        0x03: utf_16_record(0x0C)
        0x04: utf_16_record(0x0C)
        0x0c: raw_record
        0x0d: utf_16_record(0x0C)
        0x0e: utf_16_record(0x0C)
        0x17: controller_record
        0x19: controller_record
        _: utf_16_record(0x0C)


types:
  header:
     instances:
      seq_number:
        pos: 0x00
        type: u2
      record_type:
        pos: 0x02
        type: u2
      sub_record_length:
        pos: 0x04
        type: u2
      parent:
        pos: 0x06
        type: u4
  ascii_record:
      seq:
        - id: unknown_1
          size: 0x0D
        - id: object_id
          type: u4
        - id: unknown_2
          size: 0x0D
        - id: record_string
          type: strz
          encoding: UTF-8
  ascii_record_4:
    seq:
      - id: unknown_1
        size: 0x08
      - id: object_id
        type: u4
      - id: unknown_2
        size: 0x18
      - id: record_string
        type: strz
        encoding: UTF-8
  utf_16_record:
      params:
      - id: len_unknown_3
        type: u4
      seq:
        - id: unknown_1
          size: 0x08
        - id: object_id
          type: u4
        - id: unknown_2
          size: 0x04
        # NB: there is NO u2 length field here. An earlier revision read a
        # `len_record: u2` before tag_reference, which shifted tag_reference 2
        # bytes too far (dropping the leading operand char, e.g. "[0]" -> "0]")
        # and left record_string empty. The layout is identical to
        # controller_record: tag_reference (the operand) begins immediately after
        # unknown_2. Verified byte-for-byte on V34 rt=4 operand-comment records.
        - id: tag_reference
          type: strz_utf_16
        - id: unknown_3
          size: len_unknown_3
        - id: record_string
          type: strz
          encoding: UTF-8
  controller_record:
      seq:
        - id: unknown_1
          size: 0x08
        - id: object_id
          type: u4
        - id: unknown_2
          size: 0x04
        - id: tag_reference
          type: strz_utf_16
        - id: unknown_3
          size: 0x0C
        - id: record_string
          type: strz
          encoding: UTF-8

  raw_record:
    doc: |
      UDI metadata (record_type 12, e.g. the AOI RevisionNote): kept as raw
      bytes -- the body layout ([8B unknown][u32 id][u32 flags][UTF-16LE
      NUL-terminated UDI type][NUL padding][NUL-terminated ASCII text]) is
      parsed by acd.record.comments._parse_udi_body.
    seq:
      - id: data
        size-eos: true

  short_operand_record:
    doc: |
      V10..V21 short-header operand comment body (record_type is an ordinal
      3..36 within the parent group, not an enum). Not wired into the body
      switch -- short-vs-long is decided per project, and the tolerant hand
      walker acd.record.comments._parse_short_operand_body (with its
      structural validation gates) decodes these; declared here to document
      the layout. The operand and comment text are UTF-16LE NUL-terminated,
      starting at the odd offset 13.
    seq:
      - id: zero_prefix
        contents: [0, 0, 0, 0, 0, 0]
      - id: member_key
        type: u2
      - id: object_id
        type: u4
      - id: pad
        contents: [0]
      - id: operand
        type: strz_utf_16
      - id: record_string
        type: strz_utf_16

  short_desc_record:
    doc: |
      V10..V21 short-header own-description body (record_type 1/2): the
      component's own Description in UTF-16LE (the V24+ ascii_record decodes
      UTF-8, which mangles these). Decoded by the tolerant hand walker
      acd.record.comments._parse_short_desc_body; declared here to document
      the layout. The text starts at the odd body offset 15.
    seq:
      - id: member_ref
        type: u4
      - id: rung_content
        type: u4
      - id: object_id_region
        size: 7
      - id: record_string
        type: strz_utf_16

  strz_utf_16:
    seq:
      - id: value
        size: 2 * (code_units.size - 1)
        type: str
        encoding: utf-16le
      - id: term
        type: u2
        valid: 0
    instances:
      code_units:
        pos: _io.pos
        type: u2
        repeat: until
        repeat-until: _ == 0