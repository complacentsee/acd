meta:
  id: fdfd_comps
  endian: le
  tags:
    - version: 33
seq:
  # The header's last field is the 124-byte record_name window at 0x18, so the
  # header ends at 0x18 + 124 = 148 -- the same body offset as the FAFA form
  # (u4 record_length + 144-byte header). The record_buffer that follows is the
  # RxGeneric body; reading it at 148 yields the ordinary
  # prelude/main_record/ext-attr layout (the historical 155 over-counted by 7
  # and shifted every FDFD body). See P6.9: every consumer that reads an
  # FDFD-winner (dead-relic) body is liveness-gated (C2-C4) before this flip.
  - id: header
    type: header
    size: 148
  - id: record_buffer
    size-eos: true
types:
  header:
    instances:
      seq_number:
        pos: 0x04
        type: u2
      record_type:
        pos: 0x0A
        type: u2
      object_id:
        pos: 0x10
        type: u4
      parent_id:
        pos: 0x14
        type: u4
      record_name:
        pos: 0x18
        type: strz_utf_16
        size: 124

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
params:
  - id: record_length
    type: u4