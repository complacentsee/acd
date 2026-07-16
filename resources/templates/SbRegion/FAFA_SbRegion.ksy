meta:
  id: fafa_sbregions
  endian: le
  tags:
    - version: 33
seq:
  - id: record_length
    type: u4
  - id: header
    type: header
  - id: len_record_buffer
    type: u4
  - id: record_buffer
    size: len_record_buffer
  # On a source-protected rung len_record_buffer is the PLAINTEXT length, not the
  # length of the stored (encrypted) buffer, so record_buffer is cut short and the
  # ciphertext continues here. record_buffer + trailing is the true buffer; on an
  # unprotected record trailing is empty.
  - id: trailing
    size-eos: true
types:
  header:
     seq:
      - id: sb_regions
        type: u2
      - id: identifier
        type: u4
      - id: language_type
        type: strz
        size: 41
        encoding: UTF-8
