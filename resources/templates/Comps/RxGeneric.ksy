meta:
  id: rx_generic
  endian: le

instances:
  record_buffer:
    pos: 0x0E
    size: 0x3C
  # The extended-attribute tail is parsed LAZILY so a record with an encrypted
  # (source-protected) or garbage tail still yields its plaintext prelude and
  # main_record; accessing extended_records raises exactly where eager parsing
  # used to.
  ext_tail:
    pos: 0x52
    type: ext_tail
  extended_records:
    value: ext_tail.records
  last_attribute_record:
    value: ext_tail.last

seq:
  - id: parent_id
    type: u4
  - id: unique_tag_identifier
    type: u4
  - id: record_format_version
    type: u2
  - id: cip_type
    type: u2
  - id: comment_id
    type: u2
  - id: main_record
    size: 0x3C
    type:
      switch-on: cip_type
      cases:
        0x68: rx_tag
        0x6B: rx_tag
        _: unknown
  - id: len_record
    type: u4
  - id: count_record
    type: u4

types:
  ext_tail:
    seq:
      - id: records
        type: attribute_record
        repeat: expr
        repeat-expr: _parent.count_record - 1
      # The record's FINAL attribute is not covered by the count_record - 1
      # loop; it trails the counted records with data = len_value - 4 bytes.
      # Both guards mirror the tolerant hand-walkers: a short or absent tail
      # skips the field instead of failing the whole parse.
      - id: last
        type: last_attribute_record
        if: _io.size - _io.pos >= 8
  attribute_record:
    seq:
      - id: attribute_id
        type: u4
      - id: len_value
        type: u4
      - id: value
        size: len_value
  last_attribute_record:
    seq:
      - id: attribute_id
        type: u4
      - id: len_value
        type: u4
      - id: value
        size: len_value - 4
        if: len_value >= 4 and len_value - 4 <= _io.size - _io.pos
  rx_tag:
    instances:
      valid:
        value: true
      dimension_1:
        pos: 0x0C
        type: u4
      dimension_2:
        pos: 0x10
        type: u4
      dimension_3:
        pos: 0x14
        type: u4
      data_type:
        pos: 0x1C
        type: u4
      radix:
        pos: 0x20
        type: u2
      external_access:
        pos: 0x22
        type: u2
      data_table_instance:
        pos: 0x24
        type: u4
      cip_data_type:
        pos: 0x34
        type: u2

  unknown:
    seq:
      - id: body
        size: 0x3C

  rx_map_device:
    instances:
      vendor_id:
        pos: 0x02
        type: u2
      product_type:
        pos: 0x04
        type: u2
      product_code:
        pos: 0x06
        type: u2
      parent_module:
        pos: 0x16
        type: u4
      slot_no:
        pos: 0x20
        type: u4
      module_id:
        pos: 0x24
        type: u4
