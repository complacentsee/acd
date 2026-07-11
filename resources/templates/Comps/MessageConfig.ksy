meta:
  id: message_config
  endian: le

doc: |
  MESSAGE tag configuration struct: extended attribute 0x1 of the tag's
  cip-0x6a backing record (object_id == the tag's data_table_instance).
  354 bytes on every decodable pool record -- the renderer gates on that
  exact length before decoding (a different length marks a safety/variant
  config it deliberately does not emit). Fields are nevertheless
  size-guarded so a truncated buffer reads as absent rather than raising.

  The UTF-16 member references (LocalElement 0x65, DestinationTag 0x70,
  RemoteElement 0x67) are sibling attributes, not part of this struct.

instances:
  requested_length:
    pos: 139
    type: u2
    if: _io.size >= 141
    doc: RequestedLength (bytes).
  connected_flag:
    pos: 143
    type: u1
    if: _io.size >= 144
    doc: ConnectedFlag; 1 also enables CacheConnections on CIP families.
  path_size:
    pos: 144
    type: u2
    if: _io.size >= 146
    doc: Byte length of the CIP ConnectionPath EPATH at 146.
  epath:
    pos: 146
    size: path_size
    if: '_io.size >= 146 and path_size != 0 and path_size < 250 and 146 + path_size <= _io.size'
    doc: |
      The ConnectionPath EPATH bytes, present only when the declared size is
      plausible (0 < size < 250) and fully contained -- the same rule the
      renderer applied; resolved against the module topology in Python.
  large_packet_flags:
    pos: 281
    type: u1
    if: _io.size >= 282
    doc: Bit 1 = LargePacketUsage (CIP Generic).
  service_byte:
    pos: 330
    type: u1
    if: _io.size >= 331
    doc: |
      Low byte of service_code: the family sub-type discriminator (e.g.
      76/77 = CIP Data Table Read/Write under family 2).
  service_code:
    pos: 330
    type: u2
    if: _io.size >= 332
    doc: Full CIP ServiceCode (CIP Generic renders it as 16#xxxx).
  object_type:
    pos: 332
    type: u2
    if: _io.size >= 334
  target_object:
    pos: 334
    type: u4
    if: _io.size >= 338
  attribute_number:
    pos: 338
    type: u2
    if: _io.size >= 340
  family:
    pos: 353
    type: u1
    if: _io.size >= 354
    doc: |
      MessageType family: 0 Unconfigured, 1 CIP Generic, 2 CIP Data Table,
      4 SLC, 6 PLC5, 7 Module Reconfigure.
