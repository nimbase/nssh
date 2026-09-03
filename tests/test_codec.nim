import std/unittest

import nssh/codec

test "uint32 BE round trip":
  var w = initWriter()
  w.writeUint32(0x12345678'u32)
  w.writeUint32(0'u32)
  w.writeUint32(0xFFFFFFFF'u32)
  var r = initReader(w.toBytes())
  check r.readUint32() == 0x12345678'u32
  check r.readUint32() == 0'u32
  check r.readUint32() == 0xFFFFFFFF'u32
  check r.isExhausted()

test "uint64 + bool + byte round trip":
  var w = initWriter()
  w.writeUint64(0x0102030405060708'u64)
  w.writeBool(true)
  w.writeBool(false)
  w.writeByte(0x7F)
  var r = initReader(w.toBytes())
  check r.readUint64() == 0x0102030405060708'u64
  check r.readBool() == true
  check r.readBool() == false
  check r.readByte() == 0x7F

test "string round trip incl empty":
  var w = initWriter()
  w.writeString("hello")
  w.writeString("")
  w.writeString(@[0'u8, 0xFF'u8, 0x00'u8])
  var r = initReader(w.toBytes())
  check r.readStringStr() == "hello"
  check r.readString() == newSeq[byte](0)
  check r.readString() == @[0'u8, 0xFF'u8, 0x00'u8]

test "mpint zero, pad bit, strip":
  var w = initWriter()
  w.writeMpint(@[])                    # zero -> empty
  w.writeMpint(@[0'u8, 0'u8])          # zero with leading zeros -> empty
  w.writeMpint(@[0x7F'u8])             # no pad
  w.writeMpint(@[0x80'u8])             # pad with 0x00
  w.writeMpint(@[0'u8, 0x80'u8, 0x01'u8]) # leading zero stripped, then pad kept minimal
  var r = initReader(w.toBytes())
  check r.readMpint() == newSeq[byte](0)
  check r.readMpint() == newSeq[byte](0)
  check r.readMpint() == @[0x7F'u8]
  check r.readMpint() == @[0'u8, 0x80'u8]
  let p = r.readMpint()
  check p == @[0'u8, 0x80'u8, 0x01'u8]
  check mpintToUnsigned(p) == @[0x80'u8, 0x01'u8]
  check r.isExhausted()

test "mpint minimal-encoding checks":
  check isMinimalMpint(@[]) == true
  check isMinimalMpint(@[0x7F'u8]) == true
  check isMinimalMpint(@[0'u8, 0x80'u8]) == true
  check isMinimalMpint(@[0'u8]) == false
  check isMinimalMpint(@[0'u8, 0x7F'u8]) == false

test "name-list round trip":
  var w = initWriter()
  w.writeNameList(["curve25519-sha256", "diffie-hellman-group14-sha256"])
  w.writeNameList(newSeq[string](0))
  var r = initReader(w.toBytes())
  check r.readNameList() == @["curve25519-sha256", "diffie-hellman-group14-sha256"]
  check r.readNameList() == newSeq[string](0)

test "short buffer raises, ctEqual is constant-time":
  var r = initReader(@[0'u8, 1'u8])
  expect SshCodecError:
    discard r.readUint32()
  check ctEqual(@[1'u8, 2'u8], @[1'u8, 2'u8])
  check not ctEqual(@[1'u8, 2'u8], @[1'u8, 3'u8])
  check not ctEqual(@[1'u8], @[1'u8, 2'u8])
  check ctEqual(newSeq[byte](0), newSeq[byte](0))

test "reserve + patchUint32At for packet framing":
  var w = initWriter()
  let at = w.reserve(4)
  w.writeString("abc")
  w.patchUint32At(at, uint32(w.len() - 4))
  var r = initReader(w.toBytes())
  check r.readUint32() == 7'u32 # 4 len + 3 bytes
  check r.readStringStr() == "abc"
