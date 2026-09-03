import std/unittest

import nssh/transport

test "version line round trip + reject non-SSH":
  let enc = encodeVersionLine("SSH-2.0-nssh_0.1.0")
  check enc[^2] == byte('\r')
  check enc[^1] == byte('\n')
  check parseVersionLine(enc) == "SSH-2.0-nssh_0.1.0"
  expect SshTransportError:
    discard parseVersionLine(encodeVersionLine("SSH-1.0-old"))

test "findVersionLine scans preface":
  var buf: seq[byte] = @[]
  for c in "junk\r\nSSH-2.0-x\r\nrest":
    buf.add(byte(c))
  check findVersionLine(buf) == len("junk\r\n")
  check findVersionLine(@[byte('S'), byte('S')]) == 0

test "packet round trip with fixed padding, split feed":
  let payload = @[byte(20), 1, 2, 3]
  let pad = @[9'u8, 9, 9, 9, 9, 9, 9]
  # payload 4 + 5 = 9 -> pad = 8 - 1 = 7
  let pkt = encodePacket(payload, 8, pad)
  check pkt.len mod 8 == 0
  var d = initFrameDecoder(8)
  let half = pkt.len div 2
  check d.feed(pkt.toOpenArray(0, half - 1)).len == 0
  let got = d.feed(pkt.toOpenArray(half, pkt.len - 1))
  check got.len == 1
  check got[0] == payload
  check d.pendingBytes() == 0

test "two packets back to back":
  let a = encodePacket(@[byte(20)], 8, @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  let b = encodePacket(@[byte(21)], 8, @[7'u8, 8, 9, 10, 11, 12, 13, 14, 15, 16])
  var combo = a & b
  var d = initFrameDecoder()
  let got = d.feed(combo)
  check got.len == 2
  check got[0] == @[byte(20)]
  check got[1] == @[byte(21)]

test "bad padding rejected":
  let good = encodePacket(@[byte(20)], 8, @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10])
  var bad = good
  bad[4] = 2 # padding_length < 4
  var d = initFrameDecoder()
  expect SshTransportError:
    discard d.feed(bad)

test "aead length-in-clear padding aligns packlen (OpenSSH packet.c rule)":
  # SERVICE_ACCEPT payload: 1 + 4 + 12 = 17 bytes.
  let payload = @[byte(6), 0, 0, 0, 12, 115, 115, 104, 45, 117, 115, 101,
                  114, 97, 117, 116, 104]
  let pkt = encodePacket(payload, 8, lengthInClear = true)
  let packlen = (int(pkt[0]) shl 24) or (int(pkt[1]) shl 16) or
                (int(pkt[2]) shl 8) or int(pkt[3])
  check packlen mod 8 == 0
  check int(pkt[4]) >= 4 # padding_length minimum still holds
  # classic mode keeps (4 + packlen) aligned instead
  let classic = encodePacket(payload, 8)
  let cpacklen = (int(classic[0]) shl 24) or (int(classic[1]) shl 16) or
                 (int(classic[2]) shl 8) or int(classic[3])
  check (4 + cpacklen) mod 8 == 0
  check cpacklen mod 8 == 4 # AEAD receivers would reject this alignment
  # GCM shape: packlen multiple of 16
  let gpkt = encodePacket(payload, 16, lengthInClear = true)
  let gpacklen = (int(gpkt[0]) shl 24) or (int(gpkt[1]) shl 16) or
                 (int(gpkt[2]) shl 8) or int(gpkt[3])
  check gpacklen mod 16 == 0
