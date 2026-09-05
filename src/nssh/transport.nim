# SSH transport: version exchange + Binary Packet Protocol framing (RFC 4253 §4-6).
#
# Pure logic, no powpow import so it stays unit-testable. Wire it to powpow
# by keeping a `FrameDecoder` per connection (e.g. in `conn.data`) and
# feeding each `onData` chunk to `feed()`. Send encoded bytes via `send()`.

import std/sysrand
import std/sequtils

import ./codec

const
  SshVersion* = "SSH-2.0-nssh_0.1.0"
  MaxVersionLineLen* = 255
  MaxPendingBytes* = 1_048_576 ## reassembly cap before protocol error.

type
  SshTransportError* = object of ValueError

  FrameDecoder* = object
    ## Reassembly buffer for one direction. `blockSize` is the cipher
    ## block size (8 until NEWKEYS negotiates otherwise).
    buf*: seq[byte]
    blockSize*: int

proc initFrameDecoder*(blockSize = 8): FrameDecoder =
  if blockSize < 8 or blockSize > 32:
    raise newException(SshTransportError, "ssh transport: bad block size")
  result.buf = @[]
  result.blockSize = blockSize

proc pendingBytes*(d: FrameDecoder): int {.inline.} =
  result = d.buf.len

proc clear*(d: var FrameDecoder) =
  d.buf.setLen(0)

proc encodeVersionLine*(version: string): seq[byte] =
  ## `SSH-2.0-...` + CRLF.
  if version.len == 0 or version.len > MaxVersionLineLen:
    raise newException(SshTransportError, "ssh transport: bad version length")
  result = newSeq[byte](version.len + 2)
  copyMem(addr result[0], unsafeAddr version[0], version.len)
  result[version.len] = byte('\r')
  result[version.len + 1] = byte('\n')

proc parseVersionLine*(line: openArray[byte]): string =
  ## Validate `SSH-2.0-<comment> CRLF`, return the full line without CRLF.
  ## Raises on overlong lines or non-SSH peers.
  if line.len < 2 or line.len > MaxVersionLineLen + 2:
    raise newException(SshTransportError, "ssh transport: bad version line length")
  if line[^2] != byte('\r') or line[^1] != byte('\n'):
    raise newException(SshTransportError, "ssh transport: version line must end with CRLF")
  let bodyLen = line.len - 2
  if bodyLen < 8:
    raise newException(SshTransportError, "ssh transport: version line too short")
  for i in 0 ..< 7:
    if line[i] != byte("SSH-2.0"[i]):
      raise newException(SshTransportError, "ssh transport: peer is not SSH-2.0")
  result = newString(bodyLen)
  copyMem(addr result[0], unsafeAddr line[0], bodyLen)

proc findVersionLine*(buf: openArray[byte]): int =
  ## Return total bytes through CRLF if a full version line is buffered,
  ## else 0. Used before KEX when the peer may send preface lines.
  if buf.len < 2:
    return 0
  for i in 1 ..< buf.len:
    if buf[i-1] == byte('\r') and buf[i] == byte('\n'):
      return i + 1
  return 0

proc encodePacket*(payload: openArray[byte], blockSize = 8,
                   padding: openArray[byte] = [],
                   lengthInClear = false): seq[byte] =
  ## Encode one plaintext BPP packet. `padding` is caller-supplied random
  ## bytes for deterministic tests; when empty, fresh random padding is used.
  ## `lengthInClear` is for AEAD ciphers (chacha/GCM, RFC 5647, OpenSSH
  ## packet.c `len -= aadlen`) and for CTR+ETM (OpenSSH sends the length
  ## in clear as AAD there too): the 4 length bytes travel unencrypted, so
  ## packlen itself (not 4+packlen) must be block-aligned.
  if blockSize < 8:
    raise newException(SshTransportError, "ssh transport: bad block size")
  if payload.len + 5 > MaxSshPacketLen:
    raise newException(SshTransportError, "ssh transport: payload too large")
  # padding_length field (1) + payload + padding must fill blocks.
  let alignBase = if lengthInClear: payload.len + 1 else: payload.len + 5
  var padLen = blockSize - (alignBase mod blockSize)
  if padLen < 4:
    padLen += blockSize
  if padding.len != 0 and padding.len != padLen:
    raise newException(SshTransportError, "ssh transport: wrong padding length")
  let total = 4 + 1 + payload.len + padLen
  result = newSeq[byte](total)
  let packetLen = uint32(1 + payload.len + padLen)
  result[0] = byte(packetLen shr 24)
  result[1] = byte(packetLen shr 16)
  result[2] = byte(packetLen shr 8)
  result[3] = byte(packetLen)
  result[4] = byte(padLen)
  if payload.len > 0:
    copyMem(addr result[5], unsafeAddr payload[0], payload.len)
  if padLen > 0:
    if padding.len == 0:
      var rnd = urandom(padLen)
      copyMem(addr result[5 + payload.len], addr rnd[0], padLen)
    else:
      copyMem(addr result[5 + payload.len], unsafeAddr padding[0], padLen)

proc tryDecodePacket*(buf: openArray[byte], blockSize = 8): tuple[found: bool,
    payload: seq[byte], consumed: int] =
  ## Decode one packet from the front of `buf` without mutating it.
  if buf.len < 4:
    return (false, @[], 0)
  let packetLen = (uint32(buf[0]) shl 24) or (uint32(buf[1]) shl 16) or
                  (uint32(buf[2]) shl 8) or uint32(buf[3])
  if packetLen < 12 or packetLen > uint32(MaxSshPacketLen):
    raise newException(SshTransportError, "ssh transport: bad packet_length")
  let total = 4 + int(packetLen)
  if total mod blockSize != 0:
    raise newException(SshTransportError, "ssh transport: packet not block aligned")
  if buf.len < total:
    return (false, @[], 0)
  let padLen = int(buf[4])
  if padLen < 4 or padLen >= int(packetLen) - 1:
    raise newException(SshTransportError, "ssh transport: bad padding_length")
  let payloadLen = int(packetLen) - 1 - padLen
  result = (true, buf.toOpenArray(5, 5 + payloadLen - 1).toSeq(), total)

proc feed*(d: var FrameDecoder, chunk: openArray[byte]): seq[seq[byte]] =
  ## Append a powpow `onData` chunk, return all complete payloads.
  if chunk.len > 0:
    if d.buf.len + chunk.len > MaxPendingBytes:
      raise newException(SshTransportError, "ssh transport: reassembly overflow")
    let off = d.buf.len
    d.buf.setLen(off + chunk.len)
    copyMem(addr d.buf[off], unsafeAddr chunk[0], chunk.len)
  result = @[]
  while true:
    let (found, payload, consumed) = tryDecodePacket(d.buf, d.blockSize)
    if not found:
      break
    result.add(payload)
    let left = d.buf.len - consumed
    if left > 0:
      copyMem(addr d.buf[0], addr d.buf[consumed], left)
    d.buf.setLen(left)
