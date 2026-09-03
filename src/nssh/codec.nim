# SSH binary codec per RFC 4251 §5.
#
# Wire types: boolean, byte, uint32, uint64, string (BE uint32 len + bytes),
# mpint (BE uint32 len + two's complement, minimal), name-list
# (comma-joined string). All integers big-endian.
#
# Style follows openparser BE idiom (plist/common read/writeUIntBE) and
# fbe/bson bounds-checked pos/limit parsing, but BE-only and SSH-shaped.

import std/strutils
import std/sequtils

type
  SshCodecError* = object of ValueError

const
  MaxSshStringLen* = 1_048_576 ## 1 MiB cap for a single string/mpint payload.
  MaxSshPacketLen* = 35_000    ## RFC 4253 §6.1 minimum max packet size.

type
  Reader* = object
    ## Incremental cursor over an immutable input copy.
    data*: seq[byte]
    pos*: int

  Writer* = object
    ## Growable BE encoder. Reserve + patchUint32At supports packet framing.
    buf*: seq[byte]

template ensureReader(r: Reader, n: int) =
  if r.pos < 0 or n < 0 or r.pos + n > r.data.len:
    raise newException(SshCodecError, "ssh codec: short buffer")

proc initReader*(s: openArray[byte]): Reader =
  result.data = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result.data[0], unsafeAddr s[0], s.len)
  result.pos = 0

proc initReader*(s: string): Reader =
  result.data = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result.data[0], unsafeAddr s[0], s.len)
  result.pos = 0

proc remaining*(r: Reader): int {.inline.} =
  result = r.data.len - r.pos

proc consumed*(r: Reader): int {.inline.} =
  result = r.pos

proc isExhausted*(r: Reader): bool {.inline.} =
  result = r.pos == r.data.len

proc readByte*(r: var Reader): byte =
  ensureReader(r, 1)
  result = r.data[r.pos]
  inc r.pos

proc readBool*(r: var Reader): bool =
  result = readByte(r) != 0

proc readUint32*(r: var Reader): uint32 =
  ensureReader(r, 4)
  let d = r.data
  let p = r.pos
  result = (uint32(d[p]) shl 24) or (uint32(d[p+1]) shl 16) or
           (uint32(d[p+2]) shl 8) or uint32(d[p+3])
  r.pos += 4

proc readUint64*(r: var Reader): uint64 =
  ensureReader(r, 8)
  let d = r.data
  let p = r.pos
  result = (uint64(d[p]) shl 56) or (uint64(d[p+1]) shl 48) or
           (uint64(d[p+2]) shl 40) or (uint64(d[p+3]) shl 32) or
           (uint64(d[p+4]) shl 24) or (uint64(d[p+5]) shl 16) or
           (uint64(d[p+6]) shl 8) or uint64(d[p+7])
  r.pos += 8

proc readRaw*(r: var Reader, n: int): seq[byte] =
  if n < 0:
    raise newException(SshCodecError, "ssh codec: negative length")
  ensureReader(r, n)
  result = r.data[r.pos ..< r.pos + n]
  r.pos += n

proc readString*(r: var Reader): seq[byte] =
  ## RFC 4251 `string`: uint32 length + bytes (no NUL).
  let n = int(readUint32(r))
  if n > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: string too large")
  result = readRaw(r, n)

proc readStringStr*(r: var Reader): string =
  let b = readString(r)
  result = newString(b.len)
  if b.len > 0:
    copyMem(addr result[0], unsafeAddr b[0], b.len)

proc readMpint*(r: var Reader): seq[byte] =
  ## Returns the minimal two's-complement payload bytes as on the wire
  ## (including a leading zero when present). Call `mpintToUnsigned`
  ## to strip it for KEX math.
  let n = int(readUint32(r))
  if n > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: mpint too large")
  result = readRaw(r, n)

proc readNameList*(r: var Reader): seq[string] =
  let s = readStringStr(r)
  if s.len == 0:
    return @[]
  result = s.split(',')

proc initWriter*(): Writer =
  result.buf = @[]

proc len*(w: Writer): int {.inline.} =
  result = w.buf.len

proc writeByte*(w: var Writer, v: byte) =
  w.buf.add(v)

proc writeBool*(w: var Writer, v: bool) =
  w.buf.add(if v: 1'u8 else: 0'u8)

proc writeUint32*(w: var Writer, v: uint32) =
  w.buf.add(byte(v shr 24))
  w.buf.add(byte(v shr 16))
  w.buf.add(byte(v shr 8))
  w.buf.add(byte(v))

proc writeUint64*(w: var Writer, v: uint64) =
  w.buf.add(byte(v shr 56))
  w.buf.add(byte(v shr 48))
  w.buf.add(byte(v shr 40))
  w.buf.add(byte(v shr 32))
  w.buf.add(byte(v shr 24))
  w.buf.add(byte(v shr 16))
  w.buf.add(byte(v shr 8))
  w.buf.add(byte(v))

proc writeRaw*(w: var Writer, s: openArray[byte]) =
  if s.len == 0:
    return
  let off = w.buf.len
  w.buf.setLen(off + s.len)
  copyMem(addr w.buf[off], unsafeAddr s[0], s.len)

proc writeString*(w: var Writer, s: openArray[byte]) =
  if s.len > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: string too large")
  writeUint32(w, uint32(s.len))
  writeRaw(w, s)

proc writeString*(w: var Writer, s: string) =
  if s.len > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: string too large")
  writeUint32(w, uint32(s.len))
  if s.len == 0:
    return
  let off = w.buf.len
  w.buf.setLen(off + s.len)
  copyMem(addr w.buf[off], unsafeAddr s[0], s.len)

proc mpintWireLen(x: openArray[byte]): tuple[pad: bool, start: int] =
  ## Strip leading zeroes; report whether a 0x00 pad byte is needed
  ## (high bit set) and where significant bytes start.
  var start = 0
  while start < x.len and x[start] == 0:
    inc start
  if start == x.len:
    return (false, x.len) # value zero -> zero-length mpint
  result = ((x[start] and 0x80) != 0, start)

proc writeMpint*(w: var Writer, x: openArray[byte]) =
  ## Encode an unsigned big-endian integer as RFC 4251 mpint.
  let (pad, start) = mpintWireLen(x)
  if start >= x.len:
    writeUint32(w, 0)
    return
  let sigLen = x.len - start
  let total = sigLen + (if pad: 1 else: 0)
  if total > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: mpint too large")
  writeUint32(w, uint32(total))
  if pad:
    w.buf.add(0'u8)
  writeRaw(w, x.toOpenArray(start, x.len - 1))

proc writeMpintPayload*(w: var Writer, payload: openArray[byte]) =
  ## Write an already-minimal two's-complement payload (e.g. forwarded).
  if payload.len > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: mpint too large")
  writeUint32(w, uint32(payload.len))
  writeRaw(w, payload)

proc writeNameList*(w: var Writer, names: openArray[string]) =
  var total = 0
  for i, n in names:
    total += n.len
    if i < names.len - 1:
      inc total # comma
  if total > MaxSshStringLen:
    raise newException(SshCodecError, "ssh codec: name-list too large")
  writeUint32(w, uint32(total))
  for i, n in names:
    if i > 0:
      w.buf.add(byte(','))
    if n.len == 0:
      continue
    let off = w.buf.len
    w.buf.setLen(off + n.len)
    copyMem(addr w.buf[off], unsafeAddr n[0], n.len)

proc reserve*(w: var Writer, n: int): int =
  ## Reserve `n` zero bytes, return offset for later `patchUint32At`.
  result = w.buf.len
  w.buf.setLen(result + n)
  for i in result ..< result + n:
    w.buf[i] = 0

proc patchUint32At*(w: var Writer, at: int, v: uint32) =
  if at < 0 or at + 4 > w.buf.len:
    raise newException(SshCodecError, "ssh codec: patch out of range")
  w.buf[at] = byte(v shr 24)
  w.buf[at+1] = byte(v shr 16)
  w.buf[at+2] = byte(v shr 8)
  w.buf[at+3] = byte(v)

proc toBytes*(w: Writer): seq[byte] {.inline.} =
  result = w.buf

proc mpintToUnsigned*(payload: openArray[byte]): seq[byte] =
  ## Strip a single leading zero pad byte used to keep mpint positive.
  ## Does not fully validate minimal encoding; use `isMinimalMpint` for that.
  if payload.len > 0 and payload[0] == 0:
    result = payload.toOpenArray(1, payload.len - 1).toSeq()
  else:
    result = payload.toSeq()

proc isMinimalMpint*(payload: openArray[byte]): bool =
  ## Check RFC 4251 minimal encoding: no unnecessary leading 0x00/0xFF.
  if payload.len == 0:
    return true
  if payload[0] == 0x00:
    if payload.len == 1:
      return false # zero must be empty, not 0x00
    return (payload[1] and 0x80) != 0
  return true

proc ctEqual*(a, b: openArray[byte]): bool =
  ## Constant-time equality for MAC/tag/signature checks.
  if a.len != b.len:
    return false
  if a.len == 0:
    return true
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  result = diff == 0
