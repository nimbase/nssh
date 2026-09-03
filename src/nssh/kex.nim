# SSH key exchange: curve25519-sha256 (full) + diffie-hellman-group14-sha256
# math (pure Nim, no C). Exchange hash + RFC 4253 §7.2 key expansion.
#
# Wire encoding uses nssh/codec; hashing uses nimcypher SHA-256;
# X25519 uses nimcypher/algos/x25519.

import std/options
import std/sysrand
import std/sequtils

import bigints

import nimcypher/algos/sha256 as sha256Algo
import nimcypher/algos/x25519 as x25519Algo

import nssh/codec

const
  KexCurve25519Sha256* = "curve25519-sha256"
  KexGroup14Sha256* = "diffie-hellman-group14-sha256"

type
  SshKexError* = object of ValueError

  X25519KeyPair* = object
    priv*: array[32, byte]
    pub*: array[32, byte]

# ── BE bigint helpers (unsigned, minimal; math via pure-Nim `bigints`) ─────

proc trimZeros(a: openArray[byte]): seq[byte] =
  var i = 0
  while i < a.len and a[i] == 0:
    inc i
  if i == a.len:
    return @[0'u8]
  result = a.toOpenArray(i, a.len - 1).toSeq()

proc cmpBE(a, b: openArray[byte]): int =
  let x = trimZeros(a)
  let y = trimZeros(b)
  if x.len != y.len:
    return if x.len < y.len: -1 else: 1
  for i in 0 ..< x.len:
    if x[i] != y[i]:
      return if x[i] < y[i]: -1 else: 1
  return 0

proc toBig(a: openArray[byte]): BigInt =
  ## Unsigned BE bytes -> BigInt (leading zeros skipped).
  var start = 0
  while start < a.len and a[start] == 0:
    inc start
  var limbs = newSeq[uint32]()
  var i = a.len
  while i > start:
    let j = max(start, i - 4)
    var w: uint32 = 0
    for k in j ..< i:
      w = (w shl 8) or uint32(a[k])
    limbs.add(w)
    i = j
  if limbs.len == 0:
    limbs.add(0)
  result = initBigInt(limbs)

proc fromBig(x: BigInt): seq[byte] =
  ## BigInt -> minimal unsigned BE bytes (zero as @[0]).
  if x == 0.initBigInt:
    return @[0'u8]
  var t = x
  let b256 = 256.initBigInt
  var rev: seq[byte] = @[]
  while t != 0.initBigInt:
    let (q, r) = divmod(t, b256)
    rev.add(byte(toInt[uint8](r).get()))
    t = q
  result = newSeq[byte](rev.len)
  for i in 0 ..< rev.len:
    result[i] = rev[rev.len - 1 - i]

proc modBE*(a, m: openArray[byte]): seq[byte] =
  ## a mod m, both unsigned BE.
  let mm = toBig(m)
  if mm == 0.initBigInt:
    raise newException(SshKexError, "ssh kex: modulo by zero")
  result = fromBig(toBig(a) mod mm)

proc mulModBE*(a, b, m: openArray[byte]): seq[byte] =
  let mm = toBig(m)
  if mm == 0.initBigInt:
    raise newException(SshKexError, "ssh kex: modulo by zero")
  result = fromBig((toBig(a) * toBig(b)) mod mm)

proc powModBE*(base, exp, modp: openArray[byte]): seq[byte] =
  ## Binary square-and-multiply via `bigints.powmod`. Handles 2048-bit DH.
  let mm = toBig(modp)
  if mm == 0.initBigInt:
    raise newException(SshKexError, "ssh kex: modulo by zero")
  result = fromBig(powmod(toBig(base), toBig(exp), mm))

# ── Group14 (RFC 3526 2048-bit MODP, g=2) ──────────────────────────────────

const Group14PrimeHex* =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" &
  "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" &
  "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" &
  "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" &
  "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" &
  "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" &
  "83655D23DCA3AD961C62F356208552BB9ED529077096966" &
  "D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" &
  "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" &
  "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" &
  "15728E5A8AACAA68FFFFFFFFFFFFFFFF"

proc hexToBytes(s: string): seq[byte] =
  proc hv(c: char): int =
    case c
    of '0'..'9': int(c) - int('0')
    of 'a'..'f': int(c) - int('a') + 10
    of 'A'..'F': int(c) - int('A') + 10
    else: raise newException(SshKexError, "ssh kex: bad hex")
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(hv(s[2*i]) * 16 + hv(s[2*i+1]))

proc group14Prime*(): seq[byte] =
  result = hexToBytes(Group14PrimeHex)

proc dhPrivate*(bits = 256): seq[byte] =
  ## Random DH private in [1, p-1], `bits` of entropy (default 256).
  if bits < 256:
    raise newException(SshKexError, "ssh kex: DH private too small")
  let n = bits div 8
  let rnd = urandom(n)
  result = trimZeros(rnd)
  if result.len == 1 and result[0] == 0:
    result = @[1'u8]

proc dhPublic*(priv: openArray[byte], prime: openArray[byte]): seq[byte] =
  result = powModBE(@[2'u8], priv, prime)

proc dhShared*(peerPub, priv, prime: openArray[byte]): seq[byte] =
  if cmpBE(peerPub, @[1'u8]) <= 0 or cmpBE(peerPub, prime) >= 0:
    raise newException(SshKexError, "ssh kex: peer DH value out of range")
  result = powModBE(peerPub, priv, prime)

# ── Curve25519 ─────────────────────────────────────────────────────────────

proc x25519GenKey*(): X25519KeyPair =
  let rnd = urandom(32)
  var priv: array[32, byte]
  copyMem(addr priv[0], unsafeAddr rnd[0], 32)
  result.priv = priv
  result.pub = x25519Algo.x25519PublicKey(priv)

proc x25519Public*(priv: array[32, byte]): array[32, byte] =
  result = x25519Algo.x25519PublicKey(priv)

proc x25519Shared*(priv: array[32, byte], peerPub: array[32, byte]): array[32, byte] =
  result = x25519Algo.x25519(priv, peerPub)

proc x25519SharedMpint*(priv: array[32, byte], peerPub: array[32, byte]): seq[byte] =
  ## Shared secret as unsigned BE bytes (mpint body without length prefix).
  let s = x25519Shared(priv, peerPub)
  # strip leading zeros for mpint encoding; keep at least one byte
  var i = 0
  while i < 31 and s[i] == 0:
    inc i
  result = s.toOpenArray(i, 31).toSeq()

# ── Exchange hash + key expansion (RFC 4253 §7-8) ──────────────────────────

proc curve25519ExchangeHash*(
    clientVersion, serverVersion: string,
    clientKexInit, serverKexInit: openArray[byte],
    hostKeyBlob: openArray[byte],
    clientEphem, serverEphem: array[32, byte] | seq[byte],
    sharedMpintBody: openArray[byte]): array[32, byte] =
  ## H = SHA256(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K).
  var w = initWriter()
  w.writeString(clientVersion)
  w.writeString(serverVersion)
  w.writeString(clientKexInit)
  w.writeString(serverKexInit)
  w.writeString(hostKeyBlob)
  when clientEphem is array:
    w.writeString(clientEphem)
  else:
    w.writeString(clientEphem)
  when serverEphem is array:
    w.writeString(serverEphem)
  else:
    w.writeString(serverEphem)
  var kw = initWriter()
  kw.writeMpint(sharedMpintBody)
  # writeMpint includes its own length prefix; H needs the full mpint field.
  # kw.buf already is [len || body], append raw.
  w.writeRaw(kw.toBytes())
  let digest = sha256Algo.sha256(w.toBytes())
  copyMem(addr result[0], unsafeAddr digest[0], 32)

proc dhExchangeHash*(
    clientVersion, serverVersion: string,
    clientKexInit, serverKexInit: openArray[byte],
    hostKeyBlob: openArray[byte],
    clientPub, serverPub: openArray[byte],
    sharedSecret: openArray[byte]): array[32, byte] =
  ## Same construction with DH e/f values as mpints.
  var w = initWriter()
  w.writeString(clientVersion)
  w.writeString(serverVersion)
  w.writeString(clientKexInit)
  w.writeString(serverKexInit)
  w.writeString(hostKeyBlob)
  w.writeMpint(clientPub)
  w.writeMpint(serverPub)
  w.writeMpint(sharedSecret)
  let digest = sha256Algo.sha256(w.toBytes())
  copyMem(addr result[0], unsafeAddr digest[0], 32)

proc deriveKey*(K: openArray[byte], H: array[32, byte],
                sessionId: array[32, byte] | seq[byte],
                letter: char, n: int): seq[byte] =
  ## RFC 4253 §7.2: K1 = HASH(K || H || X || session_id), Kn+1 = HASH(K || H || Kn).
  if n <= 0 or n > 1024:
    raise newException(SshKexError, "ssh kex: bad derive length")
  var kw = initWriter()
  kw.writeMpint(K)
  let kEnc = kw.toBytes()
  result = @[]
  var prev: seq[byte] = @[]
  var first = true
  while result.len < n:
    var w = initWriter()
    w.writeRaw(kEnc)
    w.writeRaw(H)
    if first:
      w.writeByte(byte(letter))
      when sessionId is array:
        w.writeRaw(sessionId)
      else:
        w.writeRaw(sessionId)
      first = false
    else:
      w.writeRaw(prev)
    let d = sha256Algo.sha256(w.toBytes())
    prev = d.toSeq()
    result.add(prev)
  result.setLen(n)
