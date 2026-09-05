# SSH ciphers + MACs: AES-CTR, AES-GCM (RFC 5647),
# chacha20-poly1305@openssh.com (draft-josefsson-...-00), HMAC-SHA2.
#
# One `SshCipher` object per direction (separate encrypt/decrypt state).
# Sequence numbers are managed by the caller (session layer).

import std/options
import std/sequtils

import nimcypher/algos/aes as aesAlgo
import nimcypher/algos/gcm as gcmAlgo
import nimcypher/algos/chacha20 as chachaAlgo
import nimcypher/algos/poly1305 as polyAlgo
import nimcypher/hash as hashApi

import ./kex

type
  SshCipherError* = object of ValueError

  CipherKind* = enum
    ckNone = "none"
    ckAes128Ctr = "aes128-ctr"
    ckAes256Ctr = "aes256-ctr"
    ckAes128Gcm = "aes128-gcm@openssh.com"
    ckAes256Gcm = "aes256-gcm@openssh.com"
    ckChacha20Poly1305 = "chacha20-poly1305@openssh.com"

  MacKind* = enum
    mkNone = "none"
    mkHmacSha256 = "hmac-sha2-256"
    mkHmacSha256Etm = "hmac-sha2-256-etm@openssh.com"
    mkHmacSha512 = "hmac-sha2-512"
    mkHmacSha512Etm = "hmac-sha2-512-etm@openssh.com"

  CipherSpec* = object
    kind*: CipherKind
    keyLen*: int    ## key bytes (chacha: 64 = payload-key || length-key)
    ivLen*: int     ## bytes of IV material (chacha/gcm-nonce-salt semantics below)
    blockSize*: int ## BPP cipher block size (padding granularity)
    tagLen*: int    ## AEAD tag bytes appended per packet (0 for CTR/none)
    isAead*: bool

  SshCipher* = object
    kind*: CipherKind
    case isAeadCipher*: bool
    of false:
      aesCtx*: aesAlgo.AesContext
      ctr*: array[16, byte] ## running counter block (CTR) / unused (none)
    of true:
      gcmKey*: seq[byte]
      gcmNonce*: array[12, byte] ## GCM running nonce: starts at the full
        ## KEX-derived IV, +1 per packet (OpenSSH cipher.c); unused for chacha
      chaK1*: array[32, byte]   ## chacha LENGTH key (key[32..64]); zeroed for GCM
      chaK2*: array[32, byte]   ## chacha PAYLOAD key (key[0..32]); zeroed for GCM

const
  GcmNonceLen* = 12
  ChaTagLen* = 16
  GcmTagLen* = 16

proc specFor*(kind: CipherKind): CipherSpec =
  case kind
  of ckNone:
    CipherSpec(kind: kind, keyLen: 0, ivLen: 0, blockSize: 8, tagLen: 0, isAead: false)
  of ckAes128Ctr:
    CipherSpec(kind: kind, keyLen: 16, ivLen: 16, blockSize: 16, tagLen: 0, isAead: false)
  of ckAes256Ctr:
    CipherSpec(kind: kind, keyLen: 32, ivLen: 16, blockSize: 16, tagLen: 0, isAead: false)
  of ckAes128Gcm:
    CipherSpec(kind: kind, keyLen: 16, ivLen: 12, blockSize: 16, tagLen: 16, isAead: true)
  of ckAes256Gcm:
    CipherSpec(kind: kind, keyLen: 32, ivLen: 12, blockSize: 16, tagLen: 16, isAead: true)
  of ckChacha20Poly1305:
    CipherSpec(kind: kind, keyLen: 64, ivLen: 0, blockSize: 8, tagLen: 16, isAead: true)

proc macLen*(kind: MacKind): int =
  case kind
  of mkNone: 0
  of mkHmacSha256, mkHmacSha256Etm: 32
  of mkHmacSha512, mkHmacSha512Etm: 64

proc isEtm*(kind: MacKind): bool {.inline.} =
  kind == mkHmacSha256Etm or kind == mkHmacSha512Etm

proc initCipher*(kind: CipherKind, key, iv: openArray[byte]): SshCipher =
  ## `key`/`iv` are KEX-derived materials of `specFor(kind)` lengths.
  let spec = specFor(kind)
  if key.len != spec.keyLen:
    raise newException(SshCipherError, "ssh cipher: bad key length")
  if iv.len != spec.ivLen:
    raise newException(SshCipherError, "ssh cipher: bad iv length")
  case kind
  of ckNone:
    result = SshCipher(kind: kind, isAeadCipher: false)
  of ckAes128Ctr, ckAes256Ctr:
    result = SshCipher(kind: kind, isAeadCipher: false)
    aesAlgo.initAes(result.aesCtx, key)
    copyMem(addr result.ctr[0], unsafeAddr iv[0], 16)
  of ckAes128Gcm, ckAes256Gcm:
    result = SshCipher(kind: kind, isAeadCipher: true)
    result.gcmKey = key.toSeq()
    if iv.len != GcmNonceLen:
      raise newException(SshCipherError, "ssh cipher: GCM needs a 12-byte IV")
    copyMem(addr result.gcmNonce[0], unsafeAddr iv[0], GcmNonceLen)
  of ckChacha20Poly1305:
    result = SshCipher(kind: kind, isAeadCipher: true)
    # Layout matches OpenSSH cipher-chachapoly.c chachapoly_new():
    # main (payload/Poly1305) context gets key[0..32], header (length)
    # context gets key[32..64]. NOTE: draft-josefsson-00 names these
    # K_1/K_2 the other way round; the code on the wire is authoritative.
    copyMem(addr result.chaK2[0], unsafeAddr key[0], 32)
    copyMem(addr result.chaK1[0], unsafeAddr key[32], 32)

# ── AES-CTR (stateful, whole16-byte-multiple calls) ─────────────────────────

proc ctrCrypt*(c: var SshCipher, data: openArray[byte]): seq[byte] =
  ## Encrypt/decrypt (identical op). `data.len` must be a multiple of 16 so
  ## the running counter stays block-aligned across calls.
  if c.kind != ckAes128Ctr and c.kind != ckAes256Ctr:
    raise newException(SshCipherError, "ssh cipher: not a CTR cipher")
  if data.len mod 16 != 0:
    raise newException(SshCipherError, "ssh cipher: CTR chunks must be 16-byte aligned")
  result = newSeq[byte](data.len)
  if data.len == 0:
    return
  aesAlgo.ctrXorInto(c.aesCtx, c.ctr,
    cast[ptr UncheckedArray[byte]](addr result[0]),
    cast[ptr UncheckedArray[byte]](unsafeAddr data[0]), data.len)

# ── AES-GCM (RFC 5647: clear length as AAD, 4B salt + u64 counter nonce) ────

proc incGcmNonce(c: var SshCipher) =
  ## +1 over the 12-byte nonce, big-endian (matches OpenSSH increment).
  var carry: uint16 = 1
  for i in countdown(11, 0):
    let s = uint16(c.gcmNonce[i]) + carry
    c.gcmNonce[i] = byte(s and 0xFF)
    carry = s shr 8
    if carry == 0:
      break

proc gcmSealPacket*(c: var SshCipher, packetLen: array[4, byte],
                    plaintext: openArray[byte]): tuple[ct: seq[byte], tag: array[16, byte]] =
  ## `plaintext` = padding_length || payload || padding (multiple of 16).
  ## Length field travels in clear as AAD; returns ciphertext + 16B tag.
  if c.kind != ckAes128Gcm and c.kind != ckAes256Gcm:
    raise newException(SshCipherError, "ssh cipher: not a GCM cipher")
  let (ct, tag) = gcmAlgo.gcmLock(c.gcmKey, c.gcmNonce, plaintext, packetLen)
  incGcmNonce(c)
  var t: array[16, byte]
  copyMem(addr t[0], unsafeAddr tag[0], 16)
  result = (ct, t)

proc gcmOpenPacket*(c: var SshCipher, packetLen: array[4, byte],
                    ct: openArray[byte], tag: openArray[byte]): seq[byte] =
  if c.kind != ckAes128Gcm and c.kind != ckAes256Gcm:
    raise newException(SshCipherError, "ssh cipher: not a GCM cipher")
  if tag.len != 16:
    raise newException(SshCipherError, "ssh cipher: bad GCM tag length")
  let plain = gcmAlgo.gcmUnlock(c.gcmKey, c.gcmNonce, ct, tag, packetLen)
  if plain.isNone:
    raise newException(SshCipherError, "ssh cipher: GCM tag verification failed")
  incGcmNonce(c)
  result = plain.get()

# ── chacha20-poly1305@openssh.com ───────────────────────────────────────────
# Nonce = seqno as uint64 SSH wire encoding (8-byte big-endian), fed as raw
# bytes to the DJB ChaCha (reference LE word layout, matching OpenSSH which
# feeds the same seqbuf bytes).

proc chaNonce(seqno: uint32): array[8, byte] =
  for i in 0 ..< 8:
    result[i] = byte(uint64(seqno) shr (56 - 8 * i))

proc chaCrypt(key: array[32, byte], nonce: array[8, byte], counter: uint64,
              data: openArray[byte]): seq[byte] =
  result = chachaAlgo.chacha20(data, key, nonce, counter)

proc chachaSealLength*(c: SshCipher, seqno: uint32,
                       packetLen: array[4, byte]): array[4, byte] =
  if c.kind != ckChacha20Poly1305:
    raise newException(SshCipherError, "ssh cipher: not a chacha cipher")
  let ks = chaCrypt(c.chaK1, chaNonce(seqno), 0, packetLen)
  copyMem(addr result[0], unsafeAddr ks[0], 4)

proc chachaOpenLength*(c: SshCipher, seqno: uint32,
                       encLen: array[4, byte]): array[4, byte] =
  ## Length encryption is XOR: open == seal.
  chachaSealLength(c, seqno, encLen)

proc chachaPolyKey(c: SshCipher, seqno: uint32): array[32, byte] =
  ## Per-packet Poly1305 one-time key: first 32 keystream bytes of
  ## ChaCha20(K_2, nonce=seqno, counter=0).
  var zeros: array[32, byte]
  let ks = chaCrypt(c.chaK2, chaNonce(seqno), 0, zeros)
  copyMem(addr result[0], unsafeAddr ks[0], 32)

proc chachaSealPayload*(c: SshCipher, seqno: uint32,
                        payload: openArray[byte]): tuple[ct: seq[byte], tag: array[16, byte]] =
  ## `payload` = padding_length || message || padding. Returns ciphertext
  ## (ChaCha20, K_2, counter=1) and Poly1305 tag over encLen || encPayload.
  ## Call `chachaSealLength` for the length half; MAC input needs both.
  if c.kind != ckChacha20Poly1305:
    raise newException(SshCipherError, "ssh cipher: not a chacha cipher")
  result.ct = chaCrypt(c.chaK2, chaNonce(seqno), 1, payload)

proc chachaTag*(c: SshCipher, seqno: uint32, encLen: array[4, byte],
                encPayload: openArray[byte]): array[16, byte] =
  let otk = chachaPolyKey(c, seqno)
  var macInput = newSeq[byte](4 + encPayload.len)
  copyMem(addr macInput[0], unsafeAddr encLen[0], 4)
  if encPayload.len > 0:
    copyMem(addr macInput[4], unsafeAddr encPayload[0], encPayload.len)
  let t = polyAlgo.poly1305(macInput, otk)
  copyMem(addr result[0], unsafeAddr t[0], 16)

proc chachaOpenAndVerify*(c: SshCipher, seqno: uint32, encLen: array[4, byte],
                          encPayload: openArray[byte],
                          tag: openArray[byte]): seq[byte] =
  ## Verify tag (constant-time) BEFORE decrypting. Raises on failure.
  if c.kind != ckChacha20Poly1305:
    raise newException(SshCipherError, "ssh cipher: not a chacha cipher")
  if tag.len != 16:
    raise newException(SshCipherError, "ssh cipher: bad chacha tag length")
  let want = chachaTag(c, seqno, encLen, encPayload)
  var diff: uint8 = 0
  for i in 0 ..< 16:
    diff = diff or (want[i] xor tag[i])
  if diff != 0:
    raise newException(SshCipherError, "ssh cipher: chacha tag verification failed")
  result = chaCrypt(c.chaK2, chaNonce(seqno), 1, encPayload)

# ── HMAC-SHA2 MACs (implicit + ETM) ─────────────────────────────────────────

proc computeMac*(kind: MacKind, macKey: openArray[byte], seqno: uint32,
                 data: openArray[byte]): seq[byte] =
  ## MAC over (uint32-BE seqno || data). For ETM pass the ciphertext packet;
  ## otherwise pass the plaintext packet (length field included).
  case kind
  of mkNone:
    return @[]
  of mkHmacSha256, mkHmacSha256Etm:
    var st = hashApi.initSha256Hmac(macKey)
    var s: array[4, byte]
    for i in 0 ..< 4:
      s[i] = byte(seqno shr (24 - 8 * i))
    st.update(s)
    st.update(data)
    result = st.finish().toSeq()
  of mkHmacSha512, mkHmacSha512Etm:
    var st = hashApi.initSha512Hmac(macKey)
    var s: array[4, byte]
    for i in 0 ..< 4:
      s[i] = byte(seqno shr (24 - 8 * i))
    st.update(s)
    st.update(data)
    result = st.finish().toSeq()

proc verifyMac*(kind: MacKind, macKey: openArray[byte], seqno: uint32,
                data: openArray[byte], mac: openArray[byte]): bool =
  if kind == mkNone:
    return mac.len == 0
  let want = computeMac(kind, macKey, seqno, data)
  if want.len != mac.len:
    return false
  var diff: uint8 = 0
  for i in 0 ..< want.len:
    diff = diff or (want[i] xor mac[i])
  result = diff == 0

# ── KEX key schedule (RFC 4253 §7.2 letters) ────────────────────────────────

type
  DirectionKeys* = object
    cipher*: SshCipher
    mac*: MacKind
    macKey*: seq[byte]

  SessionKeys* = object
    ## Outgoing/incoming states from one endpoint's point of view.
    toPeer*: DirectionKeys
    fromPeer*: DirectionKeys

proc newDirectionKeys*(K: openArray[byte], H: array[32, byte],
                       sessionId: openArray[byte], cipherKind: CipherKind,
                       macKind: MacKind, ivLetter, keyLetter, macLetter: char): DirectionKeys =
  let cspec = specFor(cipherKind)
  let sid = sessionId.toSeq()
  let ck = deriveKey(K, H, sid, keyLetter, cspec.keyLen)
  let iv = if cspec.ivLen > 0: deriveKey(K, H, sid, ivLetter, cspec.ivLen)
           else: @[]
  let mk = if not cspec.isAead and macKind != mkNone:
             deriveKey(K, H, sid, macLetter, macLen(macKind))
           else: @[]
  result = DirectionKeys(cipher: initCipher(cipherKind, ck, iv),
                          mac: if cspec.isAead: mkNone else: macKind,
                          macKey: mk)

proc newSessionKeys*(K: openArray[byte], H: array[32, byte],
                     sessionId: openArray[byte], cipherKind: CipherKind,
                     macKind: MacKind, isClient: bool): SessionKeys =
  ## Client sends with (A, C, E) and receives with (B, D, F); server mirrors.
  if isClient:
    result.toPeer = newDirectionKeys(K, H, sessionId, cipherKind, macKind, 'A', 'C', 'E')
    result.fromPeer = newDirectionKeys(K, H, sessionId, cipherKind, macKind, 'B', 'D', 'F')
  else:
    result.toPeer = newDirectionKeys(K, H, sessionId, cipherKind, macKind, 'B', 'D', 'F')
    result.fromPeer = newDirectionKeys(K, H, sessionId, cipherKind, macKind, 'A', 'C', 'E')
