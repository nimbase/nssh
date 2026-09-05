# SSH session: version exchange, KEXINIT negotiation, curve25519 KEXDH,
# NEWKEYS, then encrypted transport. Pure state machine over byte chunks;
# no socket import. Drive two sessions against each other for loopback tests,
# or hook `takeOutbox`/`receiveBytes` to powpow `send`/`onData`.
#
# MVP scope: kex curve25519-sha256, hostkey ssh-ed25519, ciphers
# chacha20-poly1305@openssh.com / aes128-ctr / aes256-ctr, HMAC-SHA2 for CTR.

import std/sysrand
import std/sequtils

import ./codec
import ./transport
import ./kex
import ./ciphers
import ./hostkeys

const
  MsgDisconnect* = 1'u8
  MsgIgnore* = 2'u8
  MsgKexInit* = 20'u8
  MsgNewKeys* = 21'u8
  MsgKexDhInit* = 30'u8
  MsgKexDhReply* = 31'u8

type
  SshSessionError* = object of ValueError

  Role* = enum
    rClient, rServer

  Stage* = enum
    stVersion, stKexInit, stKexDh, stNewKeys, stOpen, stClosed

  EventKind* = enum
    evReady, evPacket, evDisconnect, evErrorMsg

  SessionEvent* = object
    kind*: EventKind
    msgType*: byte
    payload*: seq[byte]  ## full BPP payload for evPacket
    message*: string     ## human detail for evDisconnect/evErrorMsg

  SshSession* = object
    role*: Role
    stage*: Stage
    vLocal*: string
    vPeer*: string
    iLocal*: seq[byte]   ## our KEXINIT payload (msg type .. reserved)
    iPeer*: seq[byte]
    kexOffer*: seq[string]
    hostKeyOffer*: seq[string]
    cipherOffer*: seq[string]
    macOffer*: seq[string]
    ephLocal*: X25519KeyPair
    ephPeer*: array[32, byte]
    dhPriv*: seq[byte]       ## our DH private (group14), generated at init
    dhPeer*: seq[byte]       ## peer's e/f mpint payload as received
    hostKey*: EdKeyPair      ## server signing key
    hasHostKey*: bool
    autoTrust*: bool         ## client: accept unknown host keys (tests)
    kexName*: string
    hostKeyName*: string
    cipherKind*: CipherKind
    macKind*: MacKind
    K*: seq[byte]            ## shared secret, unsigned BE
    H*: array[32, byte]
    sessionId*: array[32, byte]
    hasSessionId*: bool
    keys*: SessionKeys
    sendActive*: bool
    recvActive*: bool
    sendSeq*: uint32
    recvSeq*: uint32
    inBuf*: seq[byte]
    outbox*: seq[seq[byte]]

proc initClient*(autoTrust = false): SshSession =
  result.role = rClient
  result.stage = stVersion
  result.vLocal = SshVersion
  result.kexOffer = @[KexCurve25519Sha256, KexGroup14Sha256]
  result.hostKeyOffer = @[HostKeyEd25519]
  result.cipherOffer = @[$ckChacha20Poly1305, $ckAes128Ctr, $ckAes256Ctr,
                         $ckAes128Gcm, $ckAes256Gcm]
  result.macOffer = @[$mkHmacSha256, $mkHmacSha512,
                      $mkHmacSha256Etm, $mkHmacSha512Etm]
  result.ephLocal = x25519GenKey()
  result.dhPriv = dhPrivate()
  result.autoTrust = autoTrust

proc initServer*(hostKey: EdKeyPair): SshSession =
  result.role = rServer
  result.stage = stVersion
  result.vLocal = SshVersion
  result.kexOffer = @[KexCurve25519Sha256, KexGroup14Sha256]
  result.hostKeyOffer = @[HostKeyEd25519]
  result.cipherOffer = @[$ckChacha20Poly1305, $ckAes128Ctr, $ckAes256Ctr,
                         $ckAes128Gcm, $ckAes256Gcm]
  result.macOffer = @[$mkHmacSha256, $mkHmacSha512,
                      $mkHmacSha256Etm, $mkHmacSha512Etm]
  result.ephLocal = x25519GenKey()
  result.dhPriv = dhPrivate()
  result.hostKey = hostKey
  result.hasHostKey = true

proc takeOutbox*(s: var SshSession): seq[seq[byte]] =
  result = s.outbox
  s.outbox = @[]

# ── KEXINIT ─────────────────────────────────────────────────────────────────

proc buildKexInit*(cookie: array[16, byte], kex, hostKey, encC2s, encS2c,
                   macC2s, macS2c, compC2s, compS2c, langC2s,
                   langS2c: openArray[string]): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgKexInit)
  w.writeRaw(cookie)
  w.writeNameList(kex)
  w.writeNameList(hostKey)
  w.writeNameList(encC2s)
  w.writeNameList(encS2c)
  w.writeNameList(macC2s)
  w.writeNameList(macS2c)
  w.writeNameList(compC2s)
  w.writeNameList(compS2c)
  w.writeNameList(langC2s)
  w.writeNameList(langS2c)
  w.writeBool(false)
  w.writeUint32(0)
  result = w.toBytes()

proc parseKexInit*(payload: openArray[byte]): array[10, seq[string]] =
  var r = initReader(payload)
  if r.readByte() != MsgKexInit:
    raise newException(SshSessionError, "ssh session: not a KEXINIT")
  discard r.readRaw(16)
  for i in 0 ..< 10:
    result[i] = r.readNameList()
  discard r.readBool()
  if r.readUint32() != 0:
    raise newException(SshSessionError, "ssh session: KEXINIT reserved != 0")
  if not r.isExhausted():
    raise newException(SshSessionError, "ssh session: KEXINIT trailing bytes")

proc localLists(s: SshSession): array[10, seq[string]] =
  result[0] = s.kexOffer
  result[1] = s.hostKeyOffer
  result[2] = s.cipherOffer
  result[3] = s.cipherOffer
  result[4] = s.macOffer
  result[5] = s.macOffer
  result[6] = @["none"]
  result[7] = @["none"]
  result[8] = @[]
  result[9] = @[]

proc pickFirst(clientPrefs, serverSupplied: openArray[string]): string =
  for c in clientPrefs:
    for su in serverSupplied:
      if c == su:
        return c
  raise newException(SshSessionError, "ssh session: no matching algorithm")

proc parseCipherKind(s: string): CipherKind =
  for v in low(CipherKind) .. high(CipherKind):
    if $v == s:
      return v
  raise newException(SshSessionError, "ssh session: unknown cipher " & s)

proc parseMacKind(s: string): MacKind =
  for v in low(MacKind) .. high(MacKind):
    if $v == s:
      return v
  raise newException(SshSessionError, "ssh session: unknown MAC " & s)

# ── send path ───────────────────────────────────────────────────────────────

proc sendPayload*(s: var SshSession, payload: openArray[byte]) =
  ## BPP-encode (+ encrypt/MAC when active), queue wire bytes, bump seqno.
  ## Raises instead of wrapping the sequence number (rekey before 2^32).
  if s.sendSeq == high(uint32):
    raise newException(SshSessionError, "ssh session: sequence rollover, rekey first")
  let spec = specFor(s.cipherKind)
  if not s.sendActive:
    s.outbox.add(encodePacket(payload, 8))
  elif s.cipherKind == ckAes128Ctr or s.cipherKind == ckAes256Ctr:
    if isEtm(s.keys.toPeer.mac):
      # ETM: packet_length travels in clear (OpenSSH packet.c `aadlen`),
      # so packlen itself must be block-aligned; only the rest is CTR
      # encrypted with the running counter (length consumes no keystream).
      let enc = encodePacket(payload, spec.blockSize, lengthInClear = true)
      let ctRest = s.keys.toPeer.cipher.ctrCrypt(enc.toOpenArray(4, enc.high))
      var wire = newSeq[byte](4 + ctRest.len)
      copyMem(addr wire[0], unsafeAddr enc[0], 4)
      copyMem(addr wire[4], unsafeAddr ctRest[0], ctRest.len)
      let m = computeMac(s.keys.toPeer.mac, s.keys.toPeer.macKey, s.sendSeq,
        wire.toOpenArray(0, wire.high))
      s.outbox.add(wire & m)
    else:
      let enc = encodePacket(payload, spec.blockSize)
      let ct = s.keys.toPeer.cipher.ctrCrypt(enc)
      let m = computeMac(s.keys.toPeer.mac, s.keys.toPeer.macKey, s.sendSeq,
        enc.toOpenArray(0, enc.high))
      s.outbox.add(ct & m)
  elif s.cipherKind == ckAes128Gcm or s.cipherKind == ckAes256Gcm:
    let enc = encodePacket(payload, spec.blockSize, lengthInClear = true)
    var plen: array[4, byte]
    for i in 0 ..< 4: plen[i] = enc[i]
    let sealed = s.keys.toPeer.cipher.gcmSealPacket(plen, enc.toOpenArray(4, enc.high))
    var wire = newSeq[byte](4 + sealed.ct.len + 16)
    copyMem(addr wire[0], unsafeAddr plen[0], 4)
    copyMem(addr wire[4], unsafeAddr sealed.ct[0], sealed.ct.len)
    copyMem(addr wire[4 + sealed.ct.len], unsafeAddr sealed.tag[0], 16)
    s.outbox.add(wire)
  elif s.cipherKind == ckChacha20Poly1305:
    let enc = encodePacket(payload, spec.blockSize, lengthInClear = true)
    var plen: array[4, byte]
    for i in 0 ..< 4: plen[i] = enc[i]
    let encLen = s.keys.toPeer.cipher.chachaSealLength(s.sendSeq, plen)
    let sealed = s.keys.toPeer.cipher.chachaSealPayload(s.sendSeq,
      enc.toOpenArray(4, enc.high))
    let tag = s.keys.toPeer.cipher.chachaTag(s.sendSeq, encLen, sealed.ct)
    var wire = newSeq[byte](4 + sealed.ct.len + 16)
    copyMem(addr wire[0], unsafeAddr encLen[0], 4)
    copyMem(addr wire[4], unsafeAddr sealed.ct[0], sealed.ct.len)
    copyMem(addr wire[4 + sealed.ct.len], unsafeAddr tag[0], 16)
    s.outbox.add(wire)
  else:
    raise newException(SshSessionError, "ssh session: cipher not wired")
  inc s.sendSeq

proc startHandshake*(s: var SshSession) =
  ## Queue version line + KEXINIT. Call once before exchanging bytes.
  s.outbox.add(encodeVersionLine(s.vLocal))
  var cookie: array[16, byte]
  let rnd = urandom(16)
  copyMem(addr cookie[0], unsafeAddr rnd[0], 16)
  let loc = s.localLists()
  let payload = buildKexInit(cookie, loc[0], loc[1], loc[2], loc[3], loc[4],
    loc[5], loc[6], loc[7], loc[8], loc[9])
  s.iLocal = payload
  s.sendPayload(payload)

proc sendIgnore*(s: var SshSession, data = "nssh") =
  var w = initWriter()
  w.writeByte(MsgIgnore)
  w.writeString(data)
  s.sendPayload(w.toBytes())

proc sendDisconnect*(s: var SshSession, reason: uint32, message: string) =
  ## Queue a DISCONNECT and mark the session closed for sending. The
  ## connection owner should flush the outbox then close TCP.
  var w = initWriter()
  w.writeByte(MsgDisconnect)
  w.writeUint32(reason)
  w.writeString(message)
  w.writeString("")
  s.sendPayload(w.toBytes())
  s.stage = stClosed

# ── receive path ────────────────────────────────────────────────────────────

proc consume(s: var SshSession, n: int) =
  let left = s.inBuf.len - n
  if left > 0:
    copyMem(addr s.inBuf[0], addr s.inBuf[n], left)
  s.inBuf.setLen(left)

proc payloadOf(packet: openArray[byte]): seq[byte] =
  ## Strip BPP length/padding, return payload (msg type + data).
  let plen = (int(packet[0]) shl 24) or (int(packet[1]) shl 16) or
             (int(packet[2]) shl 8) or int(packet[3])
  let padL = int(packet[4])
  result = packet.toOpenArray(5, 3 + plen - padL).toSeq()

proc pullPlaintextOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  ## Decode at most ONE packet; the caller handles it (possibly flipping
  ## cipher state via NEWKEYS) before the next pull. Pipelined
  ## NEWKEYS+ciphertext in one TCP chunk requires this one-at-a-time flow.
  let (found, payload, consumed) = tryDecodePacket(s.inBuf, 8)
  if not found:
    return (false, @[])
  s.consume(consumed)
  inc s.recvSeq
  result = (true, payload)

proc pullCtrOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  ## Peek length with a counter copy; only advance real state on full packets.
  let macL = macLen(s.keys.fromPeer.mac)
  if isEtm(s.keys.fromPeer.mac):
    # ETM: packet_length travels in clear (OpenSSH packet.c `aadlen`), so
    # no probe decrypt is needed; the running counter covers only the
    # bytes after the length field.
    if s.inBuf.len < 4:
      return (false, @[])
    let packetLen = (uint32(s.inBuf[0]) shl 24) or (uint32(s.inBuf[1]) shl 16) or
                    (uint32(s.inBuf[2]) shl 8) or uint32(s.inBuf[3])
    if packetLen < 12 or packetLen > uint32(MaxSshPacketLen):
      raise newException(SshSessionError, "ssh session: bad CTR packet_length")
    if int(packetLen) mod specFor(s.cipherKind).blockSize != 0:
      raise newException(SshSessionError, "ssh session: CTR packet not block aligned")
    let total = 4 + int(packetLen) + macL
    if s.inBuf.len < total:
      return (false, @[])
    let ok = verifyMac(s.keys.fromPeer.mac, s.keys.fromPeer.macKey, s.recvSeq,
      s.inBuf.toOpenArray(0, total - macL - 1),
      s.inBuf.toOpenArray(total - macL, total - 1))
    if not ok:
      raise newException(SshSessionError, "ssh session: MAC verification failed")
    let dec = s.keys.fromPeer.cipher.ctrCrypt(s.inBuf.toOpenArray(4, total - macL - 1))
    var full = newSeq[byte](4 + dec.len)
    copyMem(addr full[0], addr s.inBuf[0], 4)
    copyMem(addr full[4], unsafeAddr dec[0], dec.len)
    let payload = payloadOf(full)
    s.consume(total)
    inc s.recvSeq
    return (true, payload)
  if s.inBuf.len < 16:
    return (false, @[])
  var probe = s.keys.fromPeer.cipher
  let blk = probe.ctrCrypt(s.inBuf.toOpenArray(0, 15))
  let packetLen = (uint32(blk[0]) shl 24) or (uint32(blk[1]) shl 16) or
                  (uint32(blk[2]) shl 8) or uint32(blk[3])
  if packetLen < 12 or packetLen > uint32(MaxSshPacketLen):
    raise newException(SshSessionError, "ssh session: bad CTR packet_length")
  # Length is inside the encrypted region: whole packet must be block
  # aligned (mirrors OpenSSH's `need % block_size` rejection).
  if (4 + int(packetLen)) mod specFor(s.cipherKind).blockSize != 0:
    raise newException(SshSessionError, "ssh session: CTR packet not block aligned")
  let total = 4 + int(packetLen) + macL
  if s.inBuf.len < total:
    return (false, @[])
  let enc = s.keys.fromPeer.cipher.ctrCrypt(s.inBuf.toOpenArray(0, total - macL - 1))
  let ok =
    if isEtm(s.keys.fromPeer.mac):
      verifyMac(s.keys.fromPeer.mac, s.keys.fromPeer.macKey, s.recvSeq,
        s.inBuf.toOpenArray(0, total - macL - 1),
        s.inBuf.toOpenArray(total - macL, total - 1))
    else:
      verifyMac(s.keys.fromPeer.mac, s.keys.fromPeer.macKey, s.recvSeq, enc,
        s.inBuf.toOpenArray(total - macL, total - 1))
  if not ok:
    raise newException(SshSessionError, "ssh session: MAC verification failed")
  let payload = payloadOf(enc)
  s.consume(total)
  inc s.recvSeq
  result = (true, payload)

proc pullGcmOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  if s.inBuf.len < 4:
    return (false, @[])
  let packetLen = (uint32(s.inBuf[0]) shl 24) or (uint32(s.inBuf[1]) shl 16) or
                  (uint32(s.inBuf[2]) shl 8) or uint32(s.inBuf[3])
  if packetLen < 5 or packetLen > uint32(MaxSshPacketLen):
    raise newException(SshSessionError, "ssh session: bad GCM packet_length")
  let total = 4 + int(packetLen) + GcmTagLen
  if s.inBuf.len < total:
    return (false, @[])
  var plen: array[4, byte]
  for i in 0 ..< 4: plen[i] = s.inBuf[i]
  let pt = s.keys.fromPeer.cipher.gcmOpenPacket(plen,
    s.inBuf.toOpenArray(4, 4 + int(packetLen) - 1),
    s.inBuf.toOpenArray(4 + int(packetLen), total - 1))
  let padL = int(pt[0])
  let payload = pt.toOpenArray(1, pt.len - padL - 1).toSeq()
  s.consume(total)
  inc s.recvSeq
  result = (true, payload)

proc pullChachaOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  if s.inBuf.len < 4:
    return (false, @[])
  var encLen: array[4, byte]
  for i in 0 ..< 4: encLen[i] = s.inBuf[i]
  let plen = s.keys.fromPeer.cipher.chachaOpenLength(s.recvSeq, encLen)
  let packetLen = (uint32(plen[0]) shl 24) or (uint32(plen[1]) shl 16) or
                  (uint32(plen[2]) shl 8) or uint32(plen[3])
  # AEAD minimum is 1+4 (OpenSSH packet.c `packlen < 1 + 4`); small packets
  # like USERAUTH_SUCCESS (packlen 8) are legal — unlike CTR, the length
  # field is not inside an encrypted cipher block.
  if packetLen < 5 or packetLen > uint32(MaxSshPacketLen):
    raise newException(SshSessionError, "ssh session: bad chacha packet_length")
  let total = 4 + int(packetLen) + ChaTagLen
  if s.inBuf.len < total:
    return (false, @[])
  let pt = s.keys.fromPeer.cipher.chachaOpenAndVerify(s.recvSeq, encLen,
    s.inBuf.toOpenArray(4, 4 + int(packetLen) - 1),
    s.inBuf.toOpenArray(4 + int(packetLen), total - 1))
  let padL = int(pt[0])
  let payload = pt.toOpenArray(1, pt.len - padL - 1).toSeq()
  s.consume(total)
  inc s.recvSeq
  result = (true, payload)

proc pullOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  ## Single packet under the CURRENT cipher state. The caller must handle
  ## it before pulling again: NEWKEYS flips recvActive mid-buffer.
  if not s.recvActive:
    result = s.pullPlaintextOne()
  elif s.cipherKind == ckAes128Ctr or s.cipherKind == ckAes256Ctr:
    result = s.pullCtrOne()
  elif s.cipherKind == ckAes128Gcm or s.cipherKind == ckAes256Gcm:
    result = s.pullGcmOne()
  else:
    result = s.pullChachaOne()

# ── KEXDH ───────────────────────────────────────────────────────────────────

proc kexRoles(s: SshSession): tuple[vC, vS: string, initC, initS: seq[byte]] =
  if s.role == rClient:
    result = (s.vLocal, s.vPeer, s.iLocal, s.iPeer)
  else:
    result = (s.vPeer, s.vLocal, s.iPeer, s.iLocal)

proc activateKeys(s: var SshSession) =
  let sid = if s.hasSessionId: s.sessionId.toSeq() else: s.H.toSeq()
  s.keys = newSessionKeys(s.K, s.H, sid, s.cipherKind, s.macKind,
                          s.role == rClient)
  if not s.hasSessionId:
    s.sessionId = s.H
    s.hasSessionId = true

proc sendNewKeys(s: var SshSession) =
  var n = initWriter()
  n.writeByte(MsgNewKeys)
  s.sendPayload(n.toBytes())
  s.sendActive = true

proc handleKexDhInit(s: var SshSession, payload: openArray[byte]) =
  ## Server side: peer key -> H, sign, reply + NEWKEYS. Branches on kex.
  if not s.hasHostKey:
    raise newException(SshSessionError, "ssh session: server has no host key")
  let (vC, vS, initC, initS) = kexRoles(s)
  let ksBlob = encodePubBlob(s.hostKey.pubkey)
  var w = initWriter()
  w.writeByte(MsgKexDhReply)
  w.writeString(ksBlob)
  if s.kexName == KexGroup14Sha256:
    var r = initReader(payload)
    discard r.readByte()
    let eRaw = r.readMpint()
    if not r.isExhausted():
      raise newException(SshSessionError, "ssh session: bad KEXDH_INIT")
    let prime = group14Prime()
    let e = mpintToUnsigned(eRaw)
    let shared = dhShared(e, s.dhPriv, prime)
    let f = dhPublic(s.dhPriv, prime)
    let H = dhExchangeHash(vC, vS, initC, initS, ksBlob, e, f, shared)
    s.K = shared
    s.H = H
    s.activateKeys()
    w.writeMpint(f)
  else:
    var r = initReader(payload)
    discard r.readByte()
    let qC = r.readString()
    if qC.len != 32 or not r.isExhausted():
      raise newException(SshSessionError, "ssh session: bad KEXDH_INIT")
    copyMem(addr s.ephPeer[0], unsafeAddr qC[0], 32)
    let shared = x25519SharedMpint(s.ephLocal.priv, s.ephPeer)
    let H = curve25519ExchangeHash(vC, vS, initC, initS, ksBlob,
      s.ephPeer, s.ephLocal.pub, shared)
    s.K = shared
    s.H = H
    s.activateKeys()
    w.writeString(s.ephLocal.pub)
  let sig = edSign(s.hostKey, s.H)
  w.writeString(encodeSignature(sig))
  s.sendPayload(w.toBytes())
  s.sendNewKeys()
  s.stage = stNewKeys

proc handleKexDhReply(s: var SshSession, payload: openArray[byte]) =
  ## Client side: verify hostkey + signature, send NEWKEYS. Branches on kex.
  var r = initReader(payload)
  if r.readByte() != MsgKexDhReply:
    raise newException(SshSessionError, "ssh session: not a KEXDH_REPLY")
  let ksBlob = r.readString()
  let pub = parsePubBlob(ksBlob)
  if not s.autoTrust:
    raise newException(SshSessionError, "ssh session: untrusted host key")
  let (vC, vS, initC, initS) = kexRoles(s)
  if s.kexName == KexGroup14Sha256:
    let fRaw = r.readMpint()
    let sigBlob = r.readString()
    if not r.isExhausted():
      raise newException(SshSessionError, "ssh session: KEXDH_REPLY trailing bytes")
    let prime = group14Prime()
    let f = mpintToUnsigned(fRaw)
    let shared = dhShared(f, s.dhPriv, prime)
    let e = dhPublic(s.dhPriv, prime)
    let H = dhExchangeHash(vC, vS, initC, initS, ksBlob, e, f, shared)
    let sig = parseSignature(sigBlob)
    if not edVerify(pub, H, sig):
      raise newException(SshSessionError, "ssh session: host signature invalid")
    s.K = shared
    s.H = H
  else:
    let qS = r.readString()
    let sigBlob = r.readString()
    if not r.isExhausted():
      raise newException(SshSessionError, "ssh session: KEXDH_REPLY trailing bytes")
    if qS.len != 32:
      raise newException(SshSessionError, "ssh session: bad server epub length")
    copyMem(addr s.ephPeer[0], unsafeAddr qS[0], 32)
    let shared = x25519SharedMpint(s.ephLocal.priv, s.ephPeer)
    let H = curve25519ExchangeHash(vC, vS, initC, initS, ksBlob,
      s.ephLocal.pub, s.ephPeer, shared)
    let sig = parseSignature(sigBlob)
    if not edVerify(pub, H, sig):
      raise newException(SshSessionError, "ssh session: host signature invalid")
    s.K = shared
    s.H = H
  s.activateKeys()
  s.sendNewKeys()
  s.stage = stNewKeys

# ── message dispatch ────────────────────────────────────────────────────────

proc handleMessage(s: var SshSession, payload: openArray[byte]): seq[SessionEvent] =
  result = @[]
  if payload.len == 0:
    raise newException(SshSessionError, "ssh session: empty payload")
  case payload[0]
  of MsgKexInit:
    if s.stage != stKexInit:
      raise newException(SshSessionError, "ssh session: unexpected KEXINIT")
    s.iPeer = payload.toSeq()
    let peer = parseKexInit(payload)
    let loc = s.localLists()
    # cLists is always the CLIENT's lists, svLists the SERVER's, so both
    # sides compute identical selections (client preference order wins).
    let (cLists, svLists) =
      if s.role == rClient: (loc, peer) else: (peer, loc)
    s.kexName = pickFirst(cLists[0], svLists[0])
    s.hostKeyName = pickFirst(cLists[1], svLists[1])
    if s.kexName != KexCurve25519Sha256 and s.kexName != KexGroup14Sha256:
      raise newException(SshSessionError, "ssh session: unsupported kex " & s.kexName)
    if s.hostKeyName != HostKeyEd25519:
      raise newException(SshSessionError, "ssh session: unsupported hostkey")
    let c2s = pickFirst(cLists[2], svLists[2])
    let s2c = pickFirst(cLists[3], svLists[3])
    if c2s != s2c:
      raise newException(SshSessionError, "ssh session: asymmetric ciphers unsupported")
    s.cipherKind = parseCipherKind(c2s)
    let mC2s = pickFirst(cLists[4], svLists[4])
    let mS2c = pickFirst(cLists[5], svLists[5])
    if mC2s != mS2c:
      raise newException(SshSessionError, "ssh session: asymmetric MACs unsupported")
    s.macKind = parseMacKind(mC2s)
    if s.role == rClient:
      var w = initWriter()
      w.writeByte(MsgKexDhInit)
      if s.kexName == KexGroup14Sha256:
        w.writeMpint(dhPublic(s.dhPriv, group14Prime()))
      else:
        w.writeString(s.ephLocal.pub)
      s.sendPayload(w.toBytes())
    s.stage = stKexDh
  of MsgKexDhInit:
    if s.role != rServer or s.stage != stKexDh:
      raise newException(SshSessionError, "ssh session: unexpected KEXDH_INIT")
    s.handleKexDhInit(payload)
  of MsgKexDhReply:
    if s.role != rClient or s.stage != stKexDh:
      raise newException(SshSessionError, "ssh session: unexpected KEXDH_REPLY")
    s.handleKexDhReply(payload)
  of MsgNewKeys:
    if payload.len != 1:
      raise newException(SshSessionError, "ssh session: NEWKEYS with payload")
    s.recvActive = true
    if s.sendActive and s.recvActive and s.stage == stNewKeys:
      s.stage = stOpen
      result.add(SessionEvent(kind: evReady))
  of MsgDisconnect:
    var reason = 0'u32
    var text = "peer disconnected"
    try:
      var r = initReader(payload)
      discard r.readByte()
      reason = r.readUint32()
      text = r.readStringStr()
    except SshCodecError:
      discard
    s.stage = stClosed
    result.add(SessionEvent(kind: evDisconnect,
      message: "peer disconnected (" & $reason & "): " & text))
  else:
    if s.stage == stOpen:
      result.add(SessionEvent(kind: evPacket, msgType: payload[0],
                              payload: payload.toSeq()))
    else:
      raise newException(SshSessionError, "ssh session: unexpected message " & $payload[0])

proc receiveBytes*(s: var SshSession, chunk: openArray[byte]): seq[SessionEvent] =
  ## Feed inbound bytes (version lines + packets). Returns session events.
  ## Peer-triggered failures become evErrorMsg events, never exceptions.
  ## The reassembly buffer is capped: a peer that never completes a line
  ## or packet is cut off instead of growing memory without bound.
  const MaxSessionBuffer = 262144
  result = @[]
  if chunk.len > 0:
    if s.inBuf.len + chunk.len > MaxSessionBuffer:
      s.stage = stClosed
      result.add(SessionEvent(kind: evErrorMsg,
        message: "ssh session: inbound buffer overflow"))
      return
    let off = s.inBuf.len
    s.inBuf.setLen(off + chunk.len)
    copyMem(addr s.inBuf[off], unsafeAddr chunk[0], chunk.len)
  if s.stage == stVersion:
    let n = findVersionLine(s.inBuf)
    if n == 0:
      return
    let line = s.inBuf.toOpenArray(0, n - 1).toSeq()
    s.consume(n)
    try:
      s.vPeer = parseVersionLine(line)
    except ValueError as e:
      s.stage = stClosed
      result.add(SessionEvent(kind: evErrorMsg, message: e.msg))
      return
    s.stage = stKexInit
  try:
    while true:
      let (found, p) = s.pullOne()
      if not found:
        break
      for ev in s.handleMessage(p):
        result.add(ev)
  except ValueError as e:
    s.stage = stClosed
    result.add(SessionEvent(kind: evErrorMsg, message: e.msg))
