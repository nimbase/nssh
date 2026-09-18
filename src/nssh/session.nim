# SSH session: version exchange, KEXINIT negotiation, curve25519 KEXDH,
# NEWKEYS, then encrypted transport. Pure state machine over byte chunks;
# no socket import. Drive two sessions against each other for loopback tests,
# or hook `takeOutbox`/`receiveBytes` to powpow `send`/`onData`.
#
# MVP scope: kex curve25519-sha256, hostkey ssh-ed25519, ciphers
# chacha20-poly1305@openssh.com / aes128-ctr / aes256-ctr, HMAC-SHA2 for CTR.

import std/sysrand
import std/sequtils
import std/monotimes

import ./codec
import ./transport
import ./kex
import ./ciphers
import ./hostkeys

const
  MsgDisconnect* = 1'u8
  MsgIgnore* = 2'u8
  MsgUnimplemented* = 3'u8
  MsgDebug* = 4'u8
  MsgServiceRequest* = 5'u8
  MsgServiceAccept* = 6'u8
  MsgKexInit* = 20'u8
  MsgNewKeys* = 21'u8
  MsgKexDhInit* = 30'u8
  MsgKexDhReply* = 31'u8

  # RFC 4253 §11.1 reason codes.
  DisconnectHostNotAllowedToConnect* = 1'u32
  DisconnectProtocolError* = 2'u32
  DisconnectKeyExchangeFailed* = 3'u32
  DisconnectReserved* = 4'u32
  DisconnectMacError* = 5'u32
  DisconnectCompressionError* = 6'u32
  DisconnectServiceNotAvailable* = 7'u32
  DisconnectProtocolVersionNotSupported* = 8'u32
  DisconnectHostKeyNotVerifiable* = 9'u32
  DisconnectConnectionLost* = 10'u32
  DisconnectByApplication* = 11'u32
  DisconnectTooManyConnections* = 12'u32
  DisconnectAuthCancelledByUser* = 13'u32
  DisconnectNoMoreAuthMethodsAvailable* = 14'u32
  DisconnectIllegalUserName* = 15'u32

type
  SshSessionError* = object of ValueError

  Role* = enum
    rClient, rServer

  Stage* = enum
    stVersion, stKexInit, stKexDh, stNewKeys, stOpen, stClosed

  EventKind* = enum
    evReady, evPacket, evDisconnect, evErrorMsg, evRekeyDone

  RekeyState* = enum
    ## RFC 4253 §9 re-exchange progress while `stage == stOpen`.
    ## `rsIdle` = no rekey in flight. Any other value means we have sent
    ## (or are responding with) KEXINIT and app data must be queued
    ## per §7.1 until we have sent NEWKEYS.
    rsIdle, rsKexInitSent, rsKexDh, rsNewKeysSent

  RekeyPolicy* = object
    ## Automatic rekey triggers (RFC 4253 §9 RECOMMENDS 1 GB / 1 hour).
    ## Zero disables that trigger. Checked after each send/receive and
    ## from `client`/`server` poll loops via `maybeTriggerRekey`.
    maxBytesSent*: uint64
    maxBytesRecv*: uint64
    maxPacketsSent*: uint64
    maxPacketsRecv*: uint64
    maxSeconds*: int64
    seqnoMargin*: uint32  ## rekey when within N packets of 2^32 wrap

  VerifyMode* = enum
    ## Host-key verification policy (client side).
    vmAutoTrust,  ## accept and continue (tests / TOFU without storage)
    vmStrict,     ## require match in `knownHosts` or `onHostKey` approval
    vmTofu        ## trust on first use, persist via `onHostKey` / file

  KnownHostEntry* = object
    host*: string
    port*: int  ## -1 = any port
    alg*: string
    pubkey*: array[32, byte]

  SessionEvent* = object
    kind*: EventKind
    msgType*: byte
    payload*: seq[byte]  ## full BPP payload for evPacket
    message*: string     ## human detail for evDisconnect/evErrorMsg
    seqno*: uint32       ## inbound packet sequence number (evPacket only);
      ## lets upper layers answer (e.g. UNIMPLEMENTED) about this packet

  SshSession* = object
    role*: Role
    stage*: Stage
    vLocal*: string
    vPeer*: string
    iLocal*: seq[byte]   ## our KEXINIT payload (msg type .. reserved)
    iPeer*: seq[byte]
    kexOffer*: seq[string]
    hostKeyOffer*: seq[string]
    cipherOffer*: seq[CipherKind]
    macOffer*: seq[MacKind]
    ephLocal*: X25519KeyPair
    ephPeer*: array[32, byte]
    dhPriv*: seq[byte]       ## our DH private (group14), generated at init
    dhPeer*: seq[byte]       ## peer's e/f mpint payload as received
    hostKey*: EdKeyPair      ## server signing key
    hasHostKey*: bool
    autoTrust*: bool         ## client: accept unknown host keys (tests)
    verifyMode*: VerifyMode
    knownHosts*: seq[KnownHostEntry]
    onHostKey*: proc(host: string, port: int, alg: string,
                     pubkey: array[32, byte]): bool {.closure.}
    peerHost*: string        ## remote host for known-hosts matching
    peerPort*: int
    kexName*: string
    hostKeyName*: string
    cipherC2s*: CipherKind  ## RFC 4253 §7.1 independent per-direction
    cipherS2c*: CipherKind  ## selection; may differ when the peer offers
    macC2s*: MacKind        ## direction-specific lists
    macS2c*: MacKind
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
    # ── RFC 4253 §9 rekey state ──
    rekey*: RekeyState
    pendingILocal*: seq[byte]
    pendingIPeer*: seq[byte]
    pendingKexName*: string
    pendingHostKeyName*: string
    pendingCipherC2s*: CipherKind
    pendingCipherS2c*: CipherKind
    pendingMacC2s*: MacKind
    pendingMacS2c*: MacKind
    pendingK*: seq[byte]
    pendingH*: array[32, byte]
    hasPendingH*: bool
    pendingKeys*: SessionKeys
    hasPendingKeys*: bool
    sendNewKeysSent*: bool   ## we switched send keys, wait peer NEWKEYS
    recvNewKeysGot*: bool    ## peer NEWKEYS processed, recv keys switched
    appQueue*: seq[seq[byte]] ## app payloads queued during rekey (§7.1)
    # ── triggers / accounting ──
    policy*: RekeyPolicy
    bytesSent*: uint64
    bytesRecv*: uint64
    packetsSent*: uint64
    packetsRecv*: uint64
    lastRekeyNanos*: int64
    # ── keepalive ──
    keepaliveIntervalMs*: int
    keepalivePayload*: string
    idleTimeoutMs*: int
    lastSendNanos*: int64
    lastRecvNanos*: int64

proc cipherKind*(s: SshSession): CipherKind {.deprecated:
  "Use cipherC2s/cipherS2c; asymmetric directions may differ (RFC 4253 §7.1)".} =
  ## Backward-compat reader: client-to-server direction.
  s.cipherC2s

proc macKind*(s: SshSession): MacKind {.deprecated:
  "Use macC2s/macS2c; asymmetric directions may differ (RFC 4253 §7.1)".} =
  s.macC2s

proc defaultRekeyPolicy*(): RekeyPolicy =
  ## RFC 4253 §9 RECOMMENDED 1 GB / 1 hour, plus packet-count and
  ## sequence-margin backstops so we rekey well before 2^32 wrap.
  RekeyPolicy(maxBytesSent: 1_000_000_000'u64, maxBytesRecv: 1_000_000_000'u64,
    maxPacketsSent: 1_000_000'u64, maxPacketsRecv: 1_000_000'u64,
    maxSeconds: 3600, seqnoMargin: 65535)

proc nowNanos(): int64 =
  getMonoTime().ticks

proc initRekeyAccounting(s: var SshSession) =
  let n = nowNanos()
  s.lastRekeyNanos = n
  s.lastSendNanos = n
  s.lastRecvNanos = n

proc isRekeying*(s: SshSession): bool {.inline.} =
  s.stage == stOpen and s.rekey != rsIdle

proc initClient*(autoTrust = false): SshSession =
  result.role = rClient
  result.stage = stVersion
  result.vLocal = SshVersion
  result.kexOffer = @[KexCurve25519Sha256, KexGroup14Sha256]
  result.hostKeyOffer = @[HostKeyEd25519]
  result.cipherOffer = @[ckChacha20Poly1305, ckAes128Ctr, ckAes256Ctr,
                         ckAes128Gcm, ckAes256Gcm]
  result.macOffer = @[mkHmacSha256, mkHmacSha512,
                      mkHmacSha256Etm, mkHmacSha512Etm]
  result.ephLocal = x25519GenKey()
  result.dhPriv = dhPrivate()
  result.autoTrust = autoTrust
  result.verifyMode = if autoTrust: vmAutoTrust else: vmStrict
  result.peerPort = 22
  result.keepalivePayload = "nssh"
  result.policy = defaultRekeyPolicy()
  result.initRekeyAccounting()

proc initServer*(hostKey: EdKeyPair): SshSession =
  result.role = rServer
  result.stage = stVersion
  result.vLocal = SshVersion
  result.kexOffer = @[KexCurve25519Sha256, KexGroup14Sha256]
  result.hostKeyOffer = @[HostKeyEd25519]
  result.cipherOffer = @[ckChacha20Poly1305, ckAes128Ctr, ckAes256Ctr,
                         ckAes128Gcm, ckAes256Gcm]
  result.macOffer = @[mkHmacSha256, mkHmacSha512,
                      mkHmacSha256Etm, mkHmacSha512Etm]
  result.ephLocal = x25519GenKey()
  result.dhPriv = dhPrivate()
  result.hostKey = hostKey
  result.hasHostKey = true
  result.verifyMode = vmAutoTrust
  result.keepalivePayload = "nssh"
  result.policy = defaultRekeyPolicy()
  result.initRekeyAccounting()

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
  result[2] = s.cipherOffer.mapIt($it)
  result[3] = s.cipherOffer.mapIt($it)
  result[4] = s.macOffer.mapIt($it)
  result[5] = s.macOffer.mapIt($it)
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

proc parseCipherKind*(s: string): CipherKind =
  for v in low(CipherKind) .. high(CipherKind):
    if $v == s:
      return v
  raise newException(SshSessionError, "ssh session: unknown cipher " & s)

proc parseMacKind*(s: string): MacKind =
  for v in low(MacKind) .. high(MacKind):
    if $v == s:
      return v
  raise newException(SshSessionError, "ssh session: unknown MAC " & s)

# ── send path ───────────────────────────────────────────────────────────────

proc freshEphemeral(s: var SshSession) =
  ## Fresh KEX secrets for initial or rekey KEXINIT (RFC 4253 §9:
  ## contexts reset, keys recomputed; ephemeral MUST NOT be reused).
  s.ephLocal = x25519GenKey()
  s.dhPriv = dhPrivate()

proc buildLocalKexPayload(s: SshSession): seq[byte] =
  var cookie: array[16, byte]
  let rnd = urandom(16)
  copyMem(addr cookie[0], unsafeAddr rnd[0], 16)
  let loc = s.localLists()
  result = buildKexInit(cookie, loc[0], loc[1], loc[2], loc[3], loc[4],
    loc[5], loc[6], loc[7], loc[8], loc[9])

proc selectAlgorithms(cLists, svLists: array[10, seq[string]]): tuple[
    kex, hostkey, cipherC2s, cipherS2c, macC2s, macS2c: string] =
  ## RFC 4253 §7.1: each direction is negotiated independently as the
  ## first algorithm on the client's list that is also on the server's
  ## list. Directions MAY differ when peers offer direction-specific lists.
  result.kex = pickFirst(cLists[0], svLists[0])
  if result.kex != KexCurve25519Sha256 and result.kex != KexGroup14Sha256:
    raise newException(SshSessionError, "ssh session: unsupported kex " & result.kex)
  result.hostkey = pickFirst(cLists[1], svLists[1])
  if result.hostkey != HostKeyEd25519:
    raise newException(SshSessionError, "ssh session: unsupported hostkey")
  result.cipherC2s = pickFirst(cLists[2], svLists[2])
  result.cipherS2c = pickFirst(cLists[3], svLists[3])
  result.macC2s = pickFirst(cLists[4], svLists[4])
  result.macS2c = pickFirst(cLists[5], svLists[5])

proc isAllowedDuringRekey(msgType: byte): bool {.inline.} =
  ## RFC 4253 §7.1: after KEXINIT until NEWKEYS, MUST NOT send other than
  ## transport-generic (1-19, minus SERVICE_REQUEST/ACCEPT) + kex (20-29
  ## minus further KEXINIT, + 30-49). DISCONNECT/IGNORE/DEBUG/UNIMPLEMENTED
  ## always flow; everything else (>=50 auth/channel) is queued.
  if msgType == MsgKexInit or msgType == MsgNewKeys:
    return true
  if msgType >= 30 and msgType <= 49:
    return true
  if msgType == MsgDisconnect or msgType == MsgIgnore or
     msgType == MsgUnimplemented or msgType == MsgDebug:
    return true
  if msgType >= 7 and msgType <= 19:
    return true
  return false

proc sendPayloadInner(s: var SshSession, payload: openArray[byte]) =
  ## BPP-encode (+ encrypt/MAC when active), queue wire bytes, bump seqno.
  ## Sequence numbers are never reset across rekey (RFC 4253 §6.4); the
  ## caller must rekey before 2^32. Raises instead of wrapping as a
  ## last-resort guard (policy triggers long before).
  if s.sendSeq == high(uint32):
    raise newException(SshSessionError, "ssh session: sequence rollover, rekey first")
  # When keys are active, the cipher kind lives in the directional state
  # so the two directions can differ per RFC 4253 §7.1 (and transiently
  # across NEWKEYS during rekey).
  let activeCipher =
    if s.sendActive: s.keys.toPeer.cipher.kind else: ckNone
  let spec = specFor(if s.sendActive: activeCipher else: ckNone)
  if not s.sendActive:
    let wire = encodePacket(payload, 8)
    s.bytesSent += uint64(wire.len)
    s.outbox.add(wire)
  elif activeCipher == ckAes128Ctr or activeCipher == ckAes256Ctr:
    if isEtm(s.keys.toPeer.mac):
      let enc = encodePacket(payload, spec.blockSize, lengthInClear = true)
      let ctRest = s.keys.toPeer.cipher.ctrCrypt(enc.toOpenArray(4, enc.high))
      var wire = newSeq[byte](4 + ctRest.len)
      copyMem(addr wire[0], unsafeAddr enc[0], 4)
      copyMem(addr wire[4], unsafeAddr ctRest[0], ctRest.len)
      let m = computeMac(s.keys.toPeer.mac, s.keys.toPeer.macKey, s.sendSeq,
        wire.toOpenArray(0, wire.high))
      let full = wire & m
      s.bytesSent += uint64(full.len)
      s.outbox.add(full)
    else:
      let enc = encodePacket(payload, spec.blockSize)
      let ct = s.keys.toPeer.cipher.ctrCrypt(enc)
      let m = computeMac(s.keys.toPeer.mac, s.keys.toPeer.macKey, s.sendSeq,
        enc.toOpenArray(0, enc.high))
      let full = ct & m
      s.bytesSent += uint64(full.len)
      s.outbox.add(full)
  elif activeCipher == ckAes128Gcm or activeCipher == ckAes256Gcm:
    let enc = encodePacket(payload, spec.blockSize, lengthInClear = true)
    var plen: array[4, byte]
    for i in 0 ..< 4: plen[i] = enc[i]
    let sealed = s.keys.toPeer.cipher.gcmSealPacket(plen, enc.toOpenArray(4, enc.high))
    var wire = newSeq[byte](4 + sealed.ct.len + 16)
    copyMem(addr wire[0], unsafeAddr plen[0], 4)
    copyMem(addr wire[4], unsafeAddr sealed.ct[0], sealed.ct.len)
    copyMem(addr wire[4 + sealed.ct.len], unsafeAddr sealed.tag[0], 16)
    s.bytesSent += uint64(wire.len)
    s.outbox.add(wire)
  elif activeCipher == ckChacha20Poly1305:
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
    s.bytesSent += uint64(wire.len)
    s.outbox.add(wire)
  else:
    raise newException(SshSessionError, "ssh session: cipher not wired")
  inc s.sendSeq
  inc s.packetsSent
  s.lastSendNanos = nowNanos()

proc needsRekey*(s: SshSession, nowNanosVal = 0'i64): bool =
  ## True when any automatic trigger fires. `nowNanosVal` injectable for tests.
  if s.stage != stOpen:
    return false
  let p = s.policy
  if p.maxPacketsSent > 0 and s.packetsSent >= p.maxPacketsSent:
    return true
  if p.maxPacketsRecv > 0 and s.packetsRecv >= p.maxPacketsRecv:
    return true
  if p.maxBytesSent > 0 and s.bytesSent >= p.maxBytesSent:
    return true
  if p.maxBytesRecv > 0 and s.bytesRecv >= p.maxBytesRecv:
    return true
  if p.seqnoMargin > 0:
    let remainSend = high(uint32) - s.sendSeq
    let remainRecv = high(uint32) - s.recvSeq
    if remainSend <= p.seqnoMargin or remainRecv <= p.seqnoMargin:
      return true
  if p.maxSeconds > 0:
    let now = if nowNanosVal != 0: nowNanosVal else: nowNanos()
    let elapsedSec = (now - s.lastRekeyNanos) div 1_000_000_000'i64
    if elapsedSec >= p.maxSeconds:
      return true
  return false

proc requestRekey*(s: var SshSession): bool =
  ## Initiate RFC 4253 §9 re-exchange. Returns false when not in `stOpen`
  ## or a rekey is already in flight (MUST NOT send a second KEXINIT).
  ## The KEXINIT itself travels under the old encryption (§9).
  if s.stage != stOpen or s.rekey != rsIdle:
    return false
  s.freshEphemeral()
  let payload = s.buildLocalKexPayload()
  s.pendingILocal = payload
  s.pendingIPeer = @[]
  s.pendingKexName = ""
  s.hasPendingKeys = false
  s.sendNewKeysSent = false
  s.recvNewKeysGot = false
  s.sendPayloadInner(payload)
  s.rekey = rsKexInitSent
  return true

proc maybeTriggerRekey*(s: var SshSession) =
  if s.stage == stOpen and s.rekey == rsIdle and s.needsRekey():
    discard s.requestRekey()

proc setRekeyPolicy*(s: var SshSession, p: RekeyPolicy) =
  s.policy = p

proc rekeyStats*(s: SshSession): tuple[bytesSent, bytesRecv, packetsSent,
    packetsRecv: uint64] =
  (s.bytesSent, s.bytesRecv, s.packetsSent, s.packetsRecv)

proc completeRekeyIfDone(s: var SshSession, events: var seq[SessionEvent]) =
  ## Both directions switched: adopt pending algorithms, reset accounting,
  ## flush queued app data (RFC 4253 §9: app data may flow after NEWKEYS),
  ## stamp `lastRekeyNanos` for the time trigger.
  if s.rekey == rsIdle or not s.sendNewKeysSent or not s.recvNewKeysGot:
    return
  s.cipherC2s = s.pendingCipherC2s
  s.cipherS2c = s.pendingCipherS2c
  s.macC2s = s.pendingMacC2s
  s.macS2c = s.pendingMacS2c
  s.K = s.pendingK
  s.H = s.pendingH
  s.rekey = rsIdle
  s.hasPendingKeys = false
  s.pendingILocal = @[]
  s.pendingIPeer = @[]
  s.bytesSent = 0
  s.bytesRecv = 0
  s.packetsSent = 0
  s.packetsRecv = 0
  let n = nowNanos()
  s.lastRekeyNanos = n
  s.lastSendNanos = n
  s.lastRecvNanos = n
  let queued = s.appQueue
  s.appQueue = @[]
  for q in queued:
    s.sendPayloadInner(q)
  events.add(SessionEvent(kind: evRekeyDone))

proc sendPayload*(s: var SshSession, payload: openArray[byte]) =
  ## Public send path. During rekey (RFC 4253 §7.1) application messages
  ## are queued until NEWKEYS is sent; transport/kex control flows.
  if payload.len == 0:
    raise newException(SshSessionError, "ssh session: empty payload")
  if s.stage == stClosed:
    raise newException(SshSessionError, "ssh session: connection closed")
  if s.isRekeying() and not isAllowedDuringRekey(payload[0]):
    s.appQueue.add(payload.toSeq())
    return
  s.sendPayloadInner(payload)
  s.maybeTriggerRekey()

proc startHandshake*(s: var SshSession) =
  ## Queue version line + KEXINIT. Call once before exchanging bytes.
  s.outbox.add(encodeVersionLine(s.vLocal))
  let payload = s.buildLocalKexPayload()
  s.iLocal = payload
  s.sendPayloadInner(payload)

proc sendIgnore*(s: var SshSession, data = "nssh") =
  var w = initWriter()
  w.writeByte(MsgIgnore)
  w.writeString(data)
  s.sendPayload(w.toBytes())

proc sendDisconnect*(s: var SshSession, reason: uint32, message: string) =
  ## Queue a DISCONNECT and mark the session closed for sending. The
  ## connection owner should flush the outbox then close TCP.
  ## Bypasses the rekey app queue and rekey triggers: DISCONNECT is
  ## always allowed (RFC 4253 §7.1) and terminates the connection.
  var w = initWriter()
  w.writeByte(MsgDisconnect)
  w.writeUint32(reason)
  w.writeString(message)
  w.writeString("")
  s.sendPayloadInner(w.toBytes())
  s.stage = stClosed
  s.rekey = rsIdle
  s.appQueue = @[]

# ── receive path ────────────────────────────────────────────────────────────

proc consume(s: var SshSession, n: int) =
  let left = s.inBuf.len - n
  if left > 0:
    copyMem(addr s.inBuf[0], addr s.inBuf[n], left)
  s.inBuf.setLen(left)

proc bumpRecvSeq(s: var SshSession) =
  ## Advance the inbound sequence number. Raises instead of wrapping
  ## (rekey before 2^32), mirroring the send-side guard in sendPayload.
  if s.recvSeq == high(uint32):
    raise newException(SshSessionError,
      "ssh session: receive sequence rollover, rekey first")
  inc s.recvSeq

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
  s.bumpRecvSeq()
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
    if int(packetLen) mod specFor(s.keys.fromPeer.cipher.kind).blockSize != 0:
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
    s.bumpRecvSeq()
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
  # aligned (mirrors OpenSSH's `need % block_size` rejection). Block size
  # is per recv direction so ETM-mixed or asymmetric ciphers decode right.
  if (4 + int(packetLen)) mod specFor(s.keys.fromPeer.cipher.kind).blockSize != 0:
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
  s.bumpRecvSeq()
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
  s.bumpRecvSeq()
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
  s.bumpRecvSeq()
  result = (true, payload)

proc pullOne(s: var SshSession): tuple[found: bool, payload: seq[byte]] =
  ## Single packet under the CURRENT recv cipher state. The caller must
  ## handle it before pulling again: NEWKEYS flips recv keys mid-buffer.
  ## Uses the directional cipher so send/recv can transiently differ
  ## across NEWKEYS during rekey (RFC 4253 §7.3).
  if not s.recvActive:
    result = s.pullPlaintextOne()
  else:
    let rk = s.keys.fromPeer.cipher.kind
    if rk == ckAes128Ctr or rk == ckAes256Ctr:
      result = s.pullCtrOne()
    elif rk == ckAes128Gcm or rk == ckAes256Gcm:
      result = s.pullGcmOne()
    else:
      result = s.pullChachaOne()

# ── KEXDH ───────────────────────────────────────────────────────────────────

proc kexRoles(s: SshSession): tuple[vC, vS: string, initC, initS: seq[byte]] =
  if s.role == rClient:
    result = (s.vLocal, s.vPeer, s.iLocal, s.iPeer)
  else:
    result = (s.vPeer, s.vLocal, s.iPeer, s.iLocal)

proc rekeyRoles(s: SshSession): tuple[vC, vS: string, initC, initS: seq[byte]] =
  ## Exchange-hash inputs for a rekey: fresh KEXINIT payloads (RFC 4253 §9
  ## processes re-exchange identically to initial, only session_id stays).
  if s.role == rClient:
    result = (s.vLocal, s.vPeer, s.pendingILocal, s.pendingIPeer)
  else:
    result = (s.vPeer, s.vLocal, s.pendingIPeer, s.pendingILocal)

proc activateKeys(s: var SshSession) =
  let sid = if s.hasSessionId: s.sessionId.toSeq() else: s.H.toSeq()
  s.keys = newSessionKeysAsym(s.K, s.H, sid, s.cipherC2s, s.cipherS2c,
    s.macC2s, s.macS2c, s.role == rClient)
  if not s.hasSessionId:
    s.sessionId = s.H
    s.hasSessionId = true

proc activatePendingKeys(s: var SshSession) =
  ## Rekey key schedule: session_id MUST remain the first H (RFC 4253
  ## §7.2/§9); keys/IVs are recomputed from pending K/H + pending algos.
  let sid = s.sessionId.toSeq()
  s.pendingKeys = newSessionKeysAsym(s.pendingK, s.pendingH, sid,
    s.pendingCipherC2s, s.pendingCipherS2c, s.pendingMacC2s,
    s.pendingMacS2c, s.role == rClient)
  s.hasPendingKeys = true

proc matchKnownHost(s: SshSession, pubkey: array[32, byte]): bool =
  for e in s.knownHosts:
    if e.alg != HostKeyEd25519:
      continue
    if e.pubkey != pubkey:
      continue
    if e.port != -1 and s.peerPort != 0 and e.port != s.peerPort:
      continue
    if e.host.len > 0 and s.peerHost.len > 0 and e.host != s.peerHost:
      continue
    return true
  return false

proc verifyHostKey(s: var SshSession, pubkey: array[32, byte],
    ksBlob: seq[byte]): bool =
  ## Client host-key policy shared by initial KEX and rekey (host keys
  ## MAY change on rekey per §9, so re-verify every time).
  case s.verifyMode
  of vmAutoTrust:
    return true
  of vmStrict:
    if s.matchKnownHost(pubkey):
      return true
    if s.onHostKey != nil:
      return s.onHostKey(s.peerHost, s.peerPort, HostKeyEd25519, pubkey)
    return false
  of vmTofu:
    if s.matchKnownHost(pubkey):
      return true
    if s.onHostKey != nil:
      return s.onHostKey(s.peerHost, s.peerPort, HostKeyEd25519, pubkey)
    # Without a callback/storage hook, fall back to legacy autoTrust flag
    # so existing tests keep working; real apps should set onHostKey.
    return s.autoTrust

proc sendNewKeys(s: var SshSession) =
  var n = initWriter()
  n.writeByte(MsgNewKeys)
  # NEWKEYS travels under the OLD keys (§7.3); the switch happens after.
  s.sendPayloadInner(n.toBytes())
  if s.stage == stOpen:
    # Rekey path: flip the send direction to pending keys now. All
    # messages sent after this MUST use the new keys (§7.3).
    if not s.hasPendingKeys:
      raise newException(SshSessionError, "ssh session: NEWKEYS with no pending keys")
    s.keys.toPeer = s.pendingKeys.toPeer
    s.sendNewKeysSent = true
    s.rekey = rsNewKeysSent
  else:
    s.sendActive = true

proc handleKexDhInit(s: var SshSession, payload: openArray[byte],
    events: var seq[SessionEvent]) =
  ## Server side: peer key -> H, sign, reply + NEWKEYS. Branches on kex.
  if not s.hasHostKey:
    raise newException(SshSessionError, "ssh session: server has no host key")
  let isRekey = s.stage == stOpen
  let (vC, vS, initC, initS) =
    if isRekey: s.rekeyRoles() else: s.kexRoles()
  let kexName = if isRekey: s.pendingKexName else: s.kexName
  let ksBlob = encodePubBlob(s.hostKey.pubkey)
  var w = initWriter()
  w.writeByte(MsgKexDhReply)
  w.writeString(ksBlob)
  if kexName == KexGroup14Sha256:
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
    if isRekey:
      s.pendingK = shared
      s.pendingH = H
      s.hasPendingH = true
      s.activatePendingKeys()
    else:
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
    if isRekey:
      s.pendingK = shared
      s.pendingH = H
      s.hasPendingH = true
      s.activatePendingKeys()
    else:
      s.K = shared
      s.H = H
      s.activateKeys()
    w.writeString(s.ephLocal.pub)
  let sigH = if isRekey: s.pendingH else: s.H
  let sig = edSign(s.hostKey, sigH)
  w.writeString(encodeSignature(sig))
  s.sendPayloadInner(w.toBytes())
  s.sendNewKeys()
  if isRekey:
    s.rekey = rsNewKeysSent
    s.completeRekeyIfDone(events)
  else:
    s.stage = stNewKeys

proc handleKexDhReply(s: var SshSession, payload: openArray[byte],
    events: var seq[SessionEvent]) =
  ## Client side: verify hostkey + signature, send NEWKEYS. Branches on kex.
  var r = initReader(payload)
  if r.readByte() != MsgKexDhReply:
    raise newException(SshSessionError, "ssh session: not a KEXDH_REPLY")
  let ksBlob = r.readString()
  let pub = parsePubBlob(ksBlob)
  if not s.verifyHostKey(pub, ksBlob):
    raise newException(SshSessionError, "ssh session: untrusted host key")
  let isRekey = s.stage == stOpen
  let (vC, vS, initC, initS) =
    if isRekey: s.rekeyRoles() else: s.kexRoles()
  let kexName = if isRekey: s.pendingKexName else: s.kexName
  if kexName == KexGroup14Sha256:
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
    if isRekey:
      s.pendingK = shared
      s.pendingH = H
      s.hasPendingH = true
      s.activatePendingKeys()
    else:
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
    if isRekey:
      s.pendingK = shared
      s.pendingH = H
      s.hasPendingH = true
      s.activatePendingKeys()
    else:
      s.K = shared
      s.H = H
  if not isRekey:
    s.activateKeys()
  s.sendNewKeys()
  if isRekey:
    s.rekey = rsNewKeysSent
    s.completeRekeyIfDone(events)
  else:
    s.stage = stNewKeys

# ── message dispatch ────────────────────────────────────────────────────────

proc negotiatePending(s: var SshSession, peerPayload: openArray[byte]) =
  ## Fill pending* algorithm selections from fresh KEXINIT pair.
  ## Client preference wins on both sides (RFC 4253 §7.1).
  s.pendingIPeer = peerPayload.toSeq()
  let peer = parseKexInit(peerPayload)
  var locR = initReader(s.pendingILocal)
  discard locR.readByte()
  discard locR.readRaw(16)
  var loc: array[10, seq[string]]
  for i in 0 ..< 10:
    loc[i] = locR.readNameList()
  let (cLists, svLists) =
    if s.role == rClient: (loc, peer) else: (peer, loc)
  let sel = selectAlgorithms(cLists, svLists)
  s.pendingKexName = sel.kex
  s.pendingHostKeyName = sel.hostkey
  s.pendingCipherC2s = parseCipherKind(sel.cipherC2s)
  s.pendingCipherS2c = parseCipherKind(sel.cipherS2c)
  s.pendingMacC2s = parseMacKind(sel.macC2s)
  s.pendingMacS2c = parseMacKind(sel.macS2c)

proc handleRekeyKexInit(s: var SshSession, payload: openArray[byte],
    events: var seq[SessionEvent]) =
  ## RFC 4253 §9: KEXINIT in stOpen starts/responds to re-exchange.
  ## Uses current encryption (payload arrived under old keys); new keys
  ## take effect only at NEWKEYS (§7.3). Never changes roles.
  if s.rekey == rsIdle:
    # Peer-initiated: MUST reply with our own KEXINIT (§9), fresh secrets.
    s.freshEphemeral()
    s.pendingILocal = s.buildLocalKexPayload()
    s.sendPayloadInner(s.pendingILocal)
    s.rekey = rsKexInitSent
    s.sendNewKeysSent = false
    s.recvNewKeysGot = false
    s.hasPendingKeys = false
    s.negotiatePending(payload)
  else:
    # We already sent KEXINIT: this packet IS the reply (§9 "except when
    # the received KEXINIT already was a reply"). Do not send another.
    if s.pendingIPeer.len > 0:
      raise newException(SshSessionError, "ssh session: duplicate KEXINIT during rekey")
    s.negotiatePending(payload)
  # KEXINIT exchange complete on this side: client speaks first (§8).
  if s.role == rClient:
    var w = initWriter()
    w.writeByte(MsgKexDhInit)
    if s.pendingKexName == KexGroup14Sha256:
      w.writeMpint(dhPublic(s.dhPriv, group14Prime()))
    else:
      w.writeString(s.ephLocal.pub)
    s.sendPayloadInner(w.toBytes())
    s.rekey = rsKexDh

proc handleMessage(s: var SshSession, payload: openArray[byte]): seq[SessionEvent] =
  result = @[]
  if payload.len == 0:
    raise newException(SshSessionError, "ssh session: empty payload")
  case payload[0]
  of MsgKexInit:
    if s.stage == stOpen:
      s.handleRekeyKexInit(payload, result)
      return
    if s.stage != stKexInit:
      raise newException(SshSessionError, "ssh session: unexpected KEXINIT")
    s.iPeer = payload.toSeq()
    let peer = parseKexInit(payload)
    let loc = s.localLists()
    # cLists is always the CLIENT's lists, svLists the SERVER's, so both
    # sides compute identical selections (client preference order wins).
    let (cLists, svLists) =
      if s.role == rClient: (loc, peer) else: (peer, loc)
    let sel = selectAlgorithms(cLists, svLists)
    s.kexName = sel.kex
    s.hostKeyName = sel.hostkey
    s.cipherC2s = parseCipherKind(sel.cipherC2s)
    s.cipherS2c = parseCipherKind(sel.cipherS2c)
    s.macC2s = parseMacKind(sel.macC2s)
    s.macS2c = parseMacKind(sel.macS2c)
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
    if s.stage == stOpen:
      if s.role != rServer or not s.isRekeying():
        raise newException(SshSessionError, "ssh session: unexpected KEXDH_INIT")
      s.handleKexDhInit(payload, result)
      return
    if s.role != rServer or s.stage != stKexDh:
      raise newException(SshSessionError, "ssh session: unexpected KEXDH_INIT")
    s.handleKexDhInit(payload, result)
  of MsgKexDhReply:
    if s.stage == stOpen:
      if s.role != rClient or not s.isRekeying():
        raise newException(SshSessionError, "ssh session: unexpected KEXDH_REPLY")
      s.handleKexDhReply(payload, result)
      return
    if s.role != rClient or s.stage != stKexDh:
      raise newException(SshSessionError, "ssh session: unexpected KEXDH_REPLY")
    s.handleKexDhReply(payload, result)
  of MsgNewKeys:
    if payload.len != 1:
      raise newException(SshSessionError, "ssh session: NEWKEYS with payload")
    if s.stage == stOpen:
      # Rekey NEWKEYS arrived under OLD keys (§7.3); flip recv direction
      # to pending keys now. Send direction flips when we sent NEWKEYS.
      if not s.isRekeying() or not s.hasPendingKeys:
        raise newException(SshSessionError, "ssh session: unexpected NEWKEYS")
      s.keys.fromPeer = s.pendingKeys.fromPeer
      s.recvActive = true
      s.recvNewKeysGot = true
      s.completeRekeyIfDone(result)
      return
    s.recvActive = true
    if s.sendActive and s.recvActive and s.stage == stNewKeys:
      s.stage = stOpen
      s.lastRekeyNanos = nowNanos()
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
  ## Wire bytes count toward the rekey volume triggers (RFC 4253 §9).
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
    s.bytesRecv += uint64(chunk.len)
    s.lastRecvNanos = nowNanos()
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
      inc s.packetsRecv
      # pullOne consumed exactly one packet and advanced recvSeq, so the
      # packet now in handleMessage has this sequence number. Stamp it on
      # every event so upper layers can reference it (UNIMPLEMENTED).
      let pseq = s.recvSeq - 1
      var evs = s.handleMessage(p)
      for i in 0 ..< evs.len:
        evs[i].seqno = pseq
        result.add(evs[i])
      # In-flight app data during rekey still counts; trigger our own
      # rekey after processing (never inside handleMessage mid-burst).
      if s.stage == stOpen and s.rekey == rsIdle and s.needsRekey():
        discard s.requestRekey()
  except ValueError as e:
    s.stage = stClosed
    result.add(SessionEvent(kind: evErrorMsg, message: e.msg))

# ── keepalive (opt-in IGNORE timer + idle timeout) ──────────────────────────

proc setKeepalive*(s: var SshSession, intervalMs = 0, idleTimeoutMs = 0,
    payload = "nssh") =
  ## `intervalMs > 0` sends IGNORE when idle that long; `idleTimeoutMs > 0`
  ## disconnects when no inbound packet arrives within the window.
  s.keepaliveIntervalMs = intervalMs
  s.idleTimeoutMs = idleTimeoutMs
  if payload.len > 0:
    s.keepalivePayload = payload
  let n = nowNanos()
  s.lastSendNanos = n
  s.lastRecvNanos = n

proc pollKeepalive*(s: var SshSession, nowNanosVal = 0'i64): seq[SessionEvent] =
  ## Drive keepalive timers. Call from `client`/`server` poll loops and
  ## long-running tests. Emits `evDisconnect` on idle timeout.
  result = @[]
  if s.stage != stOpen:
    return
  let now = if nowNanosVal != 0: nowNanosVal else: nowNanos()
  if s.idleTimeoutMs > 0:
    let idleMs = (now - s.lastRecvNanos) div 1_000_000'i64
    if idleMs >= int64(s.idleTimeoutMs):
      var w = initWriter()
      w.writeByte(MsgDisconnect)
      w.writeUint32(DisconnectByApplication)
      w.writeString("idle timeout")
      w.writeString("")
      # Bypass the app queue: DISCONNECT is always allowed (§7.1).
      s.sendPayloadInner(w.toBytes())
      s.stage = stClosed
      result.add(SessionEvent(kind: evDisconnect,
        message: "idle timeout"))
      return
  if s.keepaliveIntervalMs > 0:
    let sinceSendMs = (now - s.lastSendNanos) div 1_000_000'i64
    if sinceSendMs >= int64(s.keepaliveIntervalMs):
      # IGNORE is allowed during rekey and doubles as a liveness probe.
      var w = initWriter()
      w.writeByte(MsgIgnore)
      w.writeString(s.keepalivePayload)
      if s.isRekeying():
        s.sendPayloadInner(w.toBytes())
      else:
        s.sendPayload(w.toBytes())
