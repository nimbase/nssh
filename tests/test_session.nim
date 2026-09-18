import std/strutils
import std/sequtils
import std/unittest

import nssh/session
import nssh/codec
import nssh/ciphers
import nssh/kex
import nssh/hostkeys
import nssh/transport

proc pump(cli, srv: var SshSession, chunkSize = 0,
          maxRounds = 20): tuple[cEv, sEv: seq[SessionEvent]] =
  ## Exchange outboxes until quiescent. chunkSize>0 splits writes to prove
  ## streaming reassembly (incl. through encryption).
  result.cEv = @[]
  result.sEv = @[]
  for _ in 0 ..< maxRounds:
    var moved = false
    for pkt in cli.takeOutbox():
      moved = true
      if chunkSize <= 0:
        for ev in srv.receiveBytes(pkt):
          result.sEv.add(ev)
      else:
        var i = 0
        while i < pkt.len:
          let j = min(i + chunkSize, pkt.len)
          for ev in srv.receiveBytes(pkt.toOpenArray(i, j - 1)):
            result.sEv.add(ev)
          i = j
    for pkt in srv.takeOutbox():
      moved = true
      if chunkSize <= 0:
        for ev in cli.receiveBytes(pkt):
          result.cEv.add(ev)
      else:
        var i = 0
        while i < pkt.len:
          let j = min(i + chunkSize, pkt.len)
          for ev in cli.receiveBytes(pkt.toOpenArray(i, j - 1)):
            result.cEv.add(ev)
          i = j
    if not moved:
      break

proc hasReady(ev: seq[SessionEvent]): bool =
  for e in ev:
    if e.kind == evReady:
      return true
  return false

proc hasError(ev: seq[SessionEvent]): bool =
  for e in ev:
    if e.kind == evErrorMsg:
      return true
  return false

test "loopback handshake diffie-hellman-group14-sha256":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.kexOffer = @[KexGroup14Sha256]
  srv.kexOffer = @[KexGroup14Sha256]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.stage == stOpen
  check srv.stage == stOpen
  check cli.kexName == KexGroup14Sha256
  check srv.kexName == KexGroup14Sha256
  check cli.sessionId == srv.sessionId
  check cli.K == srv.K
  check cli.K.len == 256 # full-size group14 shared secret
  cli.sendIgnore("g14-ok")
  let r1 = pump(cli, srv)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "loopback handshake chacha20-poly1305":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.stage == stOpen
  check srv.stage == stOpen
  check cli.sessionId == srv.sessionId
  check cli.H == srv.H
  check cli.K == srv.K
  check cli.cipherC2s == ckChacha20Poly1305
  check cli.cipherS2c == ckChacha20Poly1305
  check srv.cipherC2s == ckChacha20Poly1305
  check srv.cipherS2c == ckChacha20Poly1305
  # encrypted traffic both ways
  cli.sendIgnore("hello-srv")
  let r1 = pump(cli, srv)
  var gotSrv = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      var r = initReader(e.payload)
      discard r.readByte()
      check r.readStringStr() == "hello-srv"
      gotSrv = true
  check gotSrv
  srv.sendIgnore("hello-cli")
  let r2 = pump(cli, srv)
  var gotCli = false
  for e in r2.cEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      var r = initReader(e.payload)
      discard r.readByte()
      check r.readStringStr() == "hello-cli"
      gotCli = true
  check gotCli

test "loopback handshake aes128-gcm, chunked":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes128Gcm]
  srv.cipherOffer = @[ckAes128Gcm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv, chunkSize = 7)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.cipherC2s == ckAes128Gcm
  check cli.cipherS2c == ckAes128Gcm
  check cli.K == srv.K
  cli.sendIgnore("gcm-ok")
  let r1 = pump(cli, srv, chunkSize = 7)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "loopback handshake aes128-ctr, 5-byte chunks":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes128Ctr]
  srv.cipherOffer = @[ckAes128Ctr]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv, chunkSize = 5)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.cipherC2s == ckAes128Ctr
  check cli.cipherS2c == ckAes128Ctr
  check cli.K == srv.K
  check cli.sessionId == srv.sessionId
  cli.sendIgnore("ctr-ok")
  let r1 = pump(cli, srv, chunkSize = 5)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "loopback handshake aes256-ctr hmac-sha2-512-etm":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes256Ctr]
  srv.cipherOffer = @[ckAes256Ctr]
  cli.macOffer = @[mkHmacSha512Etm]
  srv.macOffer = @[mkHmacSha512Etm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.macC2s == mkHmacSha512Etm
  check cli.macS2c == mkHmacSha512Etm
  cli.sendIgnore("etm-ok")
  let r1 = pump(cli, srv)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "loopback handshake aes256-gcm, chunked":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes256Gcm]
  srv.cipherOffer = @[ckAes256Gcm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv, chunkSize = 7)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.cipherC2s == ckAes256Gcm
  check cli.cipherS2c == ckAes256Gcm
  check cli.K == srv.K
  cli.sendIgnore("gcm256-ok")
  srv.sendIgnore("gcm256-back")
  let r1 = pump(cli, srv, chunkSize = 7)
  var gotSrv = false
  var gotCli = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      gotSrv = true
  for e in r1.cEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      gotCli = true
  check gotSrv
  check gotCli

test "loopback handshake aes256-ctr hmac-sha2-256":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes256Ctr]
  srv.cipherOffer = @[ckAes256Ctr]
  cli.macOffer = @[mkHmacSha256]
  srv.macOffer = @[mkHmacSha256]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.macC2s == mkHmacSha256
  check cli.macS2c == mkHmacSha256
  check srv.macC2s == mkHmacSha256
  check srv.macS2c == mkHmacSha256
  cli.sendIgnore("ctr256-ok")
  let r1 = pump(cli, srv)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "loopback handshake aes128-ctr hmac-sha2-256-etm":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes128Ctr]
  srv.cipherOffer = @[ckAes128Ctr]
  cli.macOffer = @[mkHmacSha256Etm]
  srv.macOffer = @[mkHmacSha256Etm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.macC2s == mkHmacSha256Etm
  check cli.macS2c == mkHmacSha256Etm
  cli.sendIgnore("etm128-ok")
  let r1 = pump(cli, srv)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "asymmetric directions negotiated independently per RFC4253 7.1":
  let hk = generateEdKey()
  var srv = initServer(hk)
  srv.startHandshake()
  for ev in srv.receiveBytes(encodeVersionLine("SSH-2.0-fake")):
    check ev.kind != evErrorMsg
  check srv.stage == stKexInit
  # Peer offers direction-specific lists: c2s aes128-ctr, s2c aes256-ctr.
  var cookie: array[16, byte]
  let kexPayload = buildKexInit(cookie,
    @[KexCurve25519Sha256], @[HostKeyEd25519],
    @[$ckAes128Ctr], @[$ckAes256Ctr],
    @[$mkHmacSha256], @[$mkHmacSha256Etm],
    @["none"], @["none"], @[], @[])
  let ev = srv.receiveBytes(encodePacket(kexPayload, 8))
  check not hasError(ev)
  check srv.stage == stKexDh
  check srv.cipherC2s == ckAes128Ctr
  check srv.cipherS2c == ckAes256Ctr
  check srv.macC2s == mkHmacSha256
  check srv.macS2c == mkHmacSha256Etm

test "disjoint cipher offers fail negotiation":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[ckAes128Ctr]
  srv.cipherOffer = @[ckAes256Ctr]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasError(cEv) or hasError(sEv)

test "asymmetric transport carries both directions with mixed ciphers/MACs":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  check cli.stage == stOpen
  # Switch both sides to agreed asymmetric algorithms (C2S aes128-ctr +
  # hmac-sha2-256, S2C aes256-ctr + hmac-sha2-512-etm), same K/H/sessionId.
  # Exercises per-direction ETM framing and CTR states on the wire.
  cli.cipherC2s = ckAes128Ctr
  cli.cipherS2c = ckAes256Ctr
  cli.macC2s = mkHmacSha256
  cli.macS2c = mkHmacSha512Etm
  srv.cipherC2s = ckAes128Ctr
  srv.cipherS2c = ckAes256Ctr
  srv.macC2s = mkHmacSha256
  srv.macS2c = mkHmacSha512Etm
  let sid = cli.sessionId.toSeq()
  cli.keys = newSessionKeysAsym(cli.K, cli.H, sid, ckAes128Ctr, ckAes256Ctr,
    mkHmacSha256, mkHmacSha512Etm, true)
  srv.keys = newSessionKeysAsym(srv.K, srv.H, sid, ckAes128Ctr, ckAes256Ctr,
    mkHmacSha256, mkHmacSha512Etm, false)
  cli.sendIgnore("c2s-mixed")
  srv.sendIgnore("s2c-mixed")
  let r = pump(cli, srv, chunkSize = 5)
  var gotC2s = false
  var gotS2c = false
  for e in r.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      var rd = initReader(e.payload)
      discard rd.readByte()
      if rd.readStringStr() == "c2s-mixed":
        gotC2s = true
  for e in r.cEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      var rd = initReader(e.payload)
      discard rd.readByte()
      if rd.readStringStr() == "s2c-mixed":
        gotS2c = true
  check gotC2s
  check gotS2c

test "rekey KEXINIT performs RFC4253 re-exchange, not disconnect":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  check cli.stage == stOpen
  check srv.stage == stOpen
  let sidBefore = cli.sessionId
  check cli.requestRekey()
  let r1 = pump(cli, srv)
  var rekeyed = 0
  for e in r1.cEv:
    if e.kind == evRekeyDone:
      inc rekeyed
  for e in r1.sEv:
    if e.kind == evRekeyDone:
      inc rekeyed
  check rekeyed == 2
  check cli.stage == stOpen
  check srv.stage == stOpen
  check cli.sessionId == sidBefore
  check srv.sessionId == sidBefore
  check cli.K == srv.K
  # Traffic flows under the new keys with continuing sequence numbers.
  cli.sendIgnore("post-rekey")
  let r2 = pump(cli, srv)
  var got = false
  for e in r2.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "receive sequence rollover refused, not wrapped":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  check srv.stage == stOpen
  srv.recvSeq = high(uint32)
  cli.sendIgnore("last")
  let r1 = pump(cli, srv)
  check hasError(r1.sEv)
  check srv.stage == stClosed
  check srv.recvSeq == high(uint32)

test "graceful disconnect carries reason":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  check cli.stage == stOpen
  cli.sendDisconnect(11'u32, "admin bye")
  check cli.stage == stClosed
  let (_, sEv) = pump(cli, srv)
  var gotDisc = ""
  for e in sEv:
    if e.kind == evDisconnect:
      gotDisc = e.message
  check gotDisc.contains("admin bye")
  check srv.stage == stClosed

test "untrusted host key aborts":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = false)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, _) = pump(cli, srv)
  check hasError(cEv)
  check cli.stage == stClosed

test "tampered ciphertext aborts session":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  check cli.stage == stOpen
  cli.sendIgnore("secret")
  var wire = cli.takeOutbox()
  check wire.len == 1
  wire[0][7] = wire[0][7] xor 0xFF
  let ev = srv.receiveBytes(wire[0])
  check hasError(ev)
  check srv.stage == stClosed
