import std/strutils
import std/unittest

import nssh/session
import nssh/codec
import nssh/ciphers
import nssh/kex
import nssh/hostkeys

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
  check cli.cipherKind == ckChacha20Poly1305
  check srv.cipherKind == ckChacha20Poly1305
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
  cli.cipherOffer = @[$ckAes128Gcm]
  srv.cipherOffer = @[$ckAes128Gcm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv, chunkSize = 7)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.cipherKind == ckAes128Gcm
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
  cli.cipherOffer = @[$ckAes128Ctr]
  srv.cipherOffer = @[$ckAes128Ctr]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv, chunkSize = 5)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.cipherKind == ckAes128Ctr
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
  cli.cipherOffer = @[$ckAes256Ctr]
  srv.cipherOffer = @[$ckAes256Ctr]
  cli.macOffer = @[$mkHmacSha512Etm]
  srv.macOffer = @[$mkHmacSha512Etm]
  cli.startHandshake()
  srv.startHandshake()
  let (cEv, sEv) = pump(cli, srv)
  check hasReady(cEv)
  check hasReady(sEv)
  check cli.macKind == mkHmacSha512Etm
  cli.sendIgnore("etm-ok")
  let r1 = pump(cli, srv)
  var got = false
  for e in r1.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

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
