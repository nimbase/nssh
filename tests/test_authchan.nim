import std/tables
import std/unittest

import nssh/session
import nssh/auth
import nssh/channel
import nssh/hostkeys

proc pumpHs(cli, srv: var SshSession, maxRounds = 20) =
  for _ in 0 ..< maxRounds:
    var moved = false
    for pkt in cli.takeOutbox():
      moved = true
      discard srv.receiveBytes(pkt)
    for pkt in srv.takeOutbox():
      moved = true
      discard cli.receiveBytes(pkt)
    if not moved:
      break

proc pumpUpper(cli, srv: var SshSession, ca: var AuthClient, sa: var AuthServer,
               cm, sm: var ChannelMux, maxRounds = 30,
               onCliChan: proc(ev: ChanEvent) {.closure.} = nil,
               onSrvChan: proc(ev: ChanEvent) {.closure.} = nil) =
  ## Route post-handshake evPackets to auth (<80) or channel (>=90) layers.
  for _ in 0 ..< maxRounds:
    var moved = false
    for pkt in cli.takeOutbox():
      moved = true
      for ev in srv.receiveBytes(pkt):
        if ev.kind == evPacket:
          if ev.payload[0] < 80:
            discard sa.authFeed(ev.payload)
          else:
            for ce in sm.feed(ev.payload):
              if onSrvChan != nil:
                onSrvChan(ce)
    for p in sa.takeOutbox():
      srv.sendPayload(p)
      moved = true
    for p in sm.takeOutbox():
      srv.sendPayload(p)
      moved = true
    for pkt in srv.takeOutbox():
      moved = true
      for ev in cli.receiveBytes(pkt):
        if ev.kind == evPacket:
          if ev.payload[0] < 80:
            discard ca.authFeed(ev.payload)
          else:
            for ce in cm.feed(ev.payload):
              if onCliChan != nil:
                onCliChan(ce)
    for p in ca.takeOutbox():
      cli.sendPayload(p)
      moved = true
    for p in cm.takeOutbox():
      cli.sendPayload(p)
      moved = true
    if not moved:
      break

test "auth publickey loopback":
  let hk = generateEdKey()
  let userKey = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  pumpHs(cli, srv)
  check cli.stage == stOpen
  check srv.stage == stOpen

  var ca = initAuthClient("testuser", cli.sessionId, userKey)
  var sa = initAuthServer(srv.sessionId,
    checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} =
      try:
        discard parsePubBlob(blob)
        true
      except ValueError:
        false)
  var cm = initMux(false)
  var sm = initMux(true)
  ca.authStart()
  pumpUpper(cli, srv, ca, sa, cm, sm)
  check ca.done
  check sa.done
  check sa.user == "testuser"

test "auth password loopback":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  pumpHs(cli, srv)

  var ca = initAuthClient("bob", cli.sessionId, password = "s3cret")
  var sa = initAuthServer(srv.sessionId,
    checkPassword = proc(u, p: string): bool {.closure.} = p == "s3cret")
  var cm = initMux(false)
  var sm = initMux(true)
  ca.authStart()
  pumpUpper(cli, srv, ca, sa, cm, sm)
  check ca.done
  check sa.done
  check sa.user == "bob"

test "auth wrong password fails":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  pumpHs(cli, srv)

  var ca = initAuthClient("bob", cli.sessionId, password = "wrong")
  var sa = initAuthServer(srv.sessionId,
    checkPassword = proc(u, p: string): bool {.closure.} = p == "s3cret")
  var cm = initMux(false)
  var sm = initMux(true)
  ca.authStart()
  pumpUpper(cli, srv, ca, sa, cm, sm)
  check not ca.done
  check not sa.done

test "channel exec loopback over chacha session":
  let hk = generateEdKey()
  let userKey = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  pumpHs(cli, srv)

  var ca = initAuthClient("u", cli.sessionId, userKey)
  var sa = initAuthServer(srv.sessionId,
    checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} = true)
  var cm = initMux(false)
  var sm = initMux(true)
  ca.authStart()
  pumpUpper(cli, srv, ca, sa, cm, sm)
  check ca.done and sa.done

  # open + exec
  let chId = cm.openSessionChannel()
  var srvChId: uint32 = high(uint32)
  var gotCmd = ""
  pumpUpper(cli, srv, ca, sa, cm, sm,
    onSrvChan = proc(ev: ChanEvent) {.closure.} =
      if ev.kind == cevOpened:
        srvChId = ev.localId)
  check cm.channels.hasKey(chId)
  check cm.channels[chId].state == chOpen
  cm.requestExec(chId, "echo hi")
  pumpUpper(cli, srv, ca, sa, cm, sm,
    onSrvChan = proc(ev: ChanEvent) {.closure.} =
      if ev.kind == cevExec:
        gotCmd = ev.text)
  check gotCmd == "echo hi"

  # server replies with data + status + eof + close
  var cliData: seq[byte] = @[]
  var cliStatus = -1
  var cliClosed = false
  check sm.sendData(srvChId, @[byte('h'), byte('i'), byte('\n')]) == 3
  sm.sendExitStatus(srvChId, 0)
  sm.sendEof(srvChId)
  sm.sendClose(srvChId)
  pumpUpper(cli, srv, ca, sa, cm, sm,
    onCliChan = proc(ev: ChanEvent) {.closure.} =
      case ev.kind
      of cevData: cliData.add(ev.data)
      of cevExitStatus: cliStatus = int(ev.status)
      of cevClose: cliClosed = true
      else: discard)
  check cliData == @[byte('h'), byte('i'), byte('\n')]
  check cliStatus == 0
  check cliClosed
  check srvChId notin sm.channels # reaped after close exchange
