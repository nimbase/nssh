import std/tables
import std/unittest

import nssh/channel

proc openPair(): tuple[cm, sm: ChannelMux, cliId, srvId: uint32] =
  var cm = initMux(false)
  var sm = initMux(true)
  let cliId = cm.openSessionChannel()
  # deliver OPEN -> server
  for p in cm.takeOutbox():
    for ev in sm.feed(p, 0):
      discard ev
  # server OPEN_CONFIRMATION -> client
  for p in sm.takeOutbox():
    for ev in cm.feed(p, 0):
      discard ev
  assert cm.channels[cliId].state == chOpen
  var srvId = high(uint32)
  for id, c in sm.channels:
    if c.state == chOpen:
      srvId = id
  assert srvId != high(uint32)
  result = (cm, sm, cliId, srvId)

proc deliver(src: var ChannelMux, dst: var ChannelMux): seq[ChanEvent] =
  result = @[]
  for p in src.takeOutbox():
    for ev in dst.feed(p, 7):
      result.add(ev)

test "pty-req carries dims and modes":
  var (cm, sm, cliId, srvId) = openPair()
  let modes = @[1'u8, 2, 3, 4, 5, 6, 7, 8]
  cm.requestPty(cliId, "xterm-256color", 80, 24, 640, 480, modes)
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevPty
  check evs[0].text == "xterm-256color"
  check evs[0].cols == 80
  check evs[0].rows == 24
  check evs[0].widthPx == 640
  check evs[0].heightPx == 480
  check evs[0].data == @modes
  # server auto-replied SUCCESS
  let back = deliver(sm, cm)
  check back.len == 1
  check back[0].kind == cevRequestOk

test "env request round trip":
  var (cm, sm, cliId, srvId) = openPair()
  cm.requestEnv(cliId, "LANG", "C.UTF-8")
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevEnv
  check evs[0].text == "LANG"
  check evs[0].text2 == "C.UTF-8"

test "window-change event with dims, no reply storm":
  var (cm, sm, cliId, srvId) = openPair()
  discard deliver(sm, cm) # drain open confirm replies
  cm.requestWindowChange(cliId, 120, 40, 960, 800)
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevWindowChange
  check evs[0].cols == 120
  check evs[0].rows == 40
  check evs[0].widthPx == 960
  check evs[0].heightPx == 800
  # window-change wants no reply: server outbox stays empty
  check sm.takeOutbox().len == 0

test "signal event with name":
  var (cm, sm, cliId, srvId) = openPair()
  cm.requestSignal(cliId, "INT")
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevSignal
  check evs[0].text == "INT"
  check sm.takeOutbox().len == 0

test "subsystem event, app replies explicitly":
  var (cm, sm, cliId, srvId) = openPair()
  # client asks for sftp; server emits the event with NO auto-reply
  cm.requestSubsystem(cliId, "sftp")
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevSubsystem
  check evs[0].text == "sftp"
  check sm.takeOutbox().len == 0
  # app accepts: client sees SUCCESS
  sm.replyChannelRequest(srvId, true)
  let back = deliver(sm, cm)
  check back.len == 1
  check back[0].kind == cevRequestOk
  # explicit decline path
  var (cm2, sm2, c2, s2) = openPair()
  cm2.requestSubsystem(c2, "sftp")
  check deliver(cm2, sm2)[0].kind == cevSubsystem
  sm2.replyChannelRequest(s2, false)
  let back2 = deliver(sm2, cm2)
  check back2.len == 1
  check back2[0].kind == cevRequestFail

test "exit-signal sender round trip":
  var (cm, sm, cliId, srvId) = openPair()
  sm.sendExitSignal(srvId, "TERM", false, "killed", "")
  let evs = deliver(sm, cm)
  check evs.len == 1
  check evs[0].kind == cevExitSignal
  check evs[0].text == "TERM"

test "half-close handshake: EOF answered with EOF+CLOSE":
  # Regression: OpenSSH sftp sends CHANNEL_EOF at batch end and waits
  # for our EOF+CLOSE before sending its CLOSE. No reply = hang.
  var (cm, sm, cliId, srvId) = openPair()
  cm.sendEof(cliId)
  let evs = deliver(cm, sm)
  check evs.len == 1
  check evs[0].kind == cevEof
  # app answers like an SFTP pump would
  sm.sendEof(srvId)
  sm.sendClose(srvId)
  let back = deliver(sm, cm)
  check back.len == 2
  check back[0].kind == cevEof
  check back[1].kind == cevClose
  # client CLOSE completes both sides
  let done = deliver(cm, sm)
  check done.len == 1
  check done[0].kind == cevClose
  check sm.takeOutbox().len == 0 # no duplicate CLOSE
