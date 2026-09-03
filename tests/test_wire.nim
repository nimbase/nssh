import std/net
import std/unittest

import powpow

import nssh/client
import nssh/server
import nssh/codec

proc freePort(): int =
  var s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(Port(0), "127.0.0.1")
  let (_, port) = s.getLocalAddr()
  s.close()
  result = port.int

proc ignoreText(p: seq[byte]): string =
  var r = initReader(p)
  discard r.readByte()
  result = r.readStringStr()

test "tcp loopback handshake + encrypted traffic":
  let loop = newLoop()
  let port = freePort()
  let hk = generateEdKey()

  var cliReady = false
  var srvReady = false
  var cliSid: seq[byte]
  var srvSid: seq[byte]
  var srvGot = ""
  var cliGot = ""
  var errLog: seq[string] = @[]
  var srvConn: ServerConn = nil

  var srv = newSshServer(loop, hk, "127.0.0.1", port,
    onReady = proc(c: ServerConn) =
      srvReady = true
      srvConn = c
      srvSid = @(c.session.sessionId)
    ,
    onPacket = proc(c: ServerConn, m: byte, p: seq[byte]) =
      if m == MsgIgnore:
        srvGot = ignoreText(p)
    ,
    onError = proc(c: ServerConn, msg: string) =
      errLog.add("srv: " & msg)
    ,
  )
  var cli = dial(loop, "127.0.0.1", port, autoTrust = true,
    onReady = proc(c: SshClient) =
      cliReady = true
      cliSid = @(c.session.sessionId)
    ,
    onPacket = proc(c: SshClient, m: byte, p: seq[byte]) =
      if m == MsgIgnore:
        cliGot = ignoreText(p)
    ,
    onError = proc(c: SshClient, msg: string) =
      errLog.add("cli: " & msg)
    ,
  )

  for _ in 0 ..< 500:
    if cliReady and srvReady:
      break
    loop.poll(20)
  check cliReady
  check srvReady
  check cliSid == srvSid
  check cliSid.len == 32

  cli.sendIgnore("hello-srv")
  for _ in 0 ..< 200:
    if srvGot != "":
      break
    loop.poll(20)
  check srvGot == "hello-srv"

  srv.sendIgnore(srvConn, "hello-cli")
  for _ in 0 ..< 200:
    if cliGot != "":
      break
    loop.poll(20)
  check cliGot == "hello-cli"
  check errLog.len == 0

  cli.close()
  srv.close()
  loop.close()
