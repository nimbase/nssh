## Interop against system OpenSSH (skipped if tools are missing).
##
## A: `ssh` command runs a remote exec against OUR server (tests our
##    handshake + service + publickey auth + channel/exec/exit-status).
## B: OUR client runs a remote exec against system `sshd`.

import std/net
import std/os
import std/osproc
import std/streams
import std/tables
import std/unittest

import powpow

import nssh/client
import nssh/server
import nssh/auth
import nssh/channel
import nssh/codec

proc freePort(): int =
  var s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(Port(0), "127.0.0.1")
  let (_, port) = s.getLocalAddr()
  s.close()
  result = port.int

proc haveTool(name: string): bool =
  findExe(name) != ""

type
  SrvApp = ref object
    auth: AuthServer
    mux: ChannelMux
    execCmd: string
    execCh: uint32
    hasExec: bool

proc routeSrvApp(srv: SshServer, c: ServerConn, app: SrvApp,
                 msgType: byte, payload: seq[byte]) =
  if msgType < 80:
    let ev = app.auth.authFeed(payload)
    if ev.kind == asSuccess:
      discard
    for p in app.auth.takeOutbox():
      srv.sendRaw(c, p)
  else:
    for ev in app.mux.feed(payload):
      case ev.kind
      of cevExec:
        app.execCmd = ev.text
        app.execCh = ev.localId
        app.hasExec = true
        # canned response + clean exit
        discard app.mux.sendData(ev.localId, @[byte('o'), byte('k'), byte('\n')])
        app.mux.sendExitStatus(ev.localId, 0)
        app.mux.sendEof(ev.localId)
        app.mux.sendClose(ev.localId)
      else:
        discard
    for p in app.mux.takeOutbox():
      srv.sendRaw(c, p)

test "A: openssh client runs exec on our server":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  let tmp = getTempDir() / "nssh-interop-a"
  createDir(tmp)
  defer: removeDir(tmp)
  # client key for ssh (our server auto-trusts any key)
  let keyPath = tmp / "id_ed"
  check execShellCmd("ssh-keygen -q -t ed25519 -N '' -f " & keyPath) == 0

  let loop = newLoop()
  let port = freePort()
  let hk = generateEdKey()
  var apps = initTable[pointer, SrvApp]()
  var sawExec = ""
  var srv: SshServer
  srv = newSshServer(loop, hk, "127.0.0.1", port,
    onReady = proc(c: ServerConn) =
      apps[cast[pointer](c)] = SrvApp(
        auth: initAuthServer(c.session.sessionId,
          checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} = true),
        mux: initMux(true))
    ,
    onPacket = proc(c: ServerConn, m: byte, p: seq[byte]) =
      let app = apps.getOrDefault(cast[pointer](c))
      if app != nil:
        routeSrvApp(srv, c, app, m, p)
        if app.hasExec:
          sawExec = app.execCmd
    ,
    onClose = proc(c: ServerConn) =
      apps.del(cast[pointer](c))
    ,
  )

  let sshProc = startProcess("ssh",
    args = @["-p", $port, "-i", keyPath,
             "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=10",
             "-o", "LogLevel=ERROR",
             "interop@localhost", "echo hello-interop"],
    options = {poUsePath})
  var sshOut = ""
  var sshCode = -1
  for _ in 0 ..< 1200:
    loop.poll(25)
    sshCode = sshProc.peekExitCode()
    if sshCode != -1:
      break
  if sshCode == -1:
    sshProc.kill()
    loop.poll(50)
  sshOut = sshProc.outputStream().readAll()
  sshCode = sshProc.peekExitCode()
  sshProc.close()

  check sawExec == "echo hello-interop"
  check sshCode == 0
  check sshOut == "ok\n"

  srv.close()
  loop.close()

test "B: our client runs exec on system sshd":
  if not (haveTool("sshd") and haveTool("ssh-keygen")):
    skip()
  let tmp = getHomeDir() / ".nssh-interop-b"
  createDir(tmp)
  setFilePermissions(tmp, {fpUserExec, fpUserWrite, fpUserRead})
  defer: removeDir(tmp)
  let hostKeyPath = tmp / "host_ed"
  check execShellCmd("ssh-keygen -q -t ed25519 -N '' -f " & hostKeyPath) == 0
  # user key generated in-process; authorized via our own encoder
  let userKey = generateEdKey()
  writeFile(tmp / "authorized_keys", encodeAuthorizedKeysLine(userKey.pubkey) & "\n")
  setFilePermissions(tmp / "authorized_keys",
    {fpUserWrite, fpUserRead})
  let cfgPath = tmp / "sshd_config"
  let port = freePort()
  writeFile(cfgPath,
    "Port " & $port & "\n" &
    "ListenAddress 127.0.0.1\n" &
    "HostKey " & hostKeyPath & "\n" &
    "PidFile " & tmp / "sshd.pid" & "\n" &
    "AuthorizedKeysFile " & tmp / "authorized_keys" & "\n" &
    "PasswordAuthentication no\n" &
    "PubkeyAuthentication yes\n" &
    "ChallengeResponseAuthentication no\n" &
    "UsePAM no\n")
  let logPath = tmp / "sshd.log"
  let sshdProc = startProcess("/usr/sbin/sshd",
    args = @["-f", cfgPath, "-E", logPath], options = {poUsePath})
  defer:
    sshdProc.kill()
    sshdProc.close()
  # wait for listen
  var up = false
  for _ in 0 ..< 100:
    var probe = newSocket()
    try:
      probe.connect("127.0.0.1", Port(port))
      up = true
      probe.close()
      break
    except OSError:
      sleep(50)
  check up

  let loop = newLoop()
  let user = getEnv("USER", "nobody")
  var authed = false
  var gotData = ""
  var gotStatus = -1
  var gotClosed = false
  var authDone = false
  var chanOpened = false
  var execSent = false
  var ca = initAuthClient("", [0'u8, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    userKey)
  var cm = initMux(false)
  var chId: uint32 = 0
  var cli: SshClient
  cli = dial(loop, "127.0.0.1", port, autoTrust = true,
    onReady = proc(c: SshClient) =
      ca = initAuthClient(user, c.session.sessionId, userKey)
      ca.authStart()
      for p in ca.takeOutbox():
        c.sendRaw(p)
    ,
    onPacket = proc(c: SshClient, m: byte, p: seq[byte]) =
      if m < 80 and not authDone:
        let ev = ca.authFeed(p)
        for q in ca.takeOutbox():
          c.sendRaw(q)
        if ev.kind == acSuccess:
          authDone = true
          authed = true
          chId = cm.openSessionChannel()
          for q in cm.takeOutbox():
            c.sendRaw(q)
      elif m >= 90:
        for ev in cm.feed(p):
          case ev.kind
          of cevOpened:
            if not execSent:
              execSent = true
              chanOpened = true
              cm.requestExec(ev.localId, "echo from-nssh")
              for q in cm.takeOutbox():
                c.sendRaw(q)
          of cevData:
            for b in ev.data:
              gotData.add(char(b))
          of cevExitStatus:
            gotStatus = int(ev.status)
          of cevClose:
            gotClosed = true
          else:
            discard
        for q in cm.takeOutbox():
          c.sendRaw(q)
    ,
    onError = proc(c: SshClient, msg: string) =
      echo "client err: ", msg
    ,
  )
  for _ in 0 ..< 800:
    if gotClosed and gotStatus == 0:
      break
    loop.poll(25)
  check authed
  check chanOpened
  check gotData == "from-nssh\n"
  check gotStatus == 0
  check gotClosed

  cli.close()
  loop.close()
