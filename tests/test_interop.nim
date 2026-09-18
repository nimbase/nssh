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
import nssh/ciphers
import nssh/auth
import nssh/channel
import nssh/codec
import nssh/sftp

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
                 msgType: byte, payload: seq[byte], seqno: uint32) =
  if msgType < 80:
    let ev = app.auth.authFeed(payload, seqno)
    if ev.kind == asSuccess:
      discard
    for p in app.auth.takeOutbox():
      srv.sendRaw(c, p)
  else:
    for ev in app.mux.feed(payload, seqno):
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

proc sanitize(s: string): string =
  for ch in s:
    case ch
    of 'a'..'z', 'A'..'Z', '0'..'9', '-', '_': result.add(ch)
    else: result.add('_')

proc runSshExecOnOurServer(kexAlgo, cipher: string, mac = ""): bool =
  ## Full `ssh` exec round trip against our server with forced algorithms.
  ## Returns true only when exec observed, exit 0, and stdout matches.
  ## Must be wrapped in `check` at the call site: `check` inside a helper
  ## proc does not fail the suite (vacuous OKs).
  let tag = sanitize(kexAlgo) & "-" & sanitize(cipher) &
    (if mac.len > 0: "-" & sanitize(mac) else: "") &
    "-" & $getCurrentProcessId()
  let tmp = getTempDir() / ("nssh-interop-a-" & tag)
  createDir(tmp)
  defer: removeDir(tmp)
  let keyPath = tmp / "id_ed"
  doAssert execShellCmd("ssh-keygen -q -t ed25519 -N '' -f " & keyPath) == 0

  let port = freePort()
  let hk = generateEdKey()
  var apps = initTable[pointer, SrvApp]()
  var sawExec = ""
  var srv: SshServer
  srv = newSshServer(hk, "127.0.0.1", port,
    kexOffer = @[kexAlgo],
    onReady = proc(c: ServerConn) =
      apps[cast[pointer](c)] = SrvApp(
        auth: initAuthServer(c.session.sessionId,
          checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} = true),
        mux: initMux(true))
    ,
    onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
      let app = apps.getOrDefault(cast[pointer](c))
      if app != nil:
        routeSrvApp(srv, c, app, m, p, q)
        if app.hasExec:
          sawExec = app.execCmd
    ,
    onClose = proc(c: ServerConn) =
      apps.del(cast[pointer](c))
    ,
  )

  var sshArgs = @["-p", $port, "-i", keyPath,
             "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=10",
             "-o", "LogLevel=ERROR",
             "-o", "KexAlgorithms=" & kexAlgo,
             "-o", "Ciphers=" & cipher]
  if mac.len > 0:
    sshArgs.add(["-o", "MACs=" & mac])
  sshArgs.add(["interop@localhost", "echo hello-interop"])
  var sshOut = ""
  var sshErr = ""
  var sshCode = -1
  try:
    let sshProc = startProcess("ssh", args = sshArgs, options = {poUsePath})
    for _ in 0 ..< 1200:
      srv.poll(25)
      sshCode = sshProc.peekExitCode()
      if sshCode != -1:
        break
    if sshCode == -1:
      sshProc.kill()
      srv.poll(50)
    sshOut = sshProc.outputStream().readAll()
    try:
      sshErr = sshProc.errorStream().readAll()
    except ValueError:
      discard
    sshCode = sshProc.peekExitCode()
    sshProc.close()
    result = sawExec == "echo hello-interop" and sshCode == 0 and sshOut == "ok\n"
    if not result:
      echo "INTEROP DIAG kex=", kexAlgo, " cipher=", cipher, " mac=", mac,
        " code=", sshCode, " out=", repr(sshOut), " err=", repr(sshErr)
  finally:
    srv.close()

test "A: openssh client runs exec on our server":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  check runSshExecOnOurServer("curve25519-sha256", "chacha20-poly1305@openssh.com")

test "A2: openssh client runs exec on our server via group14-sha256":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  check runSshExecOnOurServer("diffie-hellman-group14-sha256", "aes128-ctr")

test "A3: cipher matrix (aes256-ctr, gcm, etm)":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  check runSshExecOnOurServer("curve25519-sha256", "aes256-ctr")
  check runSshExecOnOurServer("curve25519-sha256", "aes128-ctr",
    "hmac-sha2-256-etm@openssh.com")
  check runSshExecOnOurServer("curve25519-sha256", "aes128-gcm@openssh.com")
  check runSshExecOnOurServer("curve25519-sha256", "aes256-gcm@openssh.com")

test "A4: group14 with gcm and etm":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  check runSshExecOnOurServer("diffie-hellman-group14-sha256",
    "aes128-gcm@openssh.com")
  check runSshExecOnOurServer("diffie-hellman-group14-sha256",
    "aes256-gcm@openssh.com")
  check runSshExecOnOurServer("diffie-hellman-group14-sha256", "aes128-ctr",
    "hmac-sha2-256-etm@openssh.com")

test "A5: hmac-sha2-512 family and non-etm hmac-sha2-256":
  if not (haveTool("ssh") and haveTool("ssh-keygen")):
    skip()
  check runSshExecOnOurServer("curve25519-sha256", "aes256-ctr",
    "hmac-sha2-512-etm@openssh.com")
  check runSshExecOnOurServer("curve25519-sha256", "aes256-ctr",
    "hmac-sha2-512")
  check runSshExecOnOurServer("curve25519-sha256", "aes128-ctr",
    "hmac-sha2-256")

proc runOurClientOnSshd(kexAlgo, cipher: string, mac = ""): bool =
  ## Our client runs a remote exec against system `sshd` with forced
  ## algorithms. Returns true only on auth + exec output + status 0 + close.
  ## Must be wrapped in `check` at the call site.
  let tag = "b-" & sanitize(kexAlgo) & "-" & sanitize(cipher) &
    (if mac.len > 0: "-" & sanitize(mac) else: "") &
    "-" & $getCurrentProcessId()
  let tmp = getTempDir() / ("nssh-interop-" & tag)
  createDir(tmp)
  setFilePermissions(tmp, {fpUserExec, fpUserWrite, fpUserRead})
  defer: removeDir(tmp)
  let hostKeyPath = tmp / "host_ed"
  doAssert execShellCmd("ssh-keygen -q -t ed25519 -N '' -f " & hostKeyPath) == 0
  # user key generated in-process; authorized via our own encoder
  let userKey = generateEdKey()
  writeFile(tmp / "authorized_keys", encodeAuthorizedKeysLine(userKey.pubkey) & "\n")
  setFilePermissions(tmp / "authorized_keys",
    {fpUserWrite, fpUserRead})
  let cfgPath = tmp / "sshd_config"
  let port = freePort()
  var cfg =
    "Port " & $port & "\n" &
    "ListenAddress 127.0.0.1\n" &
    "HostKey " & hostKeyPath & "\n" &
    "PidFile " & tmp / "sshd.pid" & "\n" &
    "AuthorizedKeysFile " & tmp / "authorized_keys" & "\n" &
    "PasswordAuthentication no\n" &
    "PubkeyAuthentication yes\n" &
    "ChallengeResponseAuthentication no\n" &
    "UsePAM no\n" &
    "HostKeyAlgorithms ssh-ed25519\n" &
    "PubkeyAcceptedAlgorithms ssh-ed25519\n"
  # Pin the algorithms under test so negotiation cannot drift.
  if kexAlgo.len > 0:
    cfg.add("KexAlgorithms " & kexAlgo & "\n")
  if cipher.len > 0:
    cfg.add("Ciphers " & cipher & "\n")
  if mac.len > 0:
    cfg.add("MACs " & mac & "\n")
  writeFile(cfgPath, cfg)
  let logPath = tmp / "sshd.log"
  let sshdBin = findExe("sshd")
  doAssert sshdBin != ""
  let sshdProc = startProcess(sshdBin,
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
  var dialKex: seq[string] = @[]
  var dialCipher: seq[CipherKind] = @[]
  var dialMac: seq[MacKind] = @[]
  if kexAlgo.len > 0:
    dialKex = @[kexAlgo]
  if cipher.len > 0:
    dialCipher = @[parseCipherKind(cipher)]
  if mac.len > 0:
    dialMac = @[parseMacKind(mac)]
  cli = dial("127.0.0.1", port, autoTrust = true,
    onReady = proc(c: SshClient) =
      ca = initAuthClient(user, c.session.sessionId, userKey)
      ca.authStart()
      for p in ca.takeOutbox():
        c.sendRaw(p)
    ,
    onPacket = proc(c: SshClient, m: byte, p: seq[byte], q: uint32) =
      if m < 80 and not authDone:
        let ev = ca.authFeed(p, q)
        for q in ca.takeOutbox():
          c.sendRaw(q)
        if ev.kind == acSuccess:
          authDone = true
          authed = true
          chId = cm.openSessionChannel()
          for q in cm.takeOutbox():
            c.sendRaw(q)
      elif m >= 90:
        for ev in cm.feed(p, q):
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
    kexOffer = dialKex,
    cipherOffer = dialCipher,
    macOffer = dialMac,
  )
  try:
    for _ in 0 ..< 800:
      if gotClosed and gotStatus == 0:
        break
      cli.poll(25)
  finally:
    cli.close()
  result = authed and chanOpened and gotData == "from-nssh\n" and
    gotStatus == 0 and gotClosed
  if not result:
    echo "INTEROP DIAG client kex=", kexAlgo, " cipher=", cipher, " mac=", mac,
      " authed=", authed, " chan=", chanOpened, " data=", repr(gotData),
      " status=", gotStatus, " closed=", gotClosed

test "B: our client runs exec on system sshd":
  if not (haveTool("sshd") and haveTool("ssh-keygen")):
    skip()
  check runOurClientOnSshd("", "", "")

test "B2: our client with forced algorithms":
  if not (haveTool("sshd") and haveTool("ssh-keygen")):
    skip()
  check runOurClientOnSshd("curve25519-sha256",
    "chacha20-poly1305@openssh.com")
  check runOurClientOnSshd("curve25519-sha256", "aes128-ctr",
    "hmac-sha2-256-etm@openssh.com")
  check runOurClientOnSshd("curve25519-sha256", "aes128-gcm@openssh.com")
  check runOurClientOnSshd("diffie-hellman-group14-sha256", "aes256-ctr",
    "hmac-sha2-512")

# ── C: system sftp client against OUR server ──────────────────────────────────

type
  SftpSrvApp = ref object
    auth: AuthServer
    mux: ChannelMux
    sftp: SftpServer
    hasSftp: bool
    sftpCh: uint32

proc routeSftpSrvApp(srv: SshServer, c: ServerConn, app: SftpSrvApp,
                     msgType: byte, payload: seq[byte], seqno: uint32) =
  if msgType < 80:
    discard app.auth.authFeed(payload, seqno)
    for p in app.auth.takeOutbox():
      srv.sendRaw(c, p)
  else:
    for ev in app.mux.feed(payload, seqno):
      case ev.kind
      of cevSubsystem:
        if ev.text == "sftp":
          app.hasSftp = true
          app.sftpCh = ev.localId
          app.mux.replyChannelRequest(ev.localId, true)
        else:
          app.mux.replyChannelRequest(ev.localId, false)
      of cevData:
        if app.hasSftp and ev.localId == app.sftpCh:
          app.sftp.sftpFeed(ev.data)
          for resp in app.sftp.takeSftpOutbox():
            discard app.mux.sendData(app.sftpCh, resp)
      of cevEof:
        # Half-close handshake (RFC 4254 §5.3): client sent EOF and
        # waits for our EOF+CLOSE before sending its CLOSE.
        if app.hasSftp and ev.localId == app.sftpCh:
          app.mux.sendEof(ev.localId)
          app.mux.sendClose(ev.localId)
      of cevClose:
        app.hasSftp = false
      else:
        discard
    for p in app.mux.takeOutbox():
      srv.sendRaw(c, p)

proc runSftpOnOurServer(): bool =
  ## System `sftp` batch session against our SFTP subsystem. Returns
  ## true on clean put/get/rename/remove/mkdir/rmdir round trip.
  let tag = "sftp-" & $getCurrentProcessId()
  let tmp = getTempDir() / ("nssh-interop-c-" & tag)
  createDir(tmp)
  defer: removeDir(tmp)
  let keyPath = tmp / "id_ed"
  doAssert execShellCmd("ssh-keygen -q -t ed25519 -N '' -f " & keyPath) == 0
  let srvRoot = tmp / "srv"
  createDir(srvRoot)
  writeFile(tmp / "local.txt", "sftp-interop-payload\n")
  writeFile(tmp / "batch",
    "put local.txt up.txt\nls\nrename up.txt down.txt\n" &
    "get down.txt got.txt\nrm down.txt\nmkdir subdir\nrmdir subdir\n")

  let port = freePort()
  let hk = generateEdKey()
  var apps = initTable[pointer, SftpSrvApp]()
  var srv: SshServer
  srv = newSshServer(hk, "127.0.0.1", port,
    onReady = proc(c: ServerConn) =
      apps[cast[pointer](c)] = SftpSrvApp(
        auth: initAuthServer(c.session.sessionId,
          checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} = true),
        mux: initMux(true),
        sftp: initSftpServer(newOsBackend(srvRoot)))
    ,
    onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
      let app = apps.getOrDefault(cast[pointer](c))
      if app != nil:
        routeSftpSrvApp(srv, c, app, m, p, q)
    ,
    onClose = proc(c: ServerConn) =
      apps.del(cast[pointer](c))
    ,
  )
  let sftpArgs = @["-P", $port, "-i", keyPath,
             "-o", "BatchMode=yes",
             "-o", "StrictHostKeyChecking=no",
             "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=10",
             "-o", "LogLevel=ERROR",
             "-b", tmp / "batch",
             "interop@127.0.0.1"]
  var sftpCode = -1
  var sftpOut = ""
  try:
    let sftpProc = startProcess("sftp", args = sftpArgs,
      workingDir = tmp, options = {poUsePath})
    for _ in 0 ..< 1200:
      srv.poll(25)
      sftpCode = sftpProc.peekExitCode()
      if sftpCode != -1:
        break
    if sftpCode == -1:
      sftpProc.kill()
      srv.poll(50)
    sftpOut = sftpProc.outputStream().readAll()
    sftpCode = sftpProc.peekExitCode()
    sftpProc.close()
    let gotOk = fileExists(tmp / "got.txt") and
      readFile(tmp / "got.txt") == "sftp-interop-payload\n"
    result = sftpCode == 0 and gotOk and not fileExists(srvRoot / "down.txt")
    if not result:
      echo "INTEROP DIAG sftp code=", sftpCode, " out=", repr(sftpOut)
  finally:
    srv.close()

test "C: openssh sftp client round trips on our server":
  if not (haveTool("sftp") and haveTool("ssh-keygen")):
    skip()
  check runSftpOnOurServer()
