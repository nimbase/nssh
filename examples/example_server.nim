## Showcase server: virtual-user auth, exec/shell channels, and the SFTP
## subsystem rooted at ./tests/root_data with per-user Match rules.
##
## Every callback is a named top-level proc so the flow reads top to bottom:
## state, auth, channel routing, filesystem, then the wiring in main.
##
## Build and run from the package root:
##   clue build examples/example_server.nim
##   ./examples/example_server
##
## Log in as alice (password: alicepw, read-write) or bob (password: bobpw,
## read-only). Any ed25519 key is accepted for a known user; unknown users
## are rejected. Demo credentials only, never do this in production.

import std/os
import std/tables

import ../src/nssh/server
import ../src/nssh/auth
import ../src/nssh/channel
import ../src/nssh/sftp
import ../src/nssh/sftp_match
import ../src/nssh/hostkeys

const
  ListenAddr = "127.0.0.1"
  ListenPort = 2222

type Conn = ref object
  auth: AuthServer
  mux: ChannelMux
  user: string
  authed: bool
  sfx: SftpServer # valid once the sftp subsystem is accepted
  hasSftp: bool
  sftpCh: uint32

# ── server state ──────────────────────────────────────────────────────────────

var conns = initTable[pointer, Conn]()
var srv: SshServer # assigned in main; handlers use it to reply
var rules: seq[MatchRule] # built in main once the root dir is known

# ── virtual users ─────────────────────────────────────────────────────────────

let demoPasswords = {"alice": "alicepw", "bob": "bobpw"}.toTable()

let resolver = newStaticResolver([
  ("alice", Identity(user: "alice", groups: @["dev"],
                     home: "/home/alice")),
  ("bob", Identity(user: "bob", groups: @["ro"],
                   home: "/home/bob")),
])

proc checkUserPassword(user, password: string): bool =
  ## Demo password check: table lookup. Production code wants salted hashes
  ## compared in constant time, not cleartext.
  password.len > 0 and demoPasswords.getOrDefault(user) == password

proc checkUserKey(user, alg: string, blob: seq[byte]): bool =
  ## Demo publickey check: any well-formed ed25519 key for a known user.
  ## Production code compares against that user's authorized_keys entries.
  if user notin demoPasswords:
    echo "publickey attempt for unknown user: ", user
    return false
  try:
    echo "publickey attempt for ", user, " key ",
      fingerprintSha256(parsePubBlob(blob))
  except CatchableError:
    return false
  result = true

# ── filesystem root ───────────────────────────────────────────────────────────

let rootBase = parentDir(parentDir(currentSourcePath())) / "tests" /
  "root_data"

proc ensureRootData() =
  ## Create the served root next to the tests and seed a welcome file.
  createDir(rootBase)
  let welcome = rootBase / "welcome.txt"
  if not fileExists(welcome):
    writeFile(welcome, "hello from the nssh example server\n")

# ── auth ──────────────────────────────────────────────────────────────────────

proc handleReady(c: ServerConn) =
  echo "new connection"
  conns[cast[pointer](c)] = Conn(
    auth: initAuthServer(c.session.sessionId,
      checkKey = checkUserKey, checkPassword = checkUserPassword),
    mux: initMux(true))

proc handleAuth(c: ServerConn, app: Conn, p: seq[byte], q: uint32) =
  let ev = app.auth.authFeed(p, q)
  if ev.kind == asSuccess:
    app.user = ev.user
    app.authed = true
    echo "authenticated as ", ev.user, " via ", ev.meth
  for q2 in app.auth.takeOutbox():
    srv.sendRaw(c, q2)

# ── channels ──────────────────────────────────────────────────────────────────

proc strToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, ch in s:
    result[i] = byte(ch)

proc answerExec(app: Conn, chId: uint32, cmd: string) =
  ## Canned exec: echo the command, exit 0. This demo server never runs
  ## client-supplied commands.
  echo "exec: ", cmd
  discard app.mux.sendData(chId, strToBytes("you ran: " & cmd & "\n"))
  app.mux.sendExitStatus(chId, 0)
  app.mux.sendEof(chId)
  app.mux.sendClose(chId)

proc answerShell(app: Conn, chId: uint32) =
  echo "shell requested"
  discard app.mux.sendData(chId, strToBytes(
    "nssh example shell (no real shell here)\n"))
  app.mux.sendExitStatus(chId, 0)
  app.mux.sendEof(chId)
  app.mux.sendClose(chId)

proc authorizeSftp(c: ServerConn, app: Conn, chId: uint32) =
  ## Accept the sftp subsystem with the backend of the authenticated user's
  ## first matching rule; decline anything else (unknown subsystem,
  ## unauthenticated user, no matching rule).
  if not app.authed:
    app.mux.replyChannelRequest(chId, false)
    return
  try:
    let ident = resolver(app.user)
    app.sfx = serverFor(matchRule(rules, ident), ident)
    app.hasSftp = true
    app.sftpCh = chId
    app.mux.replyChannelRequest(chId, true)
    echo "sftp subsystem accepted for ", app.user
  except SftpError as e:
    echo "sftp subsystem declined for ", app.user, ": ", e.msg
    app.mux.replyChannelRequest(chId, false)

proc handleChannel(c: ServerConn, app: Conn, p: seq[byte], q: uint32) =
  for ev in app.mux.feed(p, q):
    case ev.kind
    of cevOpened:
      echo "channel opened"
    of cevExec:
      answerExec(app, ev.localId, ev.text)
    of cevShell:
      answerShell(app, ev.localId)
    of cevEnv:
      # Auto-answered by the mux; just log it.
      echo "env: ", ev.text, "=", ev.text2
    of cevPty:
      # Auto-answered by the mux; just log it.
      echo "pty: ", ev.text
    of cevSubsystem:
      if ev.text == "sftp":
        authorizeSftp(c, app, ev.localId)
      else:
        echo "unknown subsystem declined: ", ev.text
        app.mux.replyChannelRequest(ev.localId, false)
    of cevData:
      if app.hasSftp and ev.localId == app.sftpCh:
        app.sfx.sftpFeed(ev.data)
        for resp in app.sfx.takeSftpOutbox():
          discard app.mux.sendData(app.sftpCh, resp)
    of cevEof:
      # Half-close handshake (RFC 4254 section 5.3): answer EOF with
      # our EOF plus CLOSE.
      if app.hasSftp and ev.localId == app.sftpCh:
        app.mux.sendEof(ev.localId)
        app.mux.sendClose(ev.localId)
    of cevClose:
      app.hasSftp = false
      echo "channel closed"
    else:
      discard
  for q2 in app.mux.takeOutbox():
    srv.sendRaw(c, q2)

# ── packet routing and connection lifecycle ───────────────────────────────────

proc handlePacket(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
  let app = conns.getOrDefault(cast[pointer](c))
  if app == nil:
    return
  if m < 80:
    handleAuth(c, app, p, q)
  else:
    handleChannel(c, app, p, q)

proc handleClose(c: ServerConn) =
  echo "connection closed"
  conns.del(cast[pointer](c))

proc handleError(c: ServerConn, msg: string) =
  echo "connection error: ", msg

proc handleDisconnect(c: ServerConn, msg: string) =
  echo "peer disconnected: ", msg

proc handleRekey(c: ServerConn) =
  echo "rekey completed"

# ── main ──────────────────────────────────────────────────────────────────────

ensureRootData()
rules = @[
  MatchRule(users: @["bob"], root: rootBase, readOnly: true,
    umask: 0o022'u32, startDir: "/"),
  MatchRule(users: @["alice"], root: rootBase, readOnly: false,
    umask: 0o022'u32, startDir: "/"),
]

srv = newSshServer(generateEdKey(), ListenAddr, ListenPort,
  onReady = handleReady,
  onPacket = handlePacket,
  onClose = handleClose,
  onError = handleError,
  onDisconnect = handleDisconnect,
  onRekey = handleRekey,
  rekeyPolicy = defaultRekeyPolicy(),
  keepaliveIntervalMs = 30_000,
  idleTimeoutMs = 600_000)

echo "serving ", rootBase, " on ", ListenAddr, ":", ListenPort,
  " (alice: read-write, bob: read-only)"
srv.run()
