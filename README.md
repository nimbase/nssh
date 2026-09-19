<p align="center">
  NSSH &mdash; Pure 👑 Nim SSH client and server<br>
  Built on top of <a href="https://github.com/openpeeps/powpow">PowPow event library</a>
</p>

<p align="center">
  <code>nimble install nssh</code>
</p>

<p align="center">
  <a href="https://nimbase.github.io/nssh">API reference</a><br>
  <img src="https://github.com/nimbase/nssh/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/nimbase/nssh/workflows/docs/badge.svg" alt="Github Actions">
</p>


> [!NOTE]
> Pure Nim SSH-2.0 with no C code and no OpenSSL. Async networking comes
> from [`powpow`](https://github.com/openpeeps/powpow), crypto from
> [`nimcypher`](https://github.com/nimbase/nimcypher). Modern algorithms
> only. **Experimental software!**

## Key Features

- Pure Nim, no C dependencies, no OpenSSL
- Server and client built on top of the PowPow event library, each owning its event loop
- Memory-flat transfers: single-buffer packet crypto, bounded per-channel send stash,<br>
  streaming SFTP uploads and downloads (bench: 64 MB at ~100 MB/s under 4 MB peak RSS)

## What you get

**A complete SSH core.** Handshake, key exchange, encrypted transport,
authentication (`publickey`, `password`, `none`), and session channels
(`exec`, `shell`, `env`, `pty`, window changes, signals, exit status).
Tested against real OpenSSH in both directions.

**Client and server in one package.** `newSshClient` (also called
`dial`) and `newSshServer` each own their event loop. Drive it with
`poll` or `run`, shut it down with `close`. No setup boilerplate.

**An SFTP file server.** Accept the `sftp` subsystem on any channel and
serve files from a sandboxed folder. Access rules work like OpenSSH
`Match` blocks: match on user or group, set a root folder, flip
read-only mode, set the umask, allow or deny specific requests.

**Safe defaults.** Rekeying runs on its own before limits are hit.
Sequence numbers refuse to wrap instead of silently overflowing. Host
keys verify against `known_hosts` (strict or trust-on-first-use).
Unknown message types get proper `UNIMPLEMENTED` replies.

## Supported algorithms

- Key exchange: `curve25519-sha256`, `diffie-hellman-group14-sha256`
- Host keys: `ssh-ed25519`
- Ciphers: `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes256-ctr`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com`
- MACs: `hmac-sha2-256`, `hmac-sha2-512`, ETM variants of both (CTR ciphers; AEAD ciphers need no separate MAC)
- Auth: `none`, `publickey` (`ssh-ed25519`), `password`
- Channels: `session` with `exec`, `shell`, `env`, `pty-req`, `window-change`, `signal`, `subsystem`, data, EOF/close, `exit-status`/`exit-signal`
- SFTP: server, protocol v3 (the version OpenSSH speaks); no client yet
- Compression: `none`

Deliberately missing: legacy ciphers and MACs, RSA/ECDSA host keys,
`keyboard-interactive` auth, forwarding. Modern-only is a design
choice, not a gap.

## Examples

### The SSH server

The skeleton every server builds on: generate a host key, create the
server, track one state machine per connection, and drive the loop.
This one completes the handshake and accepts any key, then logs what
happens. It opens no channels yet.

```nim
import std/tables
import nssh/server
import nssh/auth
import nssh/hostkeys

type Conn = ref object
  auth: AuthServer

var conns = initTable[pointer, Conn]()
let hk = generateEdKey()
var srv: SshServer
srv = newSshServer(hk, "127.0.0.1", 2222,
  onReady = proc(c: ServerConn) =
    echo "new connection"
    conns[cast[pointer](c)] = Conn(
      auth: initAuthServer(c.session.sessionId,
        checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} =
          true))
  ,
  onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
    let app = conns.getOrDefault(cast[pointer](c))
    if app == nil: return
    if m < 80:
      let ev = app.auth.authFeed(p, q)
      if ev.kind == asSuccess:
        echo "authenticated as ", ev.user
      for q2 in app.auth.takeOutbox():
        srv.sendRaw(c, q2)
    else:
      discard # channel traffic: see the next example
  ,
  onClose = proc(c: ServerConn) =
    echo "connection closed"
    conns.del(cast[pointer](c))
)
srv.run()
```

Point system ssh at it (`ssh -p 2222 user@127.0.0.1`, any key works
here) and watch the log: the handshake and authentication complete.
The next example answers channels so commands actually run.

### Run a command over SSH (server side)

Messages below 80 are authentication, the rest are channel traffic.
Feed each packet to the right state machine with its sequence number.

```nim
import std/tables
import nssh/server
import nssh/auth
import nssh/channel
import nssh/hostkeys

type App = ref object
  auth: AuthServer
  mux: ChannelMux

proc toBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  if s.len > 0:
    copyMem(addr result[0], unsafeAddr s[0], s.len)

var apps = initTable[pointer, App]()
let hk = generateEdKey()
var srv: SshServer
srv = newSshServer(hk, "127.0.0.1", 2222,
  onReady = proc(c: ServerConn) =
    apps[cast[pointer](c)] = App(
      auth: initAuthServer(c.session.sessionId,
        checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} =
          true),
      mux: initMux(true))
  ,
  onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
    let app = apps.getOrDefault(cast[pointer](c))
    if app == nil: return
    if m < 80:
      discard app.auth.authFeed(p, q)
      for q2 in app.auth.takeOutbox():
        srv.sendRaw(c, q2)
    else:
      for ev in app.mux.feed(p, q):
        if ev.kind == cevExec:
          discard app.mux.sendData(ev.localId, toBytes("hello\n"))
          app.mux.sendExitStatus(ev.localId, 0)
          app.mux.sendEof(ev.localId)
          app.mux.sendClose(ev.localId)
      for q2 in app.mux.takeOutbox():
        srv.sendRaw(c, q2)
  ,
  onClose = proc(c: ServerConn) =
    apps.del(cast[pointer](c))
)
srv.run()
```

Connect with the system client: `ssh -p 2222 user@127.0.0.1 'echo hi'`.

### Connect as a client

```nim
import nssh/client
import nssh/auth
import nssh/channel
import nssh/hostkeys

proc toString(b: seq[byte]): string =
  result = newString(b.len)
  if b.len > 0:
    copyMem(addr result[0], unsafeAddr b[0], b.len)

let myKey = generateEdKey() # demo key: load your real key here
var authc: AuthClient
var mux = initMux(false)
let cli = newSshClient("127.0.0.1", 2222,
  knownHostsFile = "/home/user/.ssh/known_hosts", # strict by default
  onReady = proc(c: SshClient) =
    authc = initAuthClient("user", c.session.sessionId, myKey)
    authc.authStart()
    for p in authc.takeOutbox():
      c.sendRaw(p)
  ,
  onPacket = proc(c: SshClient, m: byte, p: seq[byte], q: uint32) =
    if m < 80:
      discard authc.authFeed(p, q)
      for q2 in authc.takeOutbox():
        c.sendRaw(q2)
      if authc.done: # authenticated: open a channel, run a command
        discard mux.openSessionChannel()
        for q2 in mux.takeOutbox():
          c.sendRaw(q2)
    else:
      for ev in mux.feed(p, q):
        case ev.kind
        of cevOpened: mux.requestExec(ev.localId, "echo hi")
        of cevData: echo toString(ev.data)
        else: discard
      for q2 in mux.takeOutbox():
        c.sendRaw(q2)
)
cli.run()
```

The client example generates a throwaway key. In real code, load your
key from disk. For tests you can pass `autoTrust = true` instead of a
known-hosts file. Force algorithms with `cipherOffer`, `macOffer`,
`kexOffer` when the peer is picky.

### Serve files over SFTP with per-group rules

```nim
import nssh/server
import nssh/auth
import nssh/channel
import nssh/sftp
import nssh/sftp_match

let resolver = newStaticResolver([
  ("alice", Identity(user: "alice", groups: @["dev"],
                      home: "/home/alice")),
  ("bob", Identity(user: "bob", groups: @["ro"],
                    home: "/home/bob")),
])
# First match wins, like sshd_config Match blocks. No match = decline.
let rules = @[
  MatchRule(users: @["bob"], root: "/srv/sftp/ro/%u", readOnly: true,
    umask: 0o022'u32, startDir: "/"),
  MatchRule(groups: @["dev"], root: "/srv/sftp/dev/%u",
    umask: 0o002'u32, startDir: "/"),
]
# Prefer real accounts? Use systemIdentity(user) as the resolver.
```

How the pieces fit on each connection: `AuthServer` tells you the
username once authentication succeeds. Turn it into an identity with
the resolver (groups included), run it through the rules, and build
a server for the winner with `serverFor`. Anything else, unknown
users and non-sftp subsystems alike, gets a decline. Channel data
then flows through `sftpFeed`, with every response packet sent back
via `sendData`. EOF closes the channel with `sendEof` plus
`sendClose`, as always.

```nim
import std/tables
import nssh/server
import nssh/auth
import nssh/channel
import nssh/hostkeys
import nssh/sftp
import nssh/sftp_match

let resolver = newStaticResolver([
  ("alice", Identity(user: "alice", groups: @["dev"],
                      home: "/home/alice")),
  ("bob", Identity(user: "bob", groups: @["ro"],
                    home: "/home/bob")),
])
let rules = @[
  MatchRule(users: @["bob"], root: "/srv/sftp/ro/%u", readOnly: true,
    umask: 0o022'u32, startDir: "/"),
  MatchRule(groups: @["dev"], root: "/srv/sftp/dev/%u",
    umask: 0o002'u32, startDir: "/"),
]

type SftpApp = ref object
  auth: AuthServer
  mux: ChannelMux
  user: string
  authed: bool
  sfx: SftpServer # valid once the subsystem is accepted
  hasSftp: bool
  sftpCh: uint32

var apps = initTable[pointer, SftpApp]()
let hk = generateEdKey()
var srv: SshServer
srv = newSshServer(hk, "127.0.0.1", 2222,
  onReady = proc(c: ServerConn) =
    apps[cast[pointer](c)] = SftpApp(
      auth: initAuthServer(c.session.sessionId,
        checkKey = proc(u, alg: string, blob: seq[byte]): bool {.closure.} =
          true),
      mux: initMux(true))
  ,
  onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
    let app = apps.getOrDefault(cast[pointer](c))
    if app == nil: return
    if m < 80:
      let ev = app.auth.authFeed(p, q)
      if ev.kind == asSuccess:
        app.user = ev.user
        app.authed = true
      for q2 in app.auth.takeOutbox():
        srv.sendRaw(c, q2)
    else:
      for ev in app.mux.feed(p, q):
        case ev.kind
        of cevSubsystem:
          if ev.text == "sftp" and app.authed:
            try:
              let ident = resolver(app.user)
              app.sfx = serverFor(matchRule(rules, ident), ident)
              app.hasSftp = true
              app.sftpCh = ev.localId
              app.mux.replyChannelRequest(ev.localId, true)
            except SftpError:
              app.mux.replyChannelRequest(ev.localId, false)
          else:
            app.mux.replyChannelRequest(ev.localId, false)
        of cevData:
          if app.hasSftp and ev.localId == app.sftpCh:
            app.sfx.sftpFeed(ev.data)
            for resp in app.sfx.takeSftpOutbox():
              discard app.mux.sendData(app.sftpCh, resp)
        of cevEof:
          if app.hasSftp and ev.localId == app.sftpCh:
            app.mux.sendEof(ev.localId)
            app.mux.sendClose(ev.localId)
        of cevClose:
          app.hasSftp = false
        else:
          discard
      for q2 in app.mux.takeOutbox():
        srv.sendRaw(c, q2)
  ,
  onClose = proc(c: ServerConn) =
    apps.del(cast[pointer](c))
)
srv.run()
```

### Serve a custom filesystem

`SftpBackend` is a base type with one method per SFTP operation.
Override the ones you need and pass the result to `initSftpServer`.
Anything left out answers `OpUnsupported` on its own, and raising
`SftpError` with an `SSH_FX_*` code becomes the client's status
reply. A tiny in-memory read-only filesystem looks like this:

```nim
import std/tables
import nssh/sftp

type
  MemBackend* = ref object of SftpBackend
    files: Table[string, string] # client path -> content
    openDirs: Table[string, seq[string]]

proc memErr(code: uint32, msg: string): ref SftpError =
  var e = newException(SftpError, msg)
  e.code = code
  e

method openFile(b: MemBackend, path: string, pflags: uint32,
    attrs: SftpAttrs): string =
  if path notin b.files:
    raise memErr(FxNoSuchFile, "no such file: " & path)
  if (pflags and (OpenWrite or OpenAppend or OpenCreat or OpenTrunc or
      OpenExcl)) != 0:
    raise memErr(FxPermissionDenied, "read-only backend")
  path # the path doubles as the open handle

method close(b: MemBackend, handle: string) =
  if handle in b.openDirs:
    b.openDirs.del(handle)
  elif handle notin b.files:
    raise memErr(FxFailure, "unknown handle")

method read(b: MemBackend, handle: string, offset: uint64,
    len: uint32): seq[byte] =
  if handle notin b.files:
    raise memErr(FxFailure, "unknown handle")
  let content = b.files[handle]
  if offset >= uint64(content.len):
    raise memErr(FxEof, "end of file")
  let n = min(uint64(len), uint64(content.len) - offset)
  result = newSeq[byte](n)
  for i in 0 ..< int(n):
    result[i] = byte(content[int(offset) + i])

method stat(b: MemBackend, path: string): SftpAttrs =
  if path == "/":
    return fullAttrs(0, 0, 0, 0o040755'u32, 0, 0)
  if path notin b.files:
    raise memErr(FxNoSuchFile, "no such file: " & path)
  fullAttrs(uint64(b.files[path].len), 0, 0, 0o100644'u32, 0, 0)

method lstat(b: MemBackend, path: string): SftpAttrs =
  b.stat(path)

method opendir(b: MemBackend, path: string): string =
  if path != "/":
    raise memErr(FxNoSuchFile, "no such directory: " & path)
  result = "dir" & $b.openDirs.len
  var names: seq[string] = @[]
  for k in b.files.keys:
    names.add(k[1 ..^ 1]) # strip the leading slash for display
  b.openDirs[result] = names

method readdir(b: MemBackend, handle: string): seq[SftpName] =
  if handle notin b.openDirs:
    raise memErr(FxFailure, "unknown handle")
  let names = b.openDirs[handle]
  b.openDirs.del(handle) # one-shot listing: the next call reports EOF
  if names.len == 0:
    raise memErr(FxEof, "empty directory")
  for n in names:
    let a = fullAttrs(uint64(b.files["/" & n].len), 0, 0,
      0o100644'u32, 0, 0)
    result.add(SftpName(filename: n, longname: formatLongname(n, a),
      attrs: a))

method realpath(b: MemBackend, path: string): string =
  if path == "/" or path in b.files:
    return path
  raise memErr(FxNoSuchFile, "no such file: " & path)

let mem = MemBackend(files: {"/hello.txt": "hi\n"}.toTable(),
  openDirs: initTable[string, seq[string]]())
var sfx = initSftpServer(mem)
# then feed channel data: sfx.sftpFeed(data), sendData each response
```

The bundled `OsBackend` serves a local folder (escapes rejected),
`ReadOnlyBackend` wraps any backend, and `denyTypes` blocks specific
requests (the `sftp-server -P` equivalent).

### Things that bite

1. **Subsystem requests need an explicit answer.** Nothing is
   auto-accepted: every `cevSubsystem` must get a
   `replyChannelRequest(id, ok)`, or the client hangs.
2. **EOF needs an answer too.** OpenSSH closes channels with a
   handshake (RFC 4254 section 5.3): it sends EOF and waits for our
   EOF plus CLOSE before sending its own CLOSE. Answer `cevEof` with
   `sendEof` + `sendClose`.
3. **Bulk senders pace on `cevWindowAdjust`.** `sendData` accepts
   everything at once: what fits the peer window frames immediately,
   the rest waits in a per-channel stash and flushes on the next
   adjust. The stash is capped (`MaxPendingSend`, 4 MB) and raises
   instead of growing forever, so if you stream bulk data, watch for
   `cevWindowAdjust` (its `status` is the granted bytes) and slow
   down. Drain before EOF: `sendEof` flushes best-effort, but bytes
   still stashed behind a shut window would land after it.

## Testing

```sh
clue test
```

15 suites cover handshake, ciphers, auth, channels, rekeying,
keepalive, SFTP, and Match rules. `tests/test_interop.nim` additionally
runs system `ssh` against our server, our client against system `sshd`,
and system `sftp` against our SFTP server. Interop tests skip
gracefully when OpenSSH is missing. `examples/sftp_loopback.nim` and
`examples/exec_loopback.nim` run full sessions offline with no sockets.

## Roadmap

### Transport and crypto

- [x] Binary packet protocol: version exchange, framing, padding, limits
- [x] Key exchange: curve25519-sha256, diffie-hellman-group14-sha256
- [x] Ciphers: chacha20-poly1305, AES-CTR (128/256), AES-GCM (128/256)
- [x] MACs: hmac-sha2-256/512 plus ETM variants
- [x] Host keys: ssh-ed25519 (generate, sign, verify, authorized_keys, fingerprints)
- [x] Independent C2S/S2C cipher and MAC negotiation (RFC 4253 section 7.1)
- [x] OpenSSH framing fixes: ETM clear-length CTR packets, GCM nonce from the full KEX IV
- [ ] More key exchange: groups 15-18, DH-GEX, ecdh-nistp, strict-kex (Terrapin mitigation)
- [ ] More host keys: ECDSA, RSA-SHA2
- [ ] server-sig-algs extension
- [ ] Opt-in compression through nim-zlib (including delayed zlib@openssh.com)

### Session and auth

- [x] Session state machine: handshake, NEWKEYS, encrypted transport, disconnect
- [x] Auth methods none, publickey (ed25519), and password, client and server
- [x] Known-hosts verification with strict and trust-on-first-use modes
- [x] Transparent RFC 4253 rekeying with automatic triggers (1 GB / 1M packets / 3600 s)
- [x] Opt-in keepalive IGNORE timer plus idle timeout
- [x] Sequence numbers raise instead of wrapping
- [ ] keyboard-interactive authentication
- [ ] OpenSSH certificates

### Channels

- [x] Session channels: open, exec, shell, env, pty-req, data, EOF/close, exit status and exit signal
- [x] window-change and signal events plus senders
- [x] Explicit subsystem authorization (no auto-accept, the app replies)
- [ ] TCP forwarding (direct-tcpip, forwarded-tcpip)
- [ ] Agent forwarding

### SFTP

- [x] SFTP v3 server with the full file, dir, status, rename, and symlink op set
- [x] Pluggable SftpBackend plus sandboxed OsBackend and ReadOnlyBackend
- [x] User and group Match rules with root expansion, read-only flag, and umask
- [x] ATTRS responses carry full st_mode type bits (OpenSSH interop fix)
- [x] EOF half-close handshake answered (RFC 4254 section 5.3)
- [ ] SFTP v4 to v6 as negotiated deltas
- [ ] OpenSSH extensions: posix-rename, statvfs, hardlink, fsync, lsetstat, limits, home-directory

### Wiring, tests, and releases

- [x] Client and server with owned event loops (poll/run/close)
- [x] Typed algorithm offers with forcing for constrained peers and tests
- [x] 15 test suites covering handshake, ciphers, auth, channels, rekeying, keepalive, SFTP, and Match rules
- [x] OpenSSH interop both ways: system ssh against our server, our client against sshd, system sftp against our server
- [x] Offline loopback examples for exec and sftp (no sockets), plus an SFTP throughput bench
- [x] README with working examples, CHANGELOG, LICENSE
- [x] Memory-flat bulk transfer: bounded send stash, window re-grant, single-buffer CTR crypto, SFTP throughput bench
- [ ] GCM/chacha single-buffer pass (needs allocator-aware nimcypher APIs)
- [ ] Throughput benchmarks across all ciphers
- [ ] CI running the full suite
- [ ] 0.2.0 release

Legacy algorithms (CBC, 3DES, SHA-1 MACs) stay out on purpose.

### References
- https://www.sftp.net/specification
- https://datatracker.ietf.org/doc/html/draft-ietf-secsh-filexfer-02

### 🎩 License
MIT license
