<p align="center">
  NSSH - Pure Nim SSH client and server<br>
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
<<<<<<< HEAD
> Pure Nim SSH-2.0 with no C code and no OpenSSL. Async networking comes
> from [`powpow`](https://github.com/openpeeps/powpow), crypto from
> [`nimcypher`](https://github.com/nimbase/nimcypher). Modern algorithms
> only. **Experimental software!**
=======
> This is a modern-only SSH-2.0 client and server in strict pure Nim (no C, no OpenSSL).
> Async TCP comes from [`powpow`](https://github.com/openpeeps/powpow), crypto from [`nimcypher`](https://github.com/nimbase/nimcypher).
>>>>>>> 9ece0fcb9bfc225871de06aadd4ade31fb613ea0

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

| Area | Supported |
|---------|-----------|
| Key exchange | `curve25519-sha256`, `diffie-hellman-group14-sha256` |
| Host keys | `ssh-ed25519` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes256-ctr`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` |
| MACs | `hmac-sha2-256`, `hmac-sha2-512`, ETM variants of both (CTR ciphers; AEAD ciphers need no separate MAC) |
| Auth | `none`, `publickey` (`ssh-ed25519`), `password` |
| Channels | `session` with `exec`, `shell`, `env`, `pty-req`, `window-change`, `signal`, `subsystem`, data, EOF/close, `exit-status`/`exit-signal` |
| SFTP | server, protocol v3 (the version OpenSSH speaks); no client yet |
| Compression | `none` |

Deliberately missing: legacy ciphers and MACs, RSA/ECDSA host keys,
`keyboard-interactive` auth, forwarding. Modern-only is a design
choice, not a gap.

## Install

Requires Nim >= 2.2.10 (see `nssh.nimble` for the rest):

```sh
nimble install nssh
```

## Examples

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

# Sketch of the per-connection wiring (full pump lives in
# examples/sftp_loopback.nim). After AuthServer reports success as `user`:
#   on cevSubsystem("sftp"):
#     try:
#       app.sftp = serverFor(matchRule(rules, resolver(user)))
#       app.mux.replyChannelRequest(ev.localId, true)
#     except SftpError:
#       app.mux.replyChannelRequest(ev.localId, false)
#   on cevData: app.sftp.sftpFeed(ev.data)
#     then sendData each packet from app.sftp.takeSftpOutbox()
#   on cevEof: sendEof + sendClose (see below)
```

Want a different filesystem? Implement the `SftpBackend` methods and
pass it to `initSftpServer`. The bundled `OsBackend` serves a local
folder (escapes rejected), `ReadOnlyBackend` wraps any backend, and
`denyTypes` blocks specific requests (the `sftp-server -P` equivalent).

### Two things that bite

1. **Subsystem requests need an explicit answer.** Nothing is
   auto-accepted: every `cevSubsystem` must get a
   `replyChannelRequest(id, ok)`, or the client hangs.
2. **EOF needs an answer too.** OpenSSH closes channels with a
   handshake (RFC 4254 section 5.3): it sends EOF and waits for our
   EOF plus CLOSE before sending its own CLOSE. Answer `cevEof` with
   `sendEof` + `sendClose`.

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

**Shipped.** SSH transport, auth, and channels. Transparent rekeying,
keepalive, known-hosts verification. SFTP v3 server with user/group
Match rules. OpenSSH interop both ways.

**Next.**
- SFTP v4 to v6 plus OpenSSH extensions (`posix-rename`, `statvfs`,
  `hardlink`, `fsync`, `lsetstat`, `limits`, `home-directory`)
- Opt-in compression through nim-zlib (including delayed
  `zlib@openssh.com`)
- More key exchange methods and host key types as interop needs them
- CI running the full suite, then a 0.2.0 release

**Later.**
- TCP and agent forwarding
- `keyboard-interactive` authentication

Legacy algorithms stay out on purpose.

### 🎩 License
MIT license
