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


This is a modern-only SSH-2.0 client and server in strict pure Nim (no C, no OpenSSL). Async TCP comes from [`powpow`](https://github.com/openpeeps/powpow), crypto from [`nimcypher`](https://github.com/nimbase/nimcypher).

## Key Features
- Pure Nim SSH-2.0 with no C dependencies and no OpenSSL: crypto from
  nimcypher, async TCP from powpow
- Modern-only algorithms: `curve25519-sha256` and group14 key exchange,
  `ssh-ed25519` host keys, `chacha20-poly1305`, AES-CTR and AES-GCM
  ciphers, HMAC-SHA2 MACs including ETM variants
- Client (`newSshClient`, alias `dial`) and server (`newSshServer`),
  each owning its event loop with `poll`/`run` drivers and one-call
  `close`
- Typed algorithm offers (`seq[CipherKind]`, `seq[MacKind]`) with
  optional kex/cipher/mac forcing for testing and constrained peers
- Client and server authentication: `publickey` (`ssh-ed25519`),
  `password`, `none`
- Session channels with `exec`, `shell`, `env`, `pty-req`, data
  streaming, EOF/close exchange, and `exit-status` reporting
- OpenSSH-compatible framing: ETM clear-length packets, GCM nonce
  from the full KEX IV, correct CTR counter semantics
- Protocol hygiene: `UNIMPLEMENTED` replies carrying the packet
  sequence number, `IGNORE`/`DEBUG` keepalives swallowed mid-auth,
  rekey refused with a reasoned `DISCONNECT`, sequence numbers that
  raise instead of wrapping, capped reassembly buffers
- Interop tested against system OpenSSH in both directions across a
  KEX x cipher x MAC matrix (`tests/test_interop.nim`)

## Algorithm support (modern-only MVP)

| Area    | Supported |
|---------|-----------|
| KEX     | `curve25519-sha256`, `diffie-hellman-group14-sha256` |
| Hostkey | `ssh-ed25519` |
| Ciphers | `chacha20-poly1305@openssh.com`, `aes128-ctr`, `aes256-ctr`, `aes128-gcm@openssh.com`, `aes256-gcm@openssh.com` |
| MACs    | `hmac-sha2-256`, `hmac-sha2-512`, `hmac-sha2-256-etm@openssh.com`, `hmac-sha2-512-etm@openssh.com` (CTR ciphers; AEAD ciphers use no separate MAC) |
| Auth    | `none`, `publickey` (`ssh-ed25519`), `password` |
| Channels | `session` with `exec`, `shell`, `env`, `pty-req`, data/eof/close, `exit-status` |
| Compression | `none` |

Deliberately out of scope: `keyboard-interactive`, `subsystem`/sftp,
RSA/ECDSA/SK hostkeys, CBC/3DES/AES-192 ciphers, SHA-1/UMAC MACs,
compression, CA certificates.

## Limits

- **No rekeying.** A peer KEXINIT after the initial exchange is refused
  with `SSH_DISCONNECT_KEY_EXCHANGE_FAILED`. Sequence numbers raise
  instead of wrapping at 2^32 (rekey before that).
- **Symmetric negotiation only.** Client-to-server and server-to-client
  cipher/MAC must match; asymmetric offers are rejected.

## Install

Requires Nim >= 2.2.10 (see `nssh.nimble` for the rest):

```sh
nimble install nssh
```

## Usage

```nim
import nssh/client
import nssh/server
import nssh/hostkeys

# Server: the loop is owned internally; drive it with srv.poll/run.
let hk = generateEdKey()
let srv = newSshServer(hk, "127.0.0.1", 2222,
  onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
    discard # feed p to AuthServer (< 80) or ChannelMux (>= 90) with seqno q
)
srv.poll() # or srv.run() to block

# Client: likewise owns its loop (`dial` is an alias of `newSshClient`).
# Trust-on-first-use here; pin host keys in real code.
let cli = newSshClient("127.0.0.1", 2222, autoTrust = true,
  onReady = proc(c: SshClient) =
    discard # start auth with initAuthClient + authStart
)
cli.poll() # or cli.run() to block

# Force algorithms with typed offers (kexOffer stays strings):
let cli2 = dial("127.0.0.1", 2222, autoTrust = true,
  cipherOffer = @[ckAes128Ctr],
  macOffer = @[mkHmacSha256Etm])
# The enums carry the wire strings as values ($ckAes128Ctr ==
# "aes128-ctr"); parse strings with parseCipherKind/parseMacKind.
```

Lifecycle: both sides own their event loop, so no `Loop` setup is
needed. `srv.close()` stops listening and releases the server loop;
`cli.close()` closes the connection and releases the client loop.

`onPacket` receives the packet sequence number as third argument: pass it
to `authFeed`/`ChannelMux.feed` so unknown message types get a correct
`UNIMPLEMENTED` reply. See `examples/exec_loopback.nim` for a complete
offline handshake → auth → exec round trip, and `tests/test_interop.nim`
for wiring against real OpenSSH.

## Interop

`tests/test_interop.nim` runs system `ssh` against our server and our
client against system `sshd` across a KEX x cipher x MAC matrix
(curve25519/group14, CTR/CTR+ETM/GCM/chacha). It is part of `clue test`
and skipped when OpenSSH is absent.

## Roadmap

### Done (0.1.0, released)

- Binary packet protocol: version exchange, framing, padding, and
  limits (`transport`, `codec`)
- Key exchange: `curve25519-sha256` and `diffie-hellman-group14-sha256`
  with pure-Nim big-integer math, exchange hashes, and RFC 4253 7.2
  key expansion (`kex`)
- Transport ciphers: `chacha20-poly1305`, AES-CTR, AES-GCM, HMAC-SHA2
  with ETM variants (`ciphers`)
- Host keys: `ssh-ed25519` generate, sign, verify, `authorized_keys`
  encoding, fingerprints (`hostkeys`)
- Session state machine: handshake, NEWKEYS, encrypted transport,
  disconnect handling (`session`)
- Authentication: `none`, `publickey`, `password`, client and server
  (`auth`)
- Channels: open, `exec`, `shell`, `env`, `pty-req`, data, EOF/close,
  exit status, global-request decline (`channel`)
- powpow wiring with owned event loops, `poll`/`run` drivers
  (`client`, `server`, `wire`)

### Done (unreleased)

- OpenSSH framing fixes: ETM clear-length CTR packets (both
  directions) and GCM nonce from the full KEX IV, verified against
  real `ssh`/`sshd` with packet captures
- Full interop matrix in both directions, hardened helpers (bool
  results, unique temp dirs, guaranteed cleanup, no hardcoded paths)
- Forced algorithm offers on client and server, typed as
  `seq[CipherKind]`/`seq[MacKind]`
- `newSshClient` constructor alongside the `dial` alias
- Rekey refused with reasoned `DISCONNECT`; send and receive sequence
  numbers raise instead of wrapping
- `IGNORE`/`DEBUG` swallowed mid-auth; `UNIMPLEMENTED` replies with
  packet sequence numbers threaded through the whole stack
- Loopback and fuzz coverage for every cipher and MAC combination,
  negotiation rejection, tamper and rollback cases
- Release files: real README, MIT LICENSE, CHANGELOG, offline
  `exec_loopback` example

### Next

- Real rekeying: KEX restart on demand plus volume and time based
  triggers, negotiated transparently mid-session
- Client host-key verification beyond `autoTrust`: known-hosts file
  support with matching against `ssh-ed25519` pins
- Periodic keepalive: opt-in `IGNORE` timer with idle timeout on
  both roles
- `window-change` and `signal` channel requests, so interactive
  shells resize and interrupt cleanly
- `subsystem` requests as a stepping stone toward an SFTP subsystem
- Asymmetric algorithm negotiation (independent c2s/s2c selection)
  where peers offer direction-specific lists
- Throughput benchmarks and a performance pass over the CTR/GCM
  hot paths
- CI workflow running `clue test` (needs clue plus develop-mode
  links on the runner first)
- Version 0.2.0 release once rekeying and keepalive land

### Later (explicitly out of current scope)

- SFTP file transfer subsystem
- TCP forwarding (`direct-tcpip`, `forwarded-tcpip`) and agent
  forwarding
- `keyboard-interactive` authentication
- Additional host key types (RSA, ECDSA, SK keys)
- Legacy algorithms (CBC, 3DES, AES-192, SHA-1/UMAC MACs) and
  compression: these stay out by design, the MVP is modern-only

### 🎩 License
MIT. Copyright George Lemon & Contributors &mdash; All rights reserved.
