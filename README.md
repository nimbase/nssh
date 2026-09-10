# nssh — pure-Nim SSH client and server

Modern-only SSH-2.0 client and server in strict pure Nim (no C, no OpenSSL).
Async TCP comes from [`powpow`](https://github.com/openpeeps/powpow),
crypto from [`nimcypher`](https://github.com/nimbase/nimcypher).

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

Local development uses [`clue`](https://github.com/openpeeps/clue) with
editable links (`clue develop` inside the `nimcypher` and `powpow`
checkouts), then:

```sh
clue test
```

## Usage

```nim
import powpow
import nssh/client
import nssh/server
import nssh/hostkeys

let loop = newLoop()

# Server: accept, then route packets to auth/channel layers in onPacket.
let hk = generateEdKey()
let srv = newSshServer(loop, hk, "127.0.0.1", 2222,
  onPacket = proc(c: ServerConn, m: byte, p: seq[byte], q: uint32) =
    discard # feed p to AuthServer (< 80) or ChannelMux (>= 90) with seqno q
)

# Client: trust-on-first-use here; pin host keys in real code.
let cli = dial(loop, "127.0.0.1", 2222, autoTrust = true,
  onReady = proc(c: SshClient) =
    discard # start auth with initAuthClient + authStart
)

# Force algorithms when needed:
let cli2 = dial(loop, "127.0.0.1", 2222, autoTrust = true,
  cipherOffer = @["aes128-ctr"],
  macOffer = @["hmac-sha2-256-etm@openssh.com"])
```

`onPacket` receives the packet sequence number as third argument: pass it
to `authFeed`/`ChannelMux.feed` so unknown message types get a correct
`UNIMPLEMENTED` reply. See `examples/exec_loopback.nim` for a complete
offline handshake → auth → exec round trip, and `tests/test_interop.nim`
for wiring against real OpenSSH.

## Interop

`tests/test_interop.nim` runs system `ssh` against our server and our
client against system `sshd` across a KEX × cipher × MAC matrix
(curve25519/group14, CTR/CTR+ETM/GCM/chacha). It is part of `clue test`
and skipped when OpenSSH is absent.

## License

MIT — see `LICENSE`.
