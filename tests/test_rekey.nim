import std/strutils
import std/unittest
import std/os

import nssh/session
import nssh/ciphers
import nssh/hostkeys
import nssh/knownhosts

proc pump(cli, srv: var SshSession, chunkSize = 0,
          maxRounds = 40): tuple[cEv, sEv: seq[SessionEvent]] =
  result.cEv = @[]
  result.sEv = @[]
  for _ in 0 ..< maxRounds:
    var moved = false
    for pkt in cli.takeOutbox():
      moved = true
      if chunkSize <= 0:
        for ev in srv.receiveBytes(pkt):
          result.sEv.add(ev)
      else:
        var i = 0
        while i < pkt.len:
          let j = min(i + chunkSize, pkt.len)
          for ev in srv.receiveBytes(pkt.toOpenArray(i, j - 1)):
            result.sEv.add(ev)
          i = j
    for pkt in srv.takeOutbox():
      moved = true
      if chunkSize <= 0:
        for ev in cli.receiveBytes(pkt):
          result.cEv.add(ev)
      else:
        var i = 0
        while i < pkt.len:
          let j = min(i + chunkSize, pkt.len)
          for ev in cli.receiveBytes(pkt.toOpenArray(i, j - 1)):
            result.cEv.add(ev)
          i = j
    if not moved:
      break

proc openPair(cipher = ckChacha20Poly1305, mac = mkHmacSha256): tuple[cli, srv: SshSession] =
  let hk = generateEdKey()
  var cli = initClient(autoTrust = true)
  var srv = initServer(hk)
  cli.cipherOffer = @[cipher]
  srv.cipherOffer = @[cipher]
  cli.macOffer = @[mac]
  srv.macOffer = @[mac]
  # Disable auto triggers for deterministic tests; triggers tested explicitly.
  cli.policy = RekeyPolicy()
  srv.policy = RekeyPolicy()
  cli.startHandshake()
  srv.startHandshake()
  discard pump(cli, srv)
  assert cli.stage == stOpen
  assert srv.stage == stOpen
  result = (cli, srv)

proc countKind(ev: seq[SessionEvent], k: EventKind): int =
  for e in ev:
    if e.kind == k:
      inc result

test "client-initiated rekey preserves session id, rotates keys, traffic flows":
  var (cli, srv) = openPair()
  let sid = cli.sessionId
  let k0 = cli.K
  let s0 = cli.sendSeq
  check cli.requestRekey()
  let r = pump(cli, srv)
  check countKind(r.cEv, evRekeyDone) == 1
  check countKind(r.sEv, evRekeyDone) == 1
  check cli.stage == stOpen
  check srv.stage == stOpen
  check cli.sessionId == sid
  check srv.sessionId == sid
  check cli.K == srv.K
  check cli.K.len > 0
  # Fresh ephemeral overwhelmingly rotates K.
  check cli.K != k0
  # Sequence numbers continue, never reset (RFC 4253 §6.4).
  check cli.sendSeq > s0
  check cli.recvSeq > 0
  cli.sendIgnore("after-rekey")
  let r2 = pump(cli, srv)
  var got = false
  for e in r2.sEv:
    if e.kind == evPacket and e.msgType == MsgIgnore:
      got = true
  check got

test "rekey works for every cipher family":
  for cipher in [ckAes128Ctr, ckAes256Ctr, ckAes128Gcm, ckAes256Gcm,
                 ckChacha20Poly1305]:
    var (cli, srv) = openPair(cipher)
    check cli.requestRekey()
    let r = pump(cli, srv, chunkSize = 7)
    check countKind(r.cEv, evRekeyDone) == 1
    check countKind(r.sEv, evRekeyDone) == 1
    cli.sendIgnore("ok")
    srv.sendIgnore("back")
    let r2 = pump(cli, srv, chunkSize = 7)
    check countKind(r2.sEv, evPacket) >= 1
    check countKind(r2.cEv, evPacket) >= 1

test "server-initiated rekey completes":
  var (cli, srv) = openPair()
  check srv.requestRekey()
  let r = pump(cli, srv)
  check countKind(r.cEv, evRekeyDone) == 1
  check countKind(r.sEv, evRekeyDone) == 1
  check cli.K == srv.K

test "simultaneous rekey: both initiate, single exchange completes":
  var (cli, srv) = openPair()
  check cli.requestRekey()
  check srv.requestRekey()
  let r = pump(cli, srv)
  # Both sides converge without duplicate-KEXINIT failure or disconnect.
  check cli.stage == stOpen
  check srv.stage == stOpen
  check countKind(r.cEv, evRekeyDone) == 1
  check countKind(r.sEv, evRekeyDone) == 1
  check cli.K == srv.K
  check cli.sessionId == srv.sessionId

test "second requestRekey while in flight is refused, not duplicated":
  var (cli, srv) = openPair()
  check cli.requestRekey()
  check not cli.requestRekey()
  let r = pump(cli, srv)
  check countKind(r.cEv, evRekeyDone) == 1
  # After completion a fresh rekey is allowed again.
  check cli.requestRekey()
  let r2 = pump(cli, srv)
  check countKind(r2.cEv, evRekeyDone) == 1

test "app data sent during rekey is queued and delivered in order":
  var (cli, srv) = openPair()
  check cli.requestRekey()
  # Channel/auth messages (>=50) MUST NOT be sent until NEWKEYS (§7.1);
  # they queue. Transport control (IGNORE) still flows immediately.
  proc chanData(tag: byte): seq[byte] =
    @[94'u8, 0'u8, 0'u8, 0'u8, 0'u8, tag]
  cli.sendPayload(chanData(1))
  cli.sendPayload(chanData(2))
  check cli.appQueue.len == 2
  # IGNORE is allowed during rekey and is not queued.
  let qBefore = cli.appQueue.len
  cli.sendIgnore("still-flows")
  check cli.appQueue.len == qBefore
  let r = pump(cli, srv)
  check countKind(r.cEv, evRekeyDone) == 1
  var seen: seq[byte] = @[]
  for e in r.sEv:
    if e.kind == evPacket and e.msgType == 94:
      seen.add(e.payload[^1])
  check seen == @[1'u8, 2'u8]

test "packet trigger fires automatically":
  var (cli, srv) = openPair()
  cli.policy = RekeyPolicy(maxPacketsSent: 2)
  srv.policy = RekeyPolicy()
  # openPair handshakes with empty policy; zero counters for determinism.
  cli.packetsSent = 0
  cli.packetsRecv = 0
  cli.bytesSent = 0
  cli.bytesRecv = 0
  srv.packetsSent = 0
  srv.packetsRecv = 0
  srv.bytesSent = 0
  srv.bytesRecv = 0
  cli.sendIgnore("a")  # packetsSent=1, no trigger yet
  check not cli.isRekeying()
  cli.sendIgnore("b")  # packetsSent=2 -> trigger fires after send
  check cli.isRekeying()
  let r = pump(cli, srv)
  check countKind(r.cEv, evRekeyDone) == 1
  check countKind(r.sEv, evRekeyDone) == 1

test "byte trigger fires automatically":
  var (cli, srv) = openPair()
  cli.policy = RekeyPolicy(maxBytesSent: 10)
  srv.policy = RekeyPolicy()
  cli.sendIgnore("trigger-bytes")
  let r = pump(cli, srv)
  let r2 = pump(cli, srv)
  check countKind(r.cEv & r2.cEv, evRekeyDone) == 1

test "time trigger via injected clock":
  var (cli, srv) = openPair()
  cli.policy = RekeyPolicy(maxSeconds: 3600)
  check not cli.needsRekey(cli.lastRekeyNanos + 3599 * 1_000_000_000'i64)
  check cli.needsRekey(cli.lastRekeyNanos + 3600 * 1_000_000_000'i64)

test "seqno margin trigger before 2^32 wrap":
  var (cli, srv) = openPair()
  cli.policy = RekeyPolicy(seqnoMargin: 10)
  cli.sendSeq = high(uint32) - 11
  check not cli.needsRekey()
  cli.sendSeq = high(uint32) - 10
  check cli.needsRekey()

test "keepalive interval sends IGNORE, idle timeout disconnects":
  var (cli, srv) = openPair()
  cli.setKeepalive(intervalMs = 100, idleTimeoutMs = 0)
  # Force last-send far in the past via injected clock.
  let evs = cli.pollKeepalive(cli.lastSendNanos + 200 * 1_000_000'i64)
  check evs.len == 0
  check cli.takeOutbox().len == 1  # IGNORE queued
  # Idle timeout path.
  var (cli2, srv2) = openPair()
  cli2.setKeepalive(intervalMs = 0, idleTimeoutMs = 100)
  let d = cli2.pollKeepalive(cli2.lastRecvNanos + 200 * 1_000_000'i64)
  check cli2.stage == stClosed
  check countKind(d, evDisconnect) == 1

test "known_hosts parse, match, file round trip":
  let kp = generateEdKey()
  let line = encodeKnownHostsLine("example.com", 22, kp.pubkey)
  let entries = parseKnownHostsLine(line)
  check entries.len == 1
  check entries[0].host == "example.com"
  check matchKnownHostEntry(entries, "example.com", 22, kp.pubkey)
  check not matchKnownHostEntry(entries, "other.com", 22, kp.pubkey)
  let other = generateEdKey()
  check not matchKnownHostEntry(entries, "example.com", 22, other.pubkey)
  # Port-qualified form.
  let line2 = encodeKnownHostsLine("example.com", 2222, kp.pubkey)
  let e2 = parseKnownHostsLine(line2)
  check e2[0].port == 2222
  check matchKnownHostEntry(e2, "example.com", 2222, kp.pubkey)
  check not matchKnownHostEntry(e2, "example.com", 22, kp.pubkey)
  # File round trip + append.
  let dir = getTempDir() / "nssh-knownhosts-test"
  createDir(dir)
  let path = dir / "known_hosts"
  if fileExists(path):
    removeFile(path)
  appendKnownHost(path, "example.com", 22, kp.pubkey)
  let loaded = loadKnownHosts(path)
  check matchKnownHostEntry(loaded, "example.com", 22, kp.pubkey)
  removeFile(path)
  removeDir(dir)

test "strict host verification rejects unknown, accepts pinned":
  let hk = generateEdKey()
  var cli = initClient(autoTrust = false)
  cli.verifyMode = vmStrict
  cli.peerHost = "example.com"
  cli.peerPort = 22
  cli.knownHosts = @[KnownHostEntry(host: "example.com", port: -1,
    alg: HostKeyEd25519, pubkey: hk.pubkey)]
  var srv = initServer(hk)
  cli.startHandshake()
  srv.startHandshake()
  let r = pump(cli, srv)
  check countKind(r.cEv, evReady) == 1
  # Unknown key under strict mode aborts.
  let hk2 = generateEdKey()
  var cli2 = initClient(autoTrust = false)
  cli2.verifyMode = vmStrict
  cli2.peerHost = "example.com"
  cli2.peerPort = 22
  cli2.knownHosts = @[KnownHostEntry(host: "example.com", port: -1,
    alg: HostKeyEd25519, pubkey: hk.pubkey)]
  var srv2 = initServer(hk2)
  cli2.startHandshake()
  srv2.startHandshake()
  let r2 = pump(cli2, srv2)
  var gotErr = false
  for e in r2.cEv:
    if e.kind == evErrorMsg and e.message.contains("untrusted"):
      gotErr = true
  check gotErr
