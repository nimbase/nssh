## Robustness: malformed/truncated/adversarial input must never escape as a
## defect, hang, or unbounded allocation. Deterministic PRNG (fixed seed).
##
## Also covers negative interop over real TCP: garbage version line,
## oversize packet_length, and corrupt MAC must all end in a clean close.

import std/net
import std/random
import std/unittest

import powpow

import nssh/session
import nssh/codec
import nssh/transport
import nssh/auth
import nssh/channel
import nssh/client
import nssh/server
import nssh/hostkeys

proc randBytes(rng: var Rand, n: int, alphabet = 256): seq[byte] =
  result = newSeq[byte](n)
  for i in 0 ..< n:
    result[i] = byte(rng.rand(alphabet - 1))

proc mutate(rng: var Rand, data: seq[byte]): seq[byte] =
  ## Truncate, flip bytes, splice garbage, or return as-is.
  result = data
  case rng.rand(4)
  of 0: # truncate
    if result.len > 1:
      result.setLen(rng.rand(result.len - 1))
  of 1: # bit flips
    let n = 1 + rng.rand(4)
    for _ in 0 ..< n:
      if result.len > 0:
        let i = rng.rand(result.len - 1)
        result[i] = result[i] xor byte(1 shl rng.rand(7))
  of 2: # splice garbage
    let pos = if result.len == 0: 0 else: rng.rand(result.len)
    let g = rng.randBytes(1 + rng.rand(16))
    result = result[0 ..< pos] & g & result[pos .. ^1]
  of 3: # pure garbage
    result = rng.randBytes(rng.rand(64))
  else:
    discard

test "codec never raises Defect on random input":
  var rng = initRand(42)
  var defects = 0
  for _ in 0 ..< 3000:
    let data = rng.randBytes(rng.rand(40))
    var r = initReader(data)
    try:
      discard r.readByte()
      discard r.readBool()
      discard r.readUint32()
      discard r.readUint64()
      discard r.readString()
      discard r.readMpint()
      discard r.readNameList()
    except SshCodecError:
      discard
    except Defect:
      inc defects
  check defects == 0

test "transport tryDecodePacket never raises Defect":
  var rng = initRand(7)
  var defects = 0
  for _ in 0 ..< 3000:
    let data = rng.randBytes(rng.rand(48))
    try:
      discard tryDecodePacket(data, 8)
    except SshTransportError:
      discard
    except Defect:
      inc defects
  check defects == 0

test "session never raises Defect on mutated stream (pre + post auth)":
  var rng = initRand(99)
  var defects = 0
  # fresh sessions stuck at version stage
  for _ in 0 ..< 300:
    var s = initServer(generateEdKey())
    let chunk = mutate(rng, @[byte('S'), byte('S'), byte('H')])
    try:
      discard s.receiveBytes(chunk)
    except Defect:
      inc defects
  # open chacha sessions fed mutated packets
  for _ in 0 ..< 300:
    let hk = generateEdKey()
    var cli = initClient(autoTrust = true)
    var srv = initServer(hk)
    cli.startHandshake()
    srv.startHandshake()
    for _ in 0 ..< 10:
      var moved = false
      for pkt in cli.takeOutbox():
        moved = true
        discard srv.receiveBytes(pkt)
      for pkt in srv.takeOutbox():
        moved = true
        discard cli.receiveBytes(pkt)
      if not moved:
        break
    doAssert cli.stage == stOpen
    # mutate one legitimate encrypted packet, then spray garbage
    cli.sendIgnore("fuzzme")
    let wire = cli.takeOutbox()
    doAssert wire.len == 1
    let bad = mutate(rng, wire[0])
    try:
      discard srv.receiveBytes(bad)
      discard srv.receiveBytes(rng.randBytes(rng.rand(200)))
    except Defect:
      inc defects
  check defects == 0

test "inbound buffer is bounded":
  var s = initServer(generateEdKey())
  var errs = 0
  # 300KB of 'A' with no CRLF: must trip the cap, never OOM
  for _ in 0 ..< 30:
    for ev in s.receiveBytes(newSeq[byte](10240)):
      if ev.kind == evErrorMsg:
        inc errs
    if s.stage == stClosed:
      break
  check s.stage == stClosed
  check errs > 0
  check s.inBuf.len <= 262144

test "auth/channel feeds never raise Defect":
  var rng = initRand(1234)
  var defects = 0
  for _ in 0 ..< 2000:
    let data = rng.randBytes(rng.rand(60))
    var a = initAuthServer([0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
    try:
      discard a.authFeed(data)
    except SshAuthError:
      discard
    except Defect:
      inc defects
    var m = initMux(true)
    try:
      discard m.feed(data)
    except SshChannelError:
      discard
    except Defect:
      inc defects
  check defects == 0

proc freePort(): int =
  var s = newSocket()
  s.setSockOpt(OptReuseAddr, true)
  s.bindAddr(Port(0), "127.0.0.1")
  let (_, port) = s.getLocalAddr()
  s.close()
  result = port.int

proc drainOne(raw: Socket, cs: var SshSession): int =
  ## Read currently-available bytes (one at a time: stdlib recv fills the
  ## whole buffer before returning) and feed them.
  ## Returns: 1 = hangup (EOF/RST), 0 = drained/timeout, -1 = progress made.
  var progress = false
  while true:
    var one = newString(1)
    try:
      let n = raw.recv(one, 1, timeout = 30)
      if n <= 0:
        # 0 = orderly EOF; negative = reset (buffer left empty)
        return 1
      discard cs.receiveBytes([byte(one[0])])
      progress = true
    except TimeoutError:
      return if progress: -1 else: 0
    except OSError:
      return 1

proc flushOut(cs: var SshSession, raw: Socket) =
  for pkt in cs.takeOutbox():
    discard raw.send(addr pkt[0], pkt.len)

test "negative interop: garbage version, oversize length, bad MAC close cleanly":
  let loop = newLoop()
  let port = freePort()
  let hk = generateEdKey()
  var closed = 0
  var srv = newSshServer(loop, hk, "127.0.0.1", port,
    onClose = proc(c: ServerConn) = inc closed)
  for _ in 0 ..< 5:
    loop.poll(10)
  # 1. garbage version line
  var raw = newSocket()
  raw.connect("127.0.0.1", Port(port))
  raw.send("GET / HTTP/1.0\r\n\r\n")
  for _ in 0 ..< 40:
    loop.poll(25)
  raw.close()
  # 2. valid version, then oversize packet_length
  raw = newSocket()
  raw.connect("127.0.0.1", Port(port))
  raw.send("SSH-2.0-probe\r\n")
  for _ in 0 ..< 20:
    loop.poll(25)
  raw.send("\x7F\xFF\xFF\xFF\x00\x00\x00\x00")
  for _ in 0 ..< 40:
    loop.poll(25)
  raw.close()
  # 3. full handshake over a raw socket, then corrupt bytes post-NEWKEYS
  var cs = initClient(autoTrust = true)
  cs.cipherOffer = @["aes128-ctr"]
  var srv3 = newSshServer(loop, hk, "127.0.0.1", port + 1,
    cipherOffer = @["aes128-ctr"],
    onClose = proc(c: ServerConn) = inc closed)
  for _ in 0 ..< 5:
    loop.poll(10)
  raw = newSocket()
  raw.connect("127.0.0.1", Port(port + 1))
  cs.startHandshake()
  flushOut(cs, raw)
  var openSeen = false
  for _ in 0 ..< 120:
    loop.poll(5)
    if drainOne(raw, cs) == 1:
      break
    flushOut(cs, raw)
    # check ready by re-reading stage (evReady consumed inside receiveBytes)
    if cs.stage == stOpen:
      # one more flush: our own NEWKEYS may still be queued when the
      # peer's NEWKEYS flips us open
      flushOut(cs, raw)
      openSeen = true
      break
  check openSeen
  # corrupt packet with bad MAC: flip bytes deep inside a valid packet
  cs.sendIgnore("will-corrupt")
  var wire = cs.takeOutbox()
  check wire.len == 1
  wire[0][10] = wire[0][10] xor 0xFF
  wire[0][20] = wire[0][20] xor 0xFF
  discard raw.send(addr wire[0][0], wire[0].len)
  var serverHungUp = false
  for _ in 0 ..< 120:
    loop.poll(5)
    if drainOne(raw, cs) == 1:
      serverHungUp = true
      break
    if closed >= 3:
      serverHungUp = true
      break
  raw.close()
  check serverHungUp
  # cases 1+2 close via server-side EOF detection; case 3 is a server-side
  # self-close after the MAC failure (hangup observed above)
  check closed >= 2
  srv.close()
  srv3.close()
  loop.close()
