# SSH server over powpow: accept loop, per-connection sessions, event fan-out.
#
# Owns its event loop: created in `newSshServer`, driven with `poll`/`run`.
# Sessions live in a table keyed by connection identity; entries are dropped
# on close so refs stay alive exactly as long as the connection.

import std/tables
import std/sequtils

import powpow

import ./session
import ./ciphers
import ./wire
import ./hostkeys

export session
export hostkeys

type
  ServerConn* = ref object
    conn*: Connection
    session*: SshSession

  SshServer* = ref object
    loop*: Loop ## event loop owned by the server (created in newSshServer)
    tcp*: TcpServer
    hostKey*: EdKeyPair
    conns*: Table[pointer, ServerConn]
    onReady*: proc(c: ServerConn) {.closure.}
    onPacket*: proc(c: ServerConn, msgType: byte, payload: seq[byte],
                     seqno: uint32) {.closure.}
    onDisconnect*: proc(c: ServerConn, msg: string) {.closure.}
    onError*: proc(c: ServerConn, msg: string) {.closure.}
    onClose*: proc(c: ServerConn) {.closure.}
    onRekey*: proc(c: ServerConn) {.closure.}
    rekeyPolicy*: RekeyPolicy
    keepaliveIntervalMs*: int
    idleTimeoutMs*: int

proc key(conn: Connection): pointer {.inline.} =
  cast[pointer](conn)

proc newSshServer*(hostKey: EdKeyPair, address: string, port: int,
                   onReady: proc(c: ServerConn) {.closure.} = nil,
                   onPacket: proc(c: ServerConn, msgType: byte,
                                  payload: seq[byte],
                                  seqno: uint32) {.closure.} = nil,
                   onDisconnect: proc(c: ServerConn, msg: string) {.closure.} = nil,
                   onError: proc(c: ServerConn, msg: string) {.closure.} = nil,
                   onClose: proc(c: ServerConn) {.closure.} = nil,
                   cipherOffer: seq[CipherKind] = @[],
                   kexOffer: seq[string] = @[],
                   macOffer: seq[MacKind] = @[],
                   onRekey: proc(c: ServerConn) {.closure.} = nil,
                   rekeyPolicy: RekeyPolicy = defaultRekeyPolicy(),
                   keepaliveIntervalMs = 0,
                   idleTimeoutMs = 0): SshServer =
  result = SshServer(loop: newLoop(), hostKey: hostKey,
                     conns: initTable[pointer, ServerConn](),
                     onReady: onReady, onPacket: onPacket,
                     onDisconnect: onDisconnect, onError: onError,
                     onClose: onClose, onRekey: onRekey,
                     rekeyPolicy: rekeyPolicy,
                     keepaliveIntervalMs: keepaliveIntervalMs,
                     idleTimeoutMs: idleTimeoutMs)
  let srv = result
  let offer = cipherOffer
  srv.tcp = newTcpServer(srv.loop,
    onAccept = proc(conn: Connection) =
      var sc = ServerConn(conn: conn, session: initServer(srv.hostKey))
      if offer.len > 0:
        sc.session.cipherOffer = offer
      if kexOffer.len > 0:
        sc.session.kexOffer = kexOffer
      if macOffer.len > 0:
        sc.session.macOffer = macOffer
      sc.session.policy = srv.rekeyPolicy
      sc.session.setKeepalive(srv.keepaliveIntervalMs, srv.idleTimeoutMs)
      srv.conns[key(conn)] = sc
      sc.session.startHandshake()
      flushOutbox(conn, sc.session)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      let sc = srv.conns.getOrDefault(key(conn))
      if sc == nil:
        conn.close()
        return
      let events = sc.session.receiveBytes(data)
      flushOutbox(conn, sc.session)
      let onReadyCb = srv.onReady
      let onPacketCb = srv.onPacket
      let onDiscCb = srv.onDisconnect
      let onErrCb = srv.onError
      let onRekeyCb = srv.onRekey
      dispatch(events,
        onReady = (if onReadyCb != nil: (proc() {.closure.} = onReadyCb(sc)) else: nil),
        onPacket = (if onPacketCb != nil: (proc(m: byte, p: seq[byte], q: uint32) {.closure.} = onPacketCb(sc, m, p, q)) else: nil),
        onDisconnect = (if onDiscCb != nil: (proc(m: string) {.closure.} = onDiscCb(sc, m)) else: nil),
        onError = (if onErrCb != nil: (proc(m: string) {.closure.} = onErrCb(sc, m)) else: nil),
        onRekey = (if onRekeyCb != nil: (proc() {.closure.} = onRekeyCb(sc)) else: nil))
      closeIfDone(conn, sc.session)
    ,
    onClose = proc(conn: Connection) =
      let sc = srv.conns.getOrDefault(key(conn))
      if sc != nil:
        srv.conns.del(key(conn))
        if srv.onClose != nil:
          srv.onClose(sc)
    ,
  )
  srv.tcp.listen(address, port)

proc poll*(srv: SshServer, timeoutMs = 25) =
  ## Drive the server's owned event loop once, then keepalive timers.
  srv.loop.poll(timeoutMs)
  for k in toSeq(srv.conns.keys):
    let sc = srv.conns.getOrDefault(k)
    if sc == nil:
      continue
    if sc.session.stage == stOpen:
      let evs = sc.session.pollKeepalive()
      flushOutbox(sc.conn, sc.session)
      if evs.len > 0:
        let scCopy = sc
        let onDiscCb = srv.onDisconnect
        let onErrCb = srv.onError
        dispatch(evs,
          onDisconnect = (if onDiscCb != nil: (proc(m: string) {.closure.} = onDiscCb(scCopy, m)) else: nil),
          onError = (if onErrCb != nil: (proc(m: string) {.closure.} = onErrCb(scCopy, m)) else: nil))
        closeIfDone(sc.conn, sc.session)

proc run*(srv: SshServer) =
  ## Drive the server's owned event loop until stopped.
  srv.loop.run()

proc close*(srv: SshServer) =
  ## Stop listening and release the owned event loop.
  srv.tcp.close()
  srv.loop.close()

proc sendIgnore*(srv: SshServer, c: ServerConn, data = "nssh") =
  c.session.sendIgnore(data)
  flushOutbox(c.conn, c.session)

proc sendRaw*(srv: SshServer, c: ServerConn, payload: openArray[byte]) =
  ## Send an upper-layer payload (auth/channel) through the session.
  c.session.sendPayload(payload)
  flushOutbox(c.conn, c.session)

proc sendDisconnect*(srv: SshServer, c: ServerConn, reason: uint32,
                     message: string) =
  ## Queue DISCONNECT, flush, and close the TCP connection.
  c.session.sendDisconnect(reason, message)
  flushOutbox(c.conn, c.session)
  c.conn.close()
