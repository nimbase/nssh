# SSH server over powpow: accept loop, per-connection sessions, event fan-out.
#
# Owns nothing: the caller creates the Loop and drives it (`poll`/`run`).
# Sessions live in a table keyed by connection identity; entries are dropped
# on close so refs stay alive exactly as long as the connection.

import std/tables

import powpow

import ./session
import ./wire
import ./hostkeys

export session
export hostkeys

type
  ServerConn* = ref object
    conn*: Connection
    session*: SshSession

  SshServer* = ref object
    loop*: Loop
    tcp*: TcpServer
    hostKey*: EdKeyPair
    conns*: Table[pointer, ServerConn]
    onReady*: proc(c: ServerConn) {.closure.}
    onPacket*: proc(c: ServerConn, msgType: byte, payload: seq[byte]) {.closure.}
    onDisconnect*: proc(c: ServerConn, msg: string) {.closure.}
    onError*: proc(c: ServerConn, msg: string) {.closure.}
    onClose*: proc(c: ServerConn) {.closure.}

proc key(conn: Connection): pointer {.inline.} =
  cast[pointer](conn)

proc newSshServer*(loop: Loop, hostKey: EdKeyPair, address: string, port: int,
                   onReady: proc(c: ServerConn) {.closure.} = nil,
                   onPacket: proc(c: ServerConn, msgType: byte,
                                  payload: seq[byte]) {.closure.} = nil,
                   onDisconnect: proc(c: ServerConn, msg: string) {.closure.} = nil,
                   onError: proc(c: ServerConn, msg: string) {.closure.} = nil,
                   onClose: proc(c: ServerConn) {.closure.} = nil,
                   cipherOffer: seq[string] = @[]): SshServer =
  result = SshServer(loop: loop, hostKey: hostKey, conns: initTable[pointer, ServerConn](),
                     onReady: onReady, onPacket: onPacket,
                     onDisconnect: onDisconnect, onError: onError, onClose: onClose)
  let srv = result
  let offer = cipherOffer
  srv.tcp = newTcpServer(loop,
    onAccept = proc(conn: Connection) =
      var sc = ServerConn(conn: conn, session: initServer(srv.hostKey))
      if offer.len > 0:
        sc.session.cipherOffer = offer
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
      dispatch(events,
        onReady = (if onReadyCb != nil: (proc() {.closure.} = onReadyCb(sc)) else: nil),
        onPacket = (if onPacketCb != nil: (proc(m: byte, p: seq[byte]) {.closure.} = onPacketCb(sc, m, p)) else: nil),
        onDisconnect = (if onDiscCb != nil: (proc(m: string) {.closure.} = onDiscCb(sc, m)) else: nil),
        onError = (if onErrCb != nil: (proc(m: string) {.closure.} = onErrCb(sc, m)) else: nil))
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

proc close*(srv: SshServer) =
  srv.tcp.close()

proc sendIgnore*(srv: SshServer, c: ServerConn, data = "nssh") =
  c.session.sendIgnore(data)
  flushOutbox(c.conn, c.session)

proc sendRaw*(srv: SshServer, c: ServerConn, payload: openArray[byte]) =
  ## Send an upper-layer payload (auth/channel) through the session.
  c.session.sendPayload(payload)
  flushOutbox(c.conn, c.session)
