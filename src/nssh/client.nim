# SSH client over powpow: async connect, session handshake, event fan-out.
#
# Owns nothing: the caller creates the Loop and drives it (`poll`/`run`).

import powpow/loop
import powpow/net
import powpow/net/tcp
import powpow/proto/httpclient

import ./session
import ./ciphers
import ./wire

export session

type
  SshClient* = ref object
    loop*: Loop ## event loop owned by the client (created in newSshClient)
    conn*: Connection
    session*: SshSession
    connected*: bool
    onReady*: proc(c: SshClient) {.closure.}
    onPacket*: proc(c: SshClient, msgType: byte, payload: seq[byte],
                     seqno: uint32) {.closure.}
    onDisconnect*: proc(c: SshClient, msg: string) {.closure.}
    onError*: proc(c: SshClient, msg: string) {.closure.}
    onClose*: proc(c: SshClient) {.closure.}

proc newSshClient*(address: string, port: int, autoTrust = false,
           onReady: proc(c: SshClient) {.closure.} = nil,
           onPacket: proc(c: SshClient, msgType: byte,
                          payload: seq[byte],
                          seqno: uint32) {.closure.} = nil,
           onDisconnect: proc(c: SshClient, msg: string) {.closure.} = nil,
           onError: proc(c: SshClient, msg: string) {.closure.} = nil,
           onClose: proc(c: SshClient) {.closure.} = nil,
           cipherOffer: seq[CipherKind] = @[],
           kexOffer: seq[string] = @[],
           macOffer: seq[MacKind] = @[]): SshClient =
  result = SshClient(loop: newLoop(), session: initClient(autoTrust),
                     onReady: onReady, onPacket: onPacket,
                     onDisconnect: onDisconnect, onError: onError, onClose: onClose)
  if cipherOffer.len > 0:
    result.session.cipherOffer = cipherOffer
  if kexOffer.len > 0:
    result.session.kexOffer = kexOffer
  if macOffer.len > 0:
    result.session.macOffer = macOffer
  let cli = result
  cli.loop.connect(address, port,
    onConnect = proc(conn: Connection) =
      cli.conn = conn
      cli.connected = true
      cli.session.startHandshake()
      flushOutbox(conn, cli.session)
    ,
    onData = proc(conn: Connection, data: openArray[byte]) =
      let events = cli.session.receiveBytes(data)
      flushOutbox(conn, cli.session)
      let onReadyCb = cli.onReady
      let onPacketCb = cli.onPacket
      let onDiscCb = cli.onDisconnect
      let onErrCb = cli.onError
      dispatch(events,
        onReady = (if onReadyCb != nil: (proc() {.closure.} = onReadyCb(cli)) else: nil),
        onPacket = (if onPacketCb != nil: (proc(m: byte, p: seq[byte], q: uint32) {.closure.} = onPacketCb(cli, m, p, q)) else: nil),
        onDisconnect = (if onDiscCb != nil: (proc(m: string) {.closure.} = onDiscCb(cli, m)) else: nil),
        onError = (if onErrCb != nil: (proc(m: string) {.closure.} = onErrCb(cli, m)) else: nil))
      closeIfDone(conn, cli.session)
    ,
    onClose = proc(conn: Connection) =
      if cli.onClose != nil:
        cli.onClose(cli)
    ,
    onError = proc(err: string) =
      if cli.onError != nil:
        cli.onError(cli, err)
    ,
  )

proc dial*(address: string, port: int, autoTrust = false,
           onReady: proc(c: SshClient) {.closure.} = nil,
           onPacket: proc(c: SshClient, msgType: byte,
                          payload: seq[byte],
                          seqno: uint32) {.closure.} = nil,
           onDisconnect: proc(c: SshClient, msg: string) {.closure.} = nil,
           onError: proc(c: SshClient, msg: string) {.closure.} = nil,
           onClose: proc(c: SshClient) {.closure.} = nil,
           cipherOffer: seq[CipherKind] = @[],
           kexOffer: seq[string] = @[],
           macOffer: seq[MacKind] = @[]): SshClient =
  ## Alias for newSshClient.
  newSshClient(address, port, autoTrust, onReady, onPacket, onDisconnect,
    onError, onClose, cipherOffer, kexOffer, macOffer)

proc poll*(cli: SshClient, timeoutMs = 25) =
  ## Drive the client's owned event loop once.
  cli.loop.poll(timeoutMs)

proc run*(cli: SshClient) =
  ## Drive the client's owned event loop until stopped.
  cli.loop.run()

proc sendIgnore*(cli: SshClient, data = "nssh") =
  cli.session.sendIgnore(data)
  flushOutbox(cli.conn, cli.session)

proc sendRaw*(cli: SshClient, payload: openArray[byte]) =
  ## Send an upper-layer payload (auth/channel) through the session.
  cli.session.sendPayload(payload)
  flushOutbox(cli.conn, cli.session)

proc sendDisconnect*(cli: SshClient, reason: uint32, message: string) =
  ## Queue DISCONNECT, flush, and close the TCP connection.
  cli.session.sendDisconnect(reason, message)
  flushOutbox(cli.conn, cli.session)
  cli.conn.close()

proc close*(cli: SshClient) =
  ## Close the connection (if any) and release the owned event loop.
  if cli.conn != nil:
    cli.conn.close()
  cli.loop.close()
