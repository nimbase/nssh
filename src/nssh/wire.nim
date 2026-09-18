# Shared powpow glue: flush session outbox to a connection and fan session
# events out to role-specific callbacks.

import powpow

import ./session

export session

proc flushOutbox*(conn: Connection, s: var SshSession) =
  for pkt in s.takeOutbox():
    discard conn.send(pkt)

proc dispatch*(events: seq[SessionEvent],
               onReady: proc() {.closure.} = nil,
               onPacket: proc(msgType: byte, payload: seq[byte],
                              seqno: uint32) {.closure.} = nil,
               onDisconnect: proc(msg: string) {.closure.} = nil,
               onError: proc(msg: string) {.closure.} = nil,
               onRekey: proc() {.closure.} = nil) =
  for ev in events:
    case ev.kind
    of evReady:
      if onReady != nil:
        onReady()
    of evRekeyDone:
      # Transparent by default; apps opting into rotation accounting pass
      # onRekey. Fall back to onReady so legacy loops still observe progress.
      if onRekey != nil:
        onRekey()
      elif onReady != nil:
        onReady()
    of evPacket:
      if onPacket != nil:
        onPacket(ev.msgType, ev.payload, ev.seqno)
    of evDisconnect:
      if onDisconnect != nil:
        onDisconnect(ev.message)
    of evErrorMsg:
      if onError != nil:
        onError(ev.message)

proc closeIfDone*(conn: Connection, s: SshSession) =
  ## SSH teardown: once the session leaves stOpen path (error/disconnect),
  ## close the TCP connection. Call after dispatch.
  if s.stage == stClosed:
    conn.close()
