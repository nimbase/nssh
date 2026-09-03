# SSH connection channels (RFC 4254): session open, requests (exec/shell/
# pty-req/env/exit-status), data with window flow control, eof/close.
#
# Same outbox style as session/auth: feed inbound payloads, take response
# payloads, send them with `session.sendPayload`.

import std/tables

import nssh/codec

const
  MsgChannelOpen* = 90'u8
  MsgChannelOpenConfirmation* = 91'u8
  MsgChannelOpenFailure* = 92'u8
  MsgChannelWindowAdjust* = 93'u8
  MsgChannelData* = 94'u8
  MsgChannelExtendedData* = 95'u8
  MsgChannelEof* = 96'u8
  MsgChannelClose* = 97'u8
  MsgChannelRequest* = 98'u8
  MsgChannelSuccess* = 99'u8
  MsgChannelFailure* = 100'u8

  MsgGlobalRequest* = 80'u8
  MsgRequestSuccess* = 81'u8
  MsgRequestFailure* = 82'u8

  # Transport keepalives (RFC 4253 §11) that may arrive on the connection
  # stream; surfaced as packets by session, ignored here.
  MsgIgnore* = 2'u8
  MsgDebug* = 4'u8

  OpenAdminProhibited* = 1'u32
  OpenConnectFailed* = 2'u32
  OpenUnknownType* = 3'u32
  OpenResourceShortage* = 4'u32

  DefaultWindow* = 1_048_576'u32
  DefaultMaxPacket* = 32_768'u32

type
  SshChannelError* = object of ValueError

  ChanState* = enum
    chOpening, chOpen, chEofReceived, chClosed

  Channel* = object
    localId*: uint32
    remoteId*: uint32
    hasRemote*: bool
    localWindow*: uint32   ## how much the peer may still send us
    localMaxPkt*: uint32
    remoteWindow*: uint32  ## how much we may still send
    remoteMaxPkt*: uint32
    state*: ChanState
    eofSent*: bool
    closeSent*: bool

  ChanEventKind* = enum
    cevOpened, cevOpenFailure, cevData, cevExtendedData, cevEof, cevClose,
    cevExec, cevShell, cevEnv, cevPty, cevExitStatus, cevExitSignal,
    cevRequestOk, cevRequestFail, cevGlobalRequest

  ChanEvent* = object
    kind*: ChanEventKind
    localId*: uint32
    data*: seq[byte]
    dataType*: uint32
    text*: string
    text2*: string
    status*: uint32

  ChannelMux* = object
    isServer*: bool
    channels*: Table[uint32, Channel]
    nextId*: uint32
    outbox*: seq[seq[byte]]

proc initMux*(isServer: bool): ChannelMux =
  result.isServer = isServer
  result.channels = initTable[uint32, Channel]()
  result.nextId = 0

proc takeOutbox*(m: var ChannelMux): seq[seq[byte]] =
  result = m.outbox
  m.outbox = @[]

proc get(m: ChannelMux, id: uint32): Channel =
  if id notin m.channels:
    raise newException(SshChannelError, "ssh channel: unknown id")
  result = m.channels[id]

# ── senders ─────────────────────────────────────────────────────────────────

proc openSessionChannel*(m: var ChannelMux): uint32 =
  ## Client: open a session channel. Returns the local id.
  let id = m.nextId
  inc m.nextId
  m.channels[id] = Channel(localId: id, localWindow: DefaultWindow,
    localMaxPkt: DefaultMaxPacket, state: chOpening)
  var w = initWriter()
  w.writeByte(MsgChannelOpen)
  w.writeString("session")
  w.writeUint32(id)
  w.writeUint32(DefaultWindow)
  w.writeUint32(DefaultMaxPacket)
  m.outbox.add(w.toBytes())
  result = id

proc sendRequest(m: var ChannelMux, id: uint32, name: string, wantReply: bool,
                 body: proc(w: var Writer) {.closure.} = nil) =
  let c = m.get(id)
  var w = initWriter()
  w.writeByte(MsgChannelRequest)
  w.writeUint32(c.remoteId)
  w.writeString(name)
  w.writeBool(wantReply)
  if body != nil:
    body(w)
  m.outbox.add(w.toBytes())

proc requestExec*(m: var ChannelMux, id: uint32, command: string) =
  m.sendRequest(id, "exec", true, proc(w: var Writer) {.closure.} =
    w.writeString(command))

proc requestShell*(m: var ChannelMux, id: uint32) =
  m.sendRequest(id, "shell", true)

proc sendExitStatus*(m: var ChannelMux, id: uint32, status: uint32) =
  m.sendRequest(id, "exit-status", false, proc(w: var Writer) {.closure.} =
    w.writeUint32(status))

proc sendData*(m: var ChannelMux, id: uint32, data: openArray[byte]): int =
  ## Queue DATA frames honoring remote window + max packet. Returns bytes
  ## queued; if less than data.len, retry the remainder after WINDOW_ADJUST.
  var c = m.get(id)
  if c.state != chOpen and c.state != chEofReceived:
    raise newException(SshChannelError, "ssh channel: not open")
  var off = 0
  while off < data.len and c.remoteWindow > 0:
    let take = min(min(data.len - off, int(c.remoteWindow)),
                   int(c.remoteMaxPkt))
    if take <= 0:
      break
    var w = initWriter()
    w.writeByte(MsgChannelData)
    w.writeUint32(c.remoteId)
    w.writeString(data.toOpenArray(off, off + take - 1))
    m.outbox.add(w.toBytes())
    c.remoteWindow -= uint32(take)
    off += take
  m.channels[id] = c
  result = off

proc sendExtendedData*(m: var ChannelMux, id: uint32, dataType: uint32,
                       data: openArray[byte]): int =
  var c = m.get(id)
  if c.state != chOpen and c.state != chEofReceived:
    raise newException(SshChannelError, "ssh channel: not open")
  var off = 0
  while off < data.len and c.remoteWindow > 0:
    let take = min(min(data.len - off, int(c.remoteWindow)),
                   int(c.remoteMaxPkt))
    if take <= 0:
      break
    var w = initWriter()
    w.writeByte(MsgChannelExtendedData)
    w.writeUint32(c.remoteId)
    w.writeUint32(dataType)
    w.writeString(data.toOpenArray(off, off + take - 1))
    m.outbox.add(w.toBytes())
    c.remoteWindow -= uint32(take)
    off += take
  m.channels[id] = c
  result = off

proc sendEof*(m: var ChannelMux, id: uint32) =
  var c = m.get(id)
  if c.eofSent:
    return
  var w = initWriter()
  w.writeByte(MsgChannelEof)
  w.writeUint32(c.remoteId)
  m.outbox.add(w.toBytes())
  c.eofSent = true
  m.channels[id] = c

proc sendClose*(m: var ChannelMux, id: uint32) =
  var c = m.get(id)
  if c.closeSent:
    return
  var w = initWriter()
  w.writeByte(MsgChannelClose)
  w.writeUint32(c.remoteId)
  m.outbox.add(w.toBytes())
  c.closeSent = true
  c.state = chClosed
  m.channels[id] = c

proc maybeReap(m: var ChannelMux, id: uint32) =
  ## Drop fully-closed channels (close sent and received).
  let c = m.channels.getOrDefault(id, Channel(state: chClosed, closeSent: true))
  if c.closeSent and c.state == chClosed and id in m.channels:
    m.channels.del(id)

# ── receiver ────────────────────────────────────────────────────────────────

proc replyRequest(m: var ChannelMux, c: Channel, ok: bool) =
  var w = initWriter()
  w.writeByte(if ok: MsgChannelSuccess else: MsgChannelFailure)
  w.writeUint32(c.remoteId)
  m.outbox.add(w.toBytes())

proc feed*(m: var ChannelMux, payload: openArray[byte]): seq[ChanEvent] =
  result = @[]
  if payload.len == 0:
    return
  var r = initReader(payload)
  case r.readByte()
  of MsgChannelOpen:
    if not m.isServer:
      raise newException(SshChannelError, "ssh channel: client got OPEN")
    let typ = r.readStringStr()
    let sender = r.readUint32()
    let win = r.readUint32()
    let maxpkt = r.readUint32()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: OPEN trailing bytes")
    if typ != "session":
      var w = initWriter()
      w.writeByte(MsgChannelOpenFailure)
      w.writeUint32(sender)
      w.writeUint32(OpenUnknownType)
      w.writeString("unsupported channel type: " & typ)
      w.writeString("")
      m.outbox.add(w.toBytes())
      return
    let id = m.nextId
    inc m.nextId
    m.channels[id] = Channel(localId: id, remoteId: sender, hasRemote: true,
      localWindow: DefaultWindow, localMaxPkt: DefaultMaxPacket,
      remoteWindow: win, remoteMaxPkt: maxpkt, state: chOpen)
    var w = initWriter()
    w.writeByte(MsgChannelOpenConfirmation)
    w.writeUint32(sender)
    w.writeUint32(id)
    w.writeUint32(DefaultWindow)
    w.writeUint32(DefaultMaxPacket)
    m.outbox.add(w.toBytes())
    result.add(ChanEvent(kind: cevOpened, localId: id))
  of MsgChannelOpenConfirmation:
    let recipient = r.readUint32()
    var c = m.get(recipient)
    if c.state != chOpening:
      raise newException(SshChannelError, "ssh channel: unexpected CONFIRMATION")
    c.remoteId = r.readUint32()
    c.hasRemote = true
    c.remoteWindow = r.readUint32()
    c.remoteMaxPkt = r.readUint32()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: CONFIRMATION trailing")
    c.state = chOpen
    m.channels[recipient] = c
    result.add(ChanEvent(kind: cevOpened, localId: recipient))
  of MsgChannelOpenFailure:
    let recipient = r.readUint32()
    discard r.readUint32() # reason
    discard r.readStringStr() # description
    discard r.readStringStr() # language
    if recipient in m.channels:
      m.channels.del(recipient)
    result.add(ChanEvent(kind: cevOpenFailure, localId: recipient))
  of MsgChannelWindowAdjust:
    let recipient = r.readUint32()
    let inc = r.readUint32()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: ADJUST trailing bytes")
    var c = m.get(recipient)
    c.remoteWindow += inc
    m.channels[recipient] = c
  of MsgChannelData:
    let recipient = r.readUint32()
    let data = r.readString()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: DATA trailing bytes")
    var c = m.get(recipient)
    if data.len > int(c.localWindow):
      raise newException(SshChannelError, "ssh channel: window exceeded")
    c.localWindow -= uint32(data.len)
    m.channels[recipient] = c
    var w = initWriter()
    w.writeByte(MsgChannelWindowAdjust)
    w.writeUint32(c.remoteId)
    w.writeUint32(uint32(data.len))
    m.outbox.add(w.toBytes())
    result.add(ChanEvent(kind: cevData, localId: recipient, data: data))
  of MsgChannelExtendedData:
    let recipient = r.readUint32()
    let dt = r.readUint32()
    let data = r.readString()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: EXTENDED trailing")
    var c = m.get(recipient)
    if data.len > int(c.localWindow):
      raise newException(SshChannelError, "ssh channel: window exceeded")
    c.localWindow -= uint32(data.len)
    m.channels[recipient] = c
    var w = initWriter()
    w.writeByte(MsgChannelWindowAdjust)
    w.writeUint32(c.remoteId)
    w.writeUint32(uint32(data.len))
    m.outbox.add(w.toBytes())
    result.add(ChanEvent(kind: cevExtendedData, localId: recipient,
                         dataType: dt, data: data))
  of MsgChannelEof:
    let recipient = r.readUint32()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: EOF trailing bytes")
    var c = m.get(recipient)
    c.state = chEofReceived
    m.channels[recipient] = c
    result.add(ChanEvent(kind: cevEof, localId: recipient))
  of MsgChannelClose:
    let recipient = r.readUint32()
    if not r.isExhausted():
      raise newException(SshChannelError, "ssh channel: CLOSE trailing bytes")
    if recipient in m.channels:
      var c = m.channels[recipient]
      if not c.closeSent:
        var w = initWriter()
        w.writeByte(MsgChannelClose)
        w.writeUint32(c.remoteId)
        m.outbox.add(w.toBytes())
        c.closeSent = true
      c.state = chClosed
      m.channels[recipient] = c
      m.maybeReap(recipient)
    result.add(ChanEvent(kind: cevClose, localId: recipient))
  of MsgChannelRequest:
    let recipient = r.readUint32()
    let name = r.readStringStr()
    let wantReply = r.readBool()
    let c = m.get(recipient)
    case name
    of "exec":
      let cmd = r.readStringStr()
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: exec trailing bytes")
      if wantReply:
        m.replyRequest(c, true)
      result.add(ChanEvent(kind: cevExec, localId: recipient, text: cmd))
    of "shell":
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: shell trailing bytes")
      if wantReply:
        m.replyRequest(c, true)
      result.add(ChanEvent(kind: cevShell, localId: recipient))
    of "env":
      let k = r.readStringStr()
      let v = r.readStringStr()
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: env trailing bytes")
      if wantReply:
        m.replyRequest(c, true)
      result.add(ChanEvent(kind: cevEnv, localId: recipient, text: k, text2: v))
    of "pty-req":
      let term = r.readStringStr()
      discard r.readUint32() # width chars
      discard r.readUint32() # height rows
      discard r.readUint32() # width px
      discard r.readUint32() # height px
      discard r.readString() # modes
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: pty trailing bytes")
      if wantReply:
        m.replyRequest(c, true)
      result.add(ChanEvent(kind: cevPty, localId: recipient, text: term))
    of "exit-status":
      let st = r.readUint32()
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: status trailing")
      result.add(ChanEvent(kind: cevExitStatus, localId: recipient, status: st))
    of "exit-signal":
      let signame = r.readStringStr()
      discard r.readBool() # core dumped
      discard r.readStringStr() # message
      discard r.readStringStr() # language
      if not r.isExhausted():
        raise newException(SshChannelError, "ssh channel: signal trailing")
      result.add(ChanEvent(kind: cevExitSignal, localId: recipient, text: signame))
    else:
      if wantReply:
        m.replyRequest(c, false)
  of MsgChannelSuccess:
    let recipient = r.readUint32()
    result.add(ChanEvent(kind: cevRequestOk, localId: recipient))
  of MsgChannelFailure:
    let recipient = r.readUint32()
    result.add(ChanEvent(kind: cevRequestFail, localId: recipient))
  of MsgGlobalRequest:
    # RFC 4254 §4: server announcements like hostkeys-00@openssh.com.
    # Request data is type-specific; without a registry we decline when a
    # reply is wanted and surface the name to the app otherwise.
    let name = r.readStringStr()
    let wantReply = r.readBool()
    if wantReply:
      var w = initWriter()
      w.writeByte(MsgRequestFailure)
      m.outbox.add(w.toBytes())
    result.add(ChanEvent(kind: cevGlobalRequest, text: name))
  of MsgRequestSuccess, MsgRequestFailure:
    # Replies to global requests we never send in MVP; drop.
    discard
  of MsgIgnore, MsgDebug:
    # Transport keepalives; nothing to do.
    discard
  else:
    raise newException(SshChannelError,
      "ssh channel: unexpected message " & $payload[0])
