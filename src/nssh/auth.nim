# SSH user authentication (RFC 4252) + service requests (RFC 4253 §10).
#
# Pure message codecs plus small client/server state machines in the same
# outbox style as session/channel: feed payloads, take response payloads,
# send them with `session.sendPayload`.

import std/strutils

import ./codec
import ./hostkeys

const
  MsgServiceRequest* = 5'u8
  MsgServiceAccept* = 6'u8
  MsgUserauthRequest* = 50'u8
  MsgUserauthFailure* = 51'u8
  MsgUserauthSuccess* = 52'u8
  MsgUserauthBanner* = 53'u8
  MsgUserauthPkOk* = 60'u8

  AuthService* = "ssh-userauth"
  ConnService* = "ssh-connection"
  MethodNone* = "none"
  MethodPublickey* = "publickey"
  MethodPassword* = "password"

type
  SshAuthError* = object of ValueError

# ── codecs ──────────────────────────────────────────────────────────────────

proc buildServiceRequest*(service: string): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgServiceRequest)
  w.writeString(service)
  result = w.toBytes()

proc parseServiceRequest*(payload: openArray[byte]): string =
  var r = initReader(payload)
  if r.readByte() != MsgServiceRequest:
    raise newException(SshAuthError, "ssh auth: not a SERVICE_REQUEST")
  result = r.readStringStr()
  if not r.isExhausted():
    raise newException(SshAuthError, "ssh auth: SERVICE_REQUEST trailing bytes")

proc buildServiceAccept*(service: string): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgServiceAccept)
  w.writeString(service)
  result = w.toBytes()

proc parseServiceAccept*(payload: openArray[byte]): string =
  var r = initReader(payload)
  if r.readByte() != MsgServiceAccept:
    raise newException(SshAuthError, "ssh auth: not a SERVICE_ACCEPT")
  result = r.readStringStr()
  if not r.isExhausted():
    raise newException(SshAuthError, "ssh auth: SERVICE_ACCEPT trailing bytes")

proc buildUserauthNone*(user, service: string): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthRequest)
  w.writeString(user)
  w.writeString(service)
  w.writeString(MethodNone)
  result = w.toBytes()

proc buildUserauthPubkey*(user, alg: string, blob: openArray[byte],
                          sigBlob: seq[byte] = @[], signed = false): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthRequest)
  w.writeString(user)
  w.writeString(ConnService)
  w.writeString(MethodPublickey)
  w.writeBool(signed)
  w.writeString(alg)
  w.writeString(blob)
  if signed:
    w.writeString(sigBlob)
  result = w.toBytes()

proc buildUserauthPassword*(user, password: string): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthRequest)
  w.writeString(user)
  w.writeString(ConnService)
  w.writeString(MethodPassword)
  w.writeBool(false)
  w.writeString(password)
  result = w.toBytes()

type
  UserauthRequest* = object
    user*: string
    service*: string
    meth*: string
    isSigned*: bool        ## publickey: signature present
    alg*: string           ## publickey
    blob*: seq[byte]       ## publickey key blob
    sigBlob*: seq[byte]    ## publickey signature blob (if signed)
    password*: string      ## password

proc parseUserauthRequest*(payload: openArray[byte]): UserauthRequest =
  var r = initReader(payload)
  if r.readByte() != MsgUserauthRequest:
    raise newException(SshAuthError, "ssh auth: not a USERAUTH_REQUEST")
  result.user = r.readStringStr()
  result.service = r.readStringStr()
  result.meth = r.readStringStr()
  case result.meth
  of MethodNone:
    if not r.isExhausted():
      raise newException(SshAuthError, "ssh auth: none trailing bytes")
  of MethodPublickey:
    result.isSigned = r.readBool()
    result.alg = r.readStringStr()
    result.blob = r.readString()
    if result.isSigned:
      result.sigBlob = r.readString()
    if not r.isExhausted():
      raise newException(SshAuthError, "ssh auth: publickey trailing bytes")
  of MethodPassword:
    if r.readBool():
      raise newException(SshAuthError, "ssh auth: password change unsupported")
    result.password = r.readStringStr()
    if not r.isExhausted():
      raise newException(SshAuthError, "ssh auth: password trailing bytes")
  else:
    raise newException(SshAuthError, "ssh auth: unsupported method " & result.meth)

proc buildPubkeyOk*(alg: string, blob: openArray[byte]): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthPkOk)
  w.writeString(alg)
  w.writeString(blob)
  result = w.toBytes()

proc parsePubkeyOk*(payload: openArray[byte]): tuple[alg: string, blob: seq[byte]] =
  var r = initReader(payload)
  if r.readByte() != MsgUserauthPkOk:
    raise newException(SshAuthError, "ssh auth: not a PK_OK")
  result.alg = r.readStringStr()
  result.blob = r.readString()
  if not r.isExhausted():
    raise newException(SshAuthError, "ssh auth: PK_OK trailing bytes")

proc buildFailure*(methods: openArray[string], partial = false): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthFailure)
  w.writeNameList(methods)
  w.writeBool(partial)
  result = w.toBytes()

proc parseFailure*(payload: openArray[byte]): tuple[methods: seq[string], partial: bool] =
  var r = initReader(payload)
  if r.readByte() != MsgUserauthFailure:
    raise newException(SshAuthError, "ssh auth: not a FAILURE")
  result.methods = r.readNameList()
  result.partial = r.readBool()
  if not r.isExhausted():
    raise newException(SshAuthError, "ssh auth: FAILURE trailing bytes")

proc buildBanner*(message, lang = ""): seq[byte] =
  var w = initWriter()
  w.writeByte(MsgUserauthBanner)
  w.writeString(message)
  w.writeString(lang)
  result = w.toBytes()

proc signData*(sessionId: openArray[byte], user, alg: string,
               blob: openArray[byte]): seq[byte] =
  ## Exact bytes covered by a publickey signature (RFC 4252 §7).
  var w = initWriter()
  w.writeString(sessionId)
  w.writeByte(MsgUserauthRequest)
  w.writeString(user)
  w.writeString(ConnService)
  w.writeString(MethodPublickey)
  w.writeBool(true)
  w.writeString(alg)
  w.writeString(blob)
  result = w.toBytes()

# ── client ──────────────────────────────────────────────────────────────────

type
  AuthClientEventKind* = enum
    acWaiting, acSuccess, acFailed, acBanner

  AuthClientEvent* = object
    kind*: AuthClientEventKind
    message*: string

  AuthClient* = object
    user*: string
    sessionId*: array[32, byte]
    key*: EdKeyPair
    hasKey*: bool
    password*: string
    hasPassword*: bool
    triedNone*: bool
    triedUnsigned*: bool
    triedSigned*: bool
    triedPassword*: bool
    done*: bool
    outbox*: seq[seq[byte]]

proc initAuthClient*(user: string, sessionId: array[32, byte],
                     key = EdKeyPair(), password = ""): AuthClient =
  result.user = user
  result.sessionId = sessionId
  result.key = key
  result.hasKey = key.pubkey != default(array[32, byte])
  result.password = password
  result.hasPassword = password.len > 0

proc authStart*(c: var AuthClient) =
  c.outbox.add(buildServiceRequest(AuthService))

proc takeOutbox*(c: var AuthClient): seq[seq[byte]] =
  result = c.outbox
  c.outbox = @[]

proc authFeedInner(c: var AuthClient, payload: openArray[byte]): AuthClientEvent =
  ## Drive one inbound message. Queues responses; reports terminal states.
  if payload.len == 0:
    return AuthClientEvent(kind: acWaiting)
  case payload[0]
  of MsgServiceAccept:
    if parseServiceAccept(payload) != AuthService:
      return AuthClientEvent(kind: acFailed, message: "wrong service accepted")
    c.outbox.add(buildUserauthNone(c.user, ConnService))
    c.triedNone = true
    return AuthClientEvent(kind: acWaiting)
  of MsgUserauthSuccess:
    c.done = true
    return AuthClientEvent(kind: acSuccess)
  of MsgUserauthFailure:
    let f = parseFailure(payload)
    if MethodPublickey in f.methods and c.hasKey and not c.triedUnsigned:
      c.outbox.add(buildUserauthPubkey(c.user, HostKeyEd25519,
        encodePubBlob(c.key.pubkey)))
      c.triedUnsigned = true
      return AuthClientEvent(kind: acWaiting)
    if MethodPublickey in f.methods and c.hasKey and not c.triedSigned:
      let blob = encodePubBlob(c.key.pubkey)
      let sig = encodeSignature(edSign(c.key, signData(c.sessionId, c.user,
        HostKeyEd25519, blob)))
      c.outbox.add(buildUserauthPubkey(c.user, HostKeyEd25519, blob, sig, true))
      c.triedSigned = true
      return AuthClientEvent(kind: acWaiting)
    if MethodPassword in f.methods and c.hasPassword and not c.triedPassword:
      c.outbox.add(buildUserauthPassword(c.user, c.password))
      c.triedPassword = true
      return AuthClientEvent(kind: acWaiting)
    return AuthClientEvent(kind: acFailed,
      message: "no usable auth method (server allows: " & f.methods.join(",") & ")")
  of MsgUserauthPkOk:
    let (alg, _) = parsePubkeyOk(payload)
    if alg != HostKeyEd25519 or not c.hasKey or c.triedSigned:
      return AuthClientEvent(kind: acFailed, message: "unexpected PK_OK")
    let blob = encodePubBlob(c.key.pubkey)
    let sig = encodeSignature(edSign(c.key, signData(c.sessionId, c.user,
      HostKeyEd25519, blob)))
    c.outbox.add(buildUserauthPubkey(c.user, HostKeyEd25519, blob, sig, true))
    c.triedSigned = true
    return AuthClientEvent(kind: acWaiting)
  of MsgUserauthBanner:
    return AuthClientEvent(kind: acBanner, message: "banner")
  else:
    return AuthClientEvent(kind: acFailed,
      message: "unexpected auth message " & $payload[0])

proc authFeed*(c: var AuthClient, payload: openArray[byte]): AuthClientEvent =
  ## Drive one inbound message. Raises only SshAuthError on malformed input.
  try:
    result = authFeedInner(c, payload)
  except ValueError as e:
    raise newException(SshAuthError, "ssh auth: " & e.msg)

# ── server ──────────────────────────────────────────────────────────────────

type
  AuthServerEventKind* = enum
    asWaiting, asSuccess, asAttempt

  AuthServerEvent* = object
    kind*: AuthServerEventKind
    user*: string
    meth*: string
    message*: string

  AuthServer* = object
    sessionId*: array[32, byte]
    checkKey*: proc(user, alg: string, blob: seq[byte]): bool {.closure.}
    checkPassword*: proc(user, password: string): bool {.closure.}
    serviceOk*: bool
    user*: string
    done*: bool
    outbox*: seq[seq[byte]]

proc initAuthServer*(sessionId: array[32, byte],
                     checkKey: proc(user, alg: string, blob: seq[byte]): bool {.closure.} = nil,
                     checkPassword: proc(user, password: string): bool {.closure.} = nil): AuthServer =
  result.sessionId = sessionId
  result.checkKey = checkKey
  result.checkPassword = checkPassword

proc takeOutbox*(s: var AuthServer): seq[seq[byte]] =
  result = s.outbox
  s.outbox = @[]

proc failMethods(s: AuthServer): seq[string] =
  result = @[]
  if s.checkKey != nil:
    result.add(MethodPublickey)
  if s.checkPassword != nil:
    result.add(MethodPassword)

proc authFeedInner(s: var AuthServer, payload: openArray[byte]): AuthServerEvent =
  ## Inner dispatch; raises SshAuthError/SshCodecError/SshKeyError.
  if payload.len == 0:
    return AuthServerEvent(kind: asWaiting)
  case payload[0]
  of MsgServiceRequest:
    if parseServiceRequest(payload) == AuthService:
      s.serviceOk = true
      s.outbox.add(buildServiceAccept(AuthService))
      return AuthServerEvent(kind: asWaiting)
    return AuthServerEvent(kind: asAttempt, message: "unknown service")
  of MsgUserauthRequest:
    if not s.serviceOk:
      return AuthServerEvent(kind: asAttempt, message: "auth before service")
    if s.done:
      return AuthServerEvent(kind: asWaiting)
    let req = parseUserauthRequest(payload)
    if req.service != ConnService:
      s.outbox.add(buildFailure(s.failMethods()))
      return AuthServerEvent(kind: asAttempt, meth: req.meth, message: "bad service")
    case req.meth
    of MethodNone:
      s.outbox.add(buildFailure(s.failMethods()))
      return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth)
    of MethodPublickey:
      if req.alg != HostKeyEd25519:
        s.outbox.add(buildFailure(s.failMethods()))
        return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth,
                               message: "unsupported key alg")
      if s.checkKey == nil or not s.checkKey(req.user, req.alg, req.blob):
        s.outbox.add(buildFailure(s.failMethods()))
        return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth,
                               message: "key not authorized")
      if not req.isSigned:
        s.outbox.add(buildPubkeyOk(req.alg, req.blob))
        return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth)
      let pub = parsePubBlob(req.blob)
      let sig = parseSignature(req.sigBlob)
      if edVerify(pub, signData(s.sessionId, req.user, req.alg, req.blob), sig):
        s.done = true
        s.user = req.user
        s.outbox.add(@[MsgUserauthSuccess])
        return AuthServerEvent(kind: asSuccess, user: req.user, meth: req.meth)
      s.outbox.add(buildFailure(s.failMethods()))
      return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth,
                             message: "bad signature")
    of MethodPassword:
      if s.checkPassword != nil and s.checkPassword(req.user, req.password):
        s.done = true
        s.user = req.user
        s.outbox.add(@[MsgUserauthSuccess])
        return AuthServerEvent(kind: asSuccess, user: req.user, meth: req.meth)
      s.outbox.add(buildFailure(s.failMethods()))
      return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth,
                             message: "bad password")
    else:
      s.outbox.add(buildFailure(s.failMethods()))
      return AuthServerEvent(kind: asAttempt, user: req.user, meth: req.meth)
  else:
    return AuthServerEvent(kind: asAttempt, message: "unexpected message")

proc authFeed*(s: var AuthServer, payload: openArray[byte]): AuthServerEvent =
  ## Drive one inbound message. Raises only SshAuthError on malformed input.
  try:
    result = authFeedInner(s, payload)
  except ValueError as e:
    raise newException(SshAuthError, "ssh auth: " & e.msg)
