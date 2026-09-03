# SSH host/user keys: ssh-ed25519 blobs, signatures, authorized_keys lines,
# OpenSSH fingerprints. Crypto via nimcypher true Ed25519 (SHA-512).

import std/base64
import std/sysrand
import std/strutils

import nimcypher/algos/ed25519 as edAlgo
import nimcypher/hash as hashApi

import ./codec

const
  HostKeyEd25519* = "ssh-ed25519"
  EdPubLen* = 32
  EdSigLen* = 64
  EdSeedLen* = 32
  EdSecLen* = 64

type
  SshKeyError* = object of ValueError

  EdKeyPair* = object
    seed*: array[32, byte]   ## keep secret
    seckey*: array[64, byte] ## seed || pubkey, keep secret
    pubkey*: array[32, byte]

proc generateEdKey*(): EdKeyPair =
  let rnd = urandom(32)
  var seed: array[32, byte]
  copyMem(addr seed[0], unsafeAddr rnd[0], 32)
  let (seckey, pubkey) = edAlgo.ed25519KeyPair(seed)
  result = EdKeyPair(seed: seed, seckey: seckey, pubkey: pubkey)

proc edKeyFromSeed*(seed: array[32, byte]): EdKeyPair =
  let (seckey, pubkey) = edAlgo.ed25519KeyPair(seed)
  result = EdKeyPair(seed: seed, seckey: seckey, pubkey: pubkey)

proc edSign*(key: EdKeyPair, message: openArray[byte]): array[64, byte] =
  edAlgo.ed25519Sign(message, key.seckey)

proc edVerify*(pubkey: array[32, byte], message: openArray[byte],
               sig: array[64, byte]): bool =
  edAlgo.ed25519Check(sig, pubkey, message)

# ── SSH wire blobs (RFC 4253 §6.6) ──────────────────────────────────────────

proc encodePubBlob*(pubkey: array[32, byte]): seq[byte] =
  ## string "ssh-ed25519" || string pubkey.
  var w = initWriter()
  w.writeString(HostKeyEd25519)
  w.writeString(pubkey)
  result = w.toBytes()

proc parsePubBlob*(blob: openArray[byte]): array[32, byte] =
  var r = initReader(blob)
  let alg = r.readStringStr()
  if alg != HostKeyEd25519:
    raise newException(SshKeyError, "ssh key: unsupported algorithm " & alg)
  let key = r.readString()
  if key.len != EdPubLen:
    raise newException(SshKeyError, "ssh key: bad ed25519 key length")
  if not r.isExhausted():
    raise newException(SshKeyError, "ssh key: trailing bytes in key blob")
  copyMem(addr result[0], unsafeAddr key[0], EdPubLen)

proc encodeSignature*(sig: array[64, byte]): seq[byte] =
  ## string "ssh-ed25519" || string signature.
  var w = initWriter()
  w.writeString(HostKeyEd25519)
  w.writeString(sig)
  result = w.toBytes()

proc parseSignature*(blob: openArray[byte]): array[64, byte] =
  var r = initReader(blob)
  let alg = r.readStringStr()
  if alg != HostKeyEd25519:
    raise newException(SshKeyError, "ssh key: unsupported signature algorithm")
  let sig = r.readString()
  if sig.len != EdSigLen:
    raise newException(SshKeyError, "ssh key: bad ed25519 signature length")
  if not r.isExhausted():
    raise newException(SshKeyError, "ssh key: trailing bytes in signature")
  copyMem(addr result[0], unsafeAddr sig[0], EdSigLen)

# ── authorized_keys / known_hosts text lines ─────────────────────────────────

proc encodeAuthorizedKeysLine*(pubkey: array[32, byte],
                               comment = ""): string =
  ## "ssh-ed25519 BASE64 [comment]".
  let b64 = base64.encode(encodePubBlob(pubkey))
  if comment.len > 0:
    result = HostKeyEd25519 & " " & b64 & " " & comment
  else:
    result = HostKeyEd25519 & " " & b64

proc parseAuthorizedKeysLine*(line: string): tuple[pubkey: array[32, byte],
    comment: string] =
  ## Parses "alg base64 [comment]"; ignores options? No: options (with spaces)
  ## are out of scope for MVP — line must start with the algorithm name.
  let s = line.strip()
  if s.len == 0 or s[0] == '#':
    raise newException(SshKeyError, "ssh key: empty or comment line")
  let parts = s.split(' ', maxsplit = 2)
  if parts.len < 2 or parts[0] != HostKeyEd25519:
    raise newException(SshKeyError, "ssh key: unsupported authorized_keys algorithm")
  let blob = base64.decode(parts[1])
  if blob.len == 0:
    raise newException(SshKeyError, "ssh key: empty key blob")
  result.pubkey = parsePubBlob(blob.toOpenArrayByte(0, blob.high))
  result.comment = if parts.len > 2: parts[2] else: ""

proc fingerprintSha256*(pubkey: array[32, byte]): string =
  ## OpenSSH-style "SHA256:<base64-nopad>".
  let digest = hashApi.sha256(encodePubBlob(pubkey))
  var b64 = base64.encode(digest)
  while b64.len > 0 and b64[^1] == '=':
    b64.setLen(b64.len - 1)
  result = "SHA256:" & b64
