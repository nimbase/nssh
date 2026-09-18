# SSH known_hosts: parse, match, persist ssh-ed25519 pins.
#
# File format (OpenSSH CLIENT.INPUT): one line per key:
#   hosts SP alg SP base64 [SP comment]
# where hosts is a comma-separated list of host patterns, each either
# `host`, `host,host2`, `[host]:port`, or hashed `|1|salt|hash`.
# MVP scope: plain hosts + `[host]:port` + `ssh-ed25519` only. Hashed
# entries, markers (@revoked/@cert-authority), and other key types raise
# a descriptive error instead of being silently skipped.

import std/base64
import std/strutils
import std/os

import ./hostkeys
import ./session

type
  KnownHostsError* = object of ValueError

proc parseHostPattern*(pat: string): tuple[host: string, port: int] =
  ## `example.com` -> ("example.com", -1); `[example.com]:2222` -> host+port.
  let p = pat.strip()
  if p.len == 0:
    raise newException(KnownHostsError, "ssh known_hosts: empty host pattern")
  if p[0] == '[':
    let closeIdx = p.find(']')
    if closeIdx < 0:
      raise newException(KnownHostsError, "ssh known_hosts: bad [host]:port " & p)
    let host = p[1 ..< closeIdx]
    let rest = p[closeIdx + 1 .. ^1]
    if rest.len == 0:
      return (host, -1)
    if rest.len < 2 or rest[0] != ':':
      raise newException(KnownHostsError, "ssh known_hosts: bad [host]:port " & p)
    try:
      return (host, parseInt(rest[1 .. ^1]))
    except ValueError:
      raise newException(KnownHostsError, "ssh known_hosts: bad port " & p)
  if p.startsWith("|1|") or p.startsWith("|"):
    raise newException(KnownHostsError,
      "ssh known_hosts: hashed hosts unsupported, unhash to use")
  if p.startsWith("@"):
    raise newException(KnownHostsError,
      "ssh known_hosts: markers unsupported: " & p)
  return (p, -1)

proc parseKnownHostsLine*(line: string): seq[KnownHostEntry] =
  ## Expand one line into entries (one per host pattern). Raises on
  ## empty/comment, hashed hosts, markers, or non-ed25519 algorithms.
  result = @[]
  let s = line.strip()
  if s.len == 0 or s[0] == '#':
    raise newException(KnownHostsError, "ssh known_hosts: empty or comment line")
  let parts = s.splitWhitespace(maxsplit = 3)
  if parts.len < 3:
    raise newException(KnownHostsError, "ssh known_hosts: bad line: " & line)
  if parts[0].startsWith("@"):
    raise newException(KnownHostsError,
      "ssh known_hosts: markers unsupported: " & parts[0])
  if parts[1] != HostKeyEd25519:
    raise newException(KnownHostsError,
      "ssh known_hosts: unsupported algorithm " & parts[1])
  let blob =
    try:
      base64.decode(parts[2])
    except ValueError as e:
      raise newException(KnownHostsError, "ssh known_hosts: bad base64: " & e.msg)
  if blob.len == 0:
    raise newException(KnownHostsError, "ssh known_hosts: empty key blob")
  let pubkey = parsePubBlob(blob.toOpenArrayByte(0, blob.high))
  for pat in parts[0].split(','):
    let (host, port) = parseHostPattern(pat.strip())
    result.add(KnownHostEntry(host: host, port: port, alg: HostKeyEd25519,
      pubkey: pubkey))

proc loadKnownHosts*(path: string): seq[KnownHostEntry] =
  ## Load a known_hosts file, skipping blanks/comments, failing on
  ## malformed data lines (fail-closed: never silently accept).
  result = @[]
  if not fileExists(path):
    return @[]
  for line in readFile(path).splitLines():
    let s = line.strip()
    if s.len == 0 or s[0] == '#':
      continue
    for e in parseKnownHostsLine(s):
      result.add(e)

proc matchKnownHostEntry*(entries: openArray[KnownHostEntry], host: string,
    port: int, pubkey: array[32, byte]): bool =
  for e in entries:
    if e.alg != HostKeyEd25519:
      continue
    if e.pubkey != pubkey:
      continue
    if e.port != -1 and port != 0 and e.port != port:
      continue
    if e.host.len > 0 and host.len > 0 and e.host != host:
      continue
    return true
  return false

proc encodeKnownHostsLine*(host: string, port: int,
    pubkey: array[32, byte]): string =
  ## `host ssh-ed25519 BASE64` or `[host]:port ssh-ed25519 BASE64`.
  let b64 = base64.encode(encodePubBlob(pubkey))
  let h = if port > 0 and port != 22: "[" & host & "]:" & $port else: host
  result = h & " " & HostKeyEd25519 & " " & b64

proc appendKnownHost*(path: string, host: string, port: int,
    pubkey: array[32, byte]) =
  ## Append one pin, creating parent dirs. Caller should have verified
  ## out-of-band (TOFU prompt / fingerprint check) before calling.
  let (dir, _) = splitPath(path)
  if dir.len > 0:
    createDir(dir)
  var f = open(path, fmAppend)
  defer: f.close()
  f.writeLine(encodeKnownHostsLine(host, port, pubkey))
