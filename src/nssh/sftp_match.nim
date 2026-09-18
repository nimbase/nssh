# OpenSSH-like authorization for the SFTP subsystem.
#
# Identity (user + groups + home) is resolved per authenticated connection
# (`AuthServer.user` feeds the resolver), then first-match-wins `MatchRule`
# list maps the identity to a sandboxed backend — the equivalent of
# sshd_config `Match User/Group` + `ChrootDirectory` + `ForceCommand
# internal-sftp`, with `sftp-server -R/-u/-d/-P` folded into each rule.

import std/strutils
import std/tables

import nssh/sftp

when defined(posix):
  import std/posix

type
  Identity* = object
    user*: string
    groups*: seq[string] ## supplementary + primary groups, primary first
    home*: string

  IdentityResolver* = proc(user: string): Identity {.closure.}
    ## Resolve an authenticated username. Raises SftpError
    ## (FxPermissionDenied) for unknown users.

  MatchRule* = object
    ## One Match block. Empty `users`/`groups` means "any". Patterns
    ## support `*` and `?` wildcards (OpenSSH PATTERN matching).
    users*: seq[string]
    groups*: seq[string]
    root*: string  ## may contain %u (user), %h (home), %g (primary group)
    readOnly*: bool
    umask*: uint32
    startDir*: string
    denyTypes*: set[byte] ## request types rejected as OpUnsupported

proc defaultMatchRule*(): MatchRule =
  MatchRule(umask: 0o022'u32, startDir: "/")

proc globMatch(pattern, s: string): bool =
  ## `*`/`?` matcher (case-sensitive, OpenSSH-style).
  var px = 0
  var sx = 0
  var star = -1
  var match = 0
  while sx < s.len:
    if px < pattern.len and
        (pattern[px] == '?' or pattern[px] == s[sx]):
      inc px
      inc sx
    elif px < pattern.len and pattern[px] == '*':
      star = px
      match = sx
      inc px
    elif star != -1:
      px = star + 1
      inc match
      sx = match
    else:
      return false
  while px < pattern.len and pattern[px] == '*':
    inc px
  result = px == pattern.len

proc ruleMatches*(rule: MatchRule, id: Identity): bool =
  ## True when this rule applies to the identity (users AND groups).
  if rule.users.len > 0:
    var ok = false
    for p in rule.users:
      if globMatch(p, id.user):
        ok = true
        break
    if not ok:
      return false
  if rule.groups.len > 0:
    var ok = false
    for g in id.groups:
      for p in rule.groups:
        if globMatch(p, g):
          ok = true
          break
      if ok:
        break
    if not ok:
      return false
  result = true

proc expandRoot(root: string, id: Identity): string =
  var primary = ""
  if id.groups.len > 0:
    primary = id.groups[0]
  result = root.replace("%u", id.user).replace("%h", id.home).replace("%g",
      primary)

proc matchRule*(rules: openArray[MatchRule], id: Identity): MatchRule =
  ## First-match-wins, like sshd_config Match blocks. Raises SftpError
  ## (FxPermissionDenied) when nothing matches — the app declines the
  ## subsystem request in that case.
  for r in rules:
    if ruleMatches(r, id):
      return r
  var e = newException(SftpError, "no Match rule for user: " & id.user)
  e.code = FxPermissionDenied
  raise e

proc backendFor*(rule: MatchRule, id: Identity): SftpBackend =
  ## Build the sandboxed backend for a matched rule.
  let b = newOsBackend(expandRoot(rule.root, id), rule.umask)
  if rule.readOnly:
    result = newReadOnlyBackend(b)
  else:
    result = b

proc serverFor*(rule: MatchRule, id: Identity,
    maxVersion = SftpVersion3): SftpServer =
  ## Convenience: matched rule straight to a running SFTP server.
  result = initSftpServer(backendFor(rule, id), maxVersion)
  result.denyTypes = rule.denyTypes

# ── resolvers ─────────────────────────────────────────────────────────────────

proc newStaticResolver*(entries: openArray[(string, Identity)]):
    IdentityResolver =
  ## Fixed user table (tests, virtual users).
  let tab = entries.toTable()
  result = proc(user: string): Identity {.closure.} =
    if user notin tab:
      var e = newException(SftpError, "unknown user: " & user)
      e.code = FxPermissionDenied
      raise e
    tab[user]

proc systemIdentity*(user: string): Identity =
  ## Resolve from the OS account database (passwd + groups).
  when defined(posix):
    let pw = getpwnam(user.cstring)
    if pw == nil:
      var e = newException(SftpError, "unknown user: " & user)
      e.code = FxPermissionDenied
      raise e
    result.user = user
    result.home = $pw.pw_dir
    var groups: seq[string] = @[]
    let primary = getgrgid(pw.pw_gid)
    if primary != nil:
      groups.add($primary.gr_name)
    setgrent()
    while true:
      let g = getgrent()
      if g == nil:
        break
      var member = false
      if g.gr_mem != nil:
        var i = 0
        while g.gr_mem[i] != nil:
          if $g.gr_mem[i] == user:
            member = true
            break
          inc i
      if member and $g.gr_name notin groups:
        groups.add($g.gr_name)
    endgrent()
    result.groups = groups
  else:
    var e = newException(SftpError,
      "system identities not supported on this platform")
    e.code = FxOpUnsupported
    raise e
