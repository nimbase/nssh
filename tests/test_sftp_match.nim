import std/os
import std/unittest

import nssh/sftp
import nssh/sftp_match

let alice = Identity(user: "alice", groups: @["staff", "dev"],
  home: "/home/alice")
let bob = Identity(user: "bob", groups: @["ro"], home: "/home/bob")

let resolver = newStaticResolver([("alice", alice), ("bob", bob)])

proc rules(): seq[MatchRule] =
  @[
    MatchRule(users: @["bob"], root: "/srv/ro/%u", readOnly: true,
      umask: 0o022'u32, startDir: "/"),
    MatchRule(groups: @["dev"], root: "/srv/dev/%u", readOnly: false,
      umask: 0o002'u32, startDir: "/"),
    MatchRule(root: "/srv/fallback/%u", readOnly: false,
      umask: 0o022'u32, startDir: "/"),
  ]

test "user rule wins for bob (read-only)":
  let r = matchRule(rules(), resolver("bob"))
  check r.readOnly
  check r.root == "/srv/ro/%u"

test "group rule matches alice via dev":
  let r = matchRule(rules(), resolver("alice"))
  check not r.readOnly
  check r.root == "/srv/dev/%u"
  check r.umask == 0o002'u32

test "fallback rule catches others":
  let mallory = Identity(user: "mallory", groups: @["other"],
    home: "/home/mallory")
  let r = matchRule(rules(), mallory)
  check r.root == "/srv/fallback/%u"

test "unknown user rejected by resolver":
  expect SftpError:
    discard resolver("mallory")

test "no match raises permission denied":
  let only = @[MatchRule(users: @["alice"], root: "/srv/a",
    umask: 0o022'u32, startDir: "/")]
  try:
    discard matchRule(only, bob)
    check false
  except SftpError as e:
    check e.code == FxPermissionDenied

test "wildcard patterns match user and group":
  let wild = @[MatchRule(users: @["adm*"], groups: @["*ops"],
    root: "/srv/w", umask: 0o022'u32, startDir: "/")]
  let op = Identity(user: "admin1", groups: @["netops"], home: "/h")
  check matchRule(wild, op).root == "/srv/w"
  let no = Identity(user: "admin1", groups: @["dev"], home: "/h")
  expect SftpError:
    discard matchRule(wild, no)

test "backendFor expands root and wraps read-only":
  let root = getTempDir() / "nssh-match"
  createDir(root / "srv" / "ro" / "bob")
  let rule = MatchRule(users: @["bob"],
    root: root / "srv" / "ro" / "%u", readOnly: true,
    umask: 0o022'u32, startDir: "/")
  check ruleMatches(rule, resolver("bob"))
  let b = backendFor(rule, resolver("bob"))
  check b of ReadOnlyBackend
  let ro = ReadOnlyBackend(b)
  check OsBackend(ro.inner).root ==
    (root / "srv" / "ro" / "bob").normalizedPath()
  var s = serverFor(rule, resolver("bob"))
  check s.denyTypes == {}
  removeDir(root)

test "denyTypes flow into server":
  var rule = defaultMatchRule()
  rule.root = getTempDir()
  rule.denyTypes = {SshFxpRemove}
  let s = serverFor(rule, alice)
  check SshFxpRemove in s.denyTypes

template expectFx(want: uint32, body: untyped) =
  try:
    body
    check false
  except SftpError as e:
    check e.code == want

test "users are jailed to their own roots":
  # alice and bob get sibling roots; neither `..` nor symlinks let
  # one reach the other's files. Enforcement is the per-channel
  # backend built from the matched rule (the server runs as one uid,
  # so OS permissions do not separate users).
  let base = getTempDir() / "nssh-match-jail"
  createDir(base / "alice")
  createDir(base / "bob")
  writeFile(base / "bob" / "secret.txt", "bob-secret")
  let mkRule = proc(u: string): MatchRule =
    MatchRule(users: @[u], root: base / "%u", readOnly: false,
      umask: 0o022'u32, startDir: "/")
  let ab = backendFor(mkRule("alice"), resolver("alice"))
  # lexical escape attempt
  expectFx FxPermissionDenied:
    discard ab.stat("/../bob/secret.txt")
  # relative escape attempt
  expectFx FxPermissionDenied:
    discard ab.stat("../../bob/secret.txt")
  when defined(posix):
    # symlink planted in alice's root pointing at bob's file
    ab.symlink("/hop", base / "bob" / "secret.txt")
    expectFx FxNoSuchFile:
      discard ab.stat("/hop")
    expectFx FxNoSuchFile:
      discard ab.openFile("/hop", OpenRead, SftpAttrs())
    check readFile(base / "bob" / "secret.txt") == "bob-secret"
  removeDir(base)

test "escaping startDir fails at backendFor, not at serve time":
  let base = getTempDir() / "nssh-match-start"
  createDir(base)
  let bad = MatchRule(users: @["alice"], root: base, readOnly: false,
    umask: 0o022'u32, startDir: "/../..")
  expectFx FxPermissionDenied:
    discard backendFor(bad, alice)
  # startDir inside the root flows into the backend
  let good = MatchRule(users: @["alice"], root: base, readOnly: false,
    umask: 0o022'u32, startDir: "/sub")
  let b = backendFor(good, alice)
  check OsBackend(b).startDir == normalizedPath(base / "sub")
  removeDir(base)

test "readOnly backend still jails link following":
  when defined(posix):
    let base = getTempDir() / "nssh-match-ro"
    createDir(base / "root")
    let outside = base / "outside"
    createDir(outside)
    writeFile(outside / "secret.txt", "s")
    let rule = MatchRule(users: @["bob"], root: base / "root",
      readOnly: true, umask: 0o022'u32, startDir: "/")
    let b = backendFor(rule, bob)
    check b of ReadOnlyBackend
    # read-only denies the write, and the read side stays jailed too
    expectFx FxPermissionDenied:
      discard b.openFile("/new.txt", OpenWrite or OpenCreat,
        SftpAttrs())
    expectFx FxPermissionDenied:
      discard b.stat("/../outside/secret.txt")
    removeDir(base)
  else:
    skip()

when defined(posix):
  test "systemIdentity resolves current user":
    let who = getEnv("USER", getEnv("LOGNAME", ""))
    if who.len == 0:
      skip()
    else:
      let id = systemIdentity(who)
      check id.user == who
      check id.home.len > 0
