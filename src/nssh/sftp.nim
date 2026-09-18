# SFTP file transfer subsystem, server side (draft-ietf-secsh-filexfer-02,
# protocol version 3 — the version OpenSSH implements).
#
# Same outbox style as session/auth/channel: feed channel DATA bytes,
# take complete SFTP response packets, send them with `mux.sendData`.
# SFTP packets may split across channel messages, so the server keeps a
# reassembly buffer.
#
# Filesystem access goes through the `SftpBackend` concept below. Apps
# plug any backend (the `OsBackend` here serves a sandboxed root from
# the local disk); user/group Match rules live one layer up.

import std/os
import std/algorithm
import std/strutils
import std/tables
import std/times

import nssh/codec

when defined(posix):
  import std/posix

type
  SftpError* = object of CatchableError
    ## Backend failure carrying an SSH_FX_* status code.
    code*: uint32

const
  # Packet types (filexfer-02 §4..§7).
  SshFxpInit* = 1'u8
  SshFxpVersion* = 2'u8
  SshFxpOpen* = 3'u8
  SshFxpClose* = 4'u8
  SshFxpRead* = 5'u8
  SshFxpWrite* = 6'u8
  SshFxpLstat* = 7'u8
  SshFxpFstat* = 8'u8
  SshFxpSetstat* = 9'u8
  SshFxpFsetstat* = 10'u8
  SshFxpOpendir* = 11'u8
  SshFxpReaddir* = 12'u8
  SshFxpRemove* = 13'u8
  SshFxpMkdir* = 14'u8
  SshFxpRmdir* = 15'u8
  SshFxpRealpath* = 16'u8
  SshFxpStat* = 17'u8
  SshFxpRename* = 18'u8
  SshFxpReadlink* = 19'u8
  SshFxpSymlink* = 20'u8
  SshFxpStatus* = 101'u8
  SshFxpHandle* = 102'u8
  SshFxpData* = 103'u8
  SshFxpName* = 104'u8
  SshFxpAttrs* = 105'u8

  # Status codes (filexfer-02 §7).
  FxOk* = 0'u32
  FxEof* = 1'u32
  FxNoSuchFile* = 2'u32
  FxPermissionDenied* = 3'u32
  FxFailure* = 4'u32
  FxBadMessage* = 5'u32
  FxNoConnection* = 6'u32
  FxConnectionLost* = 7'u32
  FxOpUnsupported* = 8'u32

  # ATTRS flags (filexfer-02 §5).
  AttrSize* = 0x00000001'u32
  AttrUidgid* = 0x00000002'u32
  AttrPermissions* = 0x00000004'u32
  AttrAcmodtime* = 0x00000008'u32

  # OPEN pflags (filexfer-02 §6.3).
  OpenRead* = 0x00000001'u32
  OpenWrite* = 0x00000002'u32
  OpenAppend* = 0x00000004'u32
  OpenCreat* = 0x00000008'u32
  OpenTrunc* = 0x00000010'u32
  OpenExcl* = 0x00000020'u32

  SftpVersion3* = 3'u32
  MaxSftpPacket* = 262144 ## cap on one SFTP packet (length prefix value).
  MaxSftpRead* = 262144   ## cap on a single READ length.
  ReaddirChunk* = 64      ## NAME entries per READDIR response.

type
  SftpAttrs* = object
    ## File attributes; `mask` says which fields are valid (ATTRS flags).
    mask*: uint32
    size*: uint64
    uid*: uint32
    gid*: uint32
    permissions*: uint32
    atime*: uint32
    mtime*: uint32

  SftpName* = object
    filename*: string
    longname*: string
    attrs*: SftpAttrs

proc sftpError(code: uint32, msg: string): ref SftpError =
  var e = newException(SftpError, msg)
  e.code = code
  result = e

# ── ATTRS codec ───────────────────────────────────────────────────────────────

proc readAttrs*(r: var Reader): SftpAttrs =
  ## Parse an ATTRS struct (v3 flags format).
  result.mask = r.readUint32()
  if (result.mask and AttrSize) != 0:
    result.size = r.readUint64()
  if (result.mask and AttrUidgid) != 0:
    result.uid = r.readUint32()
    result.gid = r.readUint32()
  if (result.mask and AttrPermissions) != 0:
    result.permissions = r.readUint32()
  if (result.mask and AttrAcmodtime) != 0:
    result.atime = r.readUint32()
    result.mtime = r.readUint32()

proc writeAttrs*(w: var Writer, a: SftpAttrs) =
  w.writeUint32(a.mask)
  if (a.mask and AttrSize) != 0:
    w.writeUint64(a.size)
  if (a.mask and AttrUidgid) != 0:
    w.writeUint32(a.uid)
    w.writeUint32(a.gid)
  if (a.mask and AttrPermissions) != 0:
    w.writeUint32(a.permissions)
  if (a.mask and AttrAcmodtime) != 0:
    w.writeUint32(a.atime)
    w.writeUint32(a.mtime)

proc fullAttrs*(size: uint64, uid, gid, permissions, atime,
    mtime: uint32): SftpAttrs =
  SftpAttrs(mask: AttrSize or AttrUidgid or AttrPermissions or AttrAcmodtime,
    size: size, uid: uid, gid: gid, permissions: permissions,
    atime: atime, mtime: mtime)

proc formatLongname*(name: string, a: SftpAttrs): string =
  ## ls -l style longname for NAME responses (best effort from attrs).
  var kind = '-'
  var perms = a.permissions and 0o7777'u32
  if (a.permissions and 0o040000'u32) != 0:
    kind = 'd'
  elif (a.permissions and 0o120000'u32) != 0:
    kind = 'l'
  const rwx = "rwxrwxrwx"
  var ps = newString(9)
  for i in 0 ..< 9:
    ps[i] = if ((perms shr (8 - i)) and 1) != 0: rwx[i] else: '-'
  result = $kind & ps & " 1 " & $a.uid & " " & $a.gid & " " &
    $a.size & " " & name

# ── Backend concept ───────────────────────────────────────────────────────────

type
  SftpBackend* = ref object of RootObj
    ## Filesystem a SftpServer serves. Methods raise SftpError with an
    ## SSH_FX_* code on failure; `readdir` raises FxEof when exhausted.

method openFile*(b: SftpBackend, path: string, pflags: uint32,
    attrs: SftpAttrs): string {.base.} =
  raise sftpError(FxOpUnsupported, "open not implemented")

method close*(b: SftpBackend, handle: string) {.base.} =
  raise sftpError(FxOpUnsupported, "close not implemented")

method read*(b: SftpBackend, handle: string, offset: uint64,
    len: uint32): seq[byte] {.base.} =
  raise sftpError(FxOpUnsupported, "read not implemented")

method write*(b: SftpBackend, handle: string, offset: uint64,
    data: openArray[byte]) {.base.} =
  raise sftpError(FxOpUnsupported, "write not implemented")

method stat*(b: SftpBackend, path: string): SftpAttrs {.base.} =
  raise sftpError(FxOpUnsupported, "stat not implemented")

method lstat*(b: SftpBackend, path: string): SftpAttrs {.base.} =
  raise sftpError(FxOpUnsupported, "lstat not implemented")

method fstat*(b: SftpBackend, handle: string): SftpAttrs {.base.} =
  raise sftpError(FxOpUnsupported, "fstat not implemented")

method setstat*(b: SftpBackend, path: string, attrs: SftpAttrs) {.base.} =
  raise sftpError(FxOpUnsupported, "setstat not implemented")

method fsetstat*(b: SftpBackend, handle: string,
    attrs: SftpAttrs) {.base.} =
  raise sftpError(FxOpUnsupported, "fsetstat not implemented")

method opendir*(b: SftpBackend, path: string): string {.base.} =
  raise sftpError(FxOpUnsupported, "opendir not implemented")

method readdir*(b: SftpBackend, handle: string): seq[SftpName] {.base.} =
  raise sftpError(FxOpUnsupported, "readdir not implemented")

method remove*(b: SftpBackend, path: string) {.base.} =
  raise sftpError(FxOpUnsupported, "remove not implemented")

method mkdir*(b: SftpBackend, path: string,
    attrs: SftpAttrs) {.base.} =
  raise sftpError(FxOpUnsupported, "mkdir not implemented")

method rmdir*(b: SftpBackend, path: string) {.base.} =
  raise sftpError(FxOpUnsupported, "rmdir not implemented")

method realpath*(b: SftpBackend, path: string): string {.base.} =
  raise sftpError(FxOpUnsupported, "realpath not implemented")

method rename*(b: SftpBackend, oldpath, newpath: string) {.base.} =
  raise sftpError(FxOpUnsupported, "rename not implemented")

method readlink*(b: SftpBackend, path: string): string {.base.} =
  raise sftpError(FxOpUnsupported, "readlink not implemented")

method symlink*(b: SftpBackend, linkpath, targetpath: string) {.base.} =
  raise sftpError(FxOpUnsupported, "symlink not implemented")

# ── OS backend (sandboxed root) ──────────────────────────────────────────────

type
  OpenFile* = object
    path*: string
    fh*: File
    readable*: bool
    writable*: bool
    append*: bool

  OpenDir* = object
    path*: string
    entries*: seq[string]
    pos*: int

  OsBackend* = ref object of SftpBackend
    ## Serves `root` from the local disk. Client-visible `/` maps to
    ## root; relative client paths resolve against root/startDir.
    ## Lexical escapes are rejected, and symlink *following* is
    ## confined to the root (see resolveConfined). Symlink *targets*
    ## are unrestricted at creation; readlink reports them raw.
    root*: string
    startDir*: string ## disk path of the start dir (inside root)
    umask*: uint32
    nextId*: int
    files*: Table[string, OpenFile]
    dirs*: Table[string, OpenDir]

proc newOsBackend*(root: string, umask = 0o022'u32,
    startDir = "/"): OsBackend =
  ## `startDir` is client-visible (`/` = root, the default). It is
  ## normalized and must stay inside the root, else this raises
  ## SftpError (fail fast, before serving anything).
  let r = root.absolutePath().normalizedPath()
  var sd = startDir
  if sd.startsWith("/"):
    sd = sd[1 ..^ 1]
  let sdisk = normalizedPath(r / sd)
  if sdisk != r and not sdisk.startsWith(r & DirSep):
    var e = newException(SftpError,
      "sftp backend: start dir escapes root: " & startDir)
    e.code = FxPermissionDenied
    raise e
  result = OsBackend(root: r, startDir: sdisk, umask: umask,
    files: initTable[string, OpenFile](),
    dirs: initTable[string, OpenDir]())

proc resolvePath(b: OsBackend, path: string): string =
  ## Map a client path to disk, rejecting lexical escapes. Absolute
  ## paths resolve against the root; relative paths against
  ## root/startDir. This is lexical only: it does not resolve
  ## symlinks, so every materializing op must go through
  ## resolveConfined instead.
  if path.len == 0:
    raise sftpError(FxFailure, "empty path")
  if '\0' in path:
    raise sftpError(FxFailure, "NUL byte in path")
  var rel = path
  let base =
    if rel.startsWith("/"):
      rel = rel[1 ..^ 1]
      b.root
    else:
      b.startDir
  let full = normalizedPath(base / rel)
  if full != b.root and not full.startsWith(b.root & DirSep):
    raise sftpError(FxPermissionDenied, "path escapes root: " & path)
  result = full

proc clientPath(b: OsBackend, full: string): string =
  ## Map a disk path back to client-visible form.
  if full == b.root:
    return "/"
  result = "/" & full.relativePath(b.root).replace(DirSep, '/')

const MaxSymlinkDepth = 40 ## match SYMLOOP_MAX-style loop protection

when defined(posix):
  proc readLinkRaw(path: string): string =
    ## Single-level readlink (no recursion; the walker re-enters).
    ## Qualified: our SftpBackend.readlink method shadows posix.readlink.
    var buf = newString(256)
    while true:
      let n = posix.readlink(path.cstring, cast[cstring](addr buf[0]),
        buf.len)
      if n < 0:
        raise sftpError(FxFailure, "readlink failed: " & path)
      if n < buf.len:
        buf.setLen(n)
        return buf
      buf.setLen(buf.len * 2)

proc resolveConfined(b: OsBackend, path: string,
    followFinal = true): string =
  ## resolvePath plus jailed symlink following. Walk components from
  ## the root; every symlink met is resolved and containment is
  ## re-verified at each step, with absolute targets re-rooted
  ## (chroot semantics: `/link -> /etc/x` stays inside). Loops fail
  ## fast. `followFinal = false` leaves a trailing link unresolved
  ## (for lstat, readlink, and link creation/removal/renaming, which
  ## must address the link itself). Non-existent tails stay lexical
  ## under the last verified dir (creat case).
  ##
  ## Known limitation: check-then-use TOCTOU (a swapped component
  ## between resolve and open). Same class as OpenSSH without chroot;
  ## closing it needs openat2(RESOLVE_BENEATH), Linux-only.
  let base = b.resolvePath(path)
  when not defined(posix):
    return base # no lstat: lexical check is all we have
  if base == b.root:
    return base
  var parts = base.substr(b.root.len + 1).split(DirSep)
  var cur = b.root
  var depth = 0
  var i = 0
  while i < parts.len:
    let comp = parts[i]
    if comp.len == 0 or comp == ".":
      inc i
      continue
    if comp == "..":
      if cur == b.root:
        raise sftpError(FxPermissionDenied, "path escapes root: " & path)
      cur = parentDir(cur)
      inc i
      continue
    let isLast = i == parts.len - 1
    cur = cur / comp
    var st: Stat
    if lstat(cur.cstring, st) != 0:
      # Tail does not exist: the verified parent plus the remaining
      # lexical components (no ".." can appear: base is normalized)
      # stays inside by construction.
      var tail = parentDir(cur)
      for j in i ..< parts.len:
        if parts[j] == ".." or '\0' in parts[j]:
          raise sftpError(FxPermissionDenied, "path escapes root: " & path)
        tail = tail / parts[j]
      return normalizedPath(tail)
    if S_ISLNK(st.st_mode) and (not isLast or followFinal):
      depth += 1
      if depth > MaxSymlinkDepth:
        raise sftpError(FxFailure,
          "too many levels of symbolic links: " & path)
      let target = readLinkRaw(cur)
      var rest: seq[string] = @[]
      if i + 1 < parts.len:
        rest = parts[i + 1 ..^ 1]
      if target.len > 0 and target[0] == '/':
        cur = b.root # absolute target: re-root (chroot semantics)
        parts = target[1 ..^ 1].split(DirSep) & rest
      else:
        cur = parentDir(cur)
        parts = target.split(DirSep) & rest
      i = 0
      continue
    inc i
  result = cur

proc allocHandle(b: OsBackend, prefix: string): string =
  inc b.nextId
  result = prefix & $b.nextId

proc fileAttrs(full: string, follow = true): SftpAttrs =
  ## Attrs for a disk path. `follow = false` stats the link itself
  ## (used for directory listings so entries can't leak outside
  ## metadata through links).
  var uid = 0'u32
  var gid = 0'u32
  var perms = 0o644'u32
  var size = 0'u64
  var atime = 0'u32
  var mtime = 0'u32
  when defined(posix):
    var st: Stat
    let ok =
      if follow: stat(full.cstring, st) == 0
      else: lstat(full.cstring, st) == 0
    if ok:
      uid = uint32(st.st_uid)
      gid = uint32(st.st_gid)
      # Full st_mode including the S_IFMT file-type bits: OpenSSH
      # checks the type (S_ISREG etc.) from ATTRS permissions.
      perms = uint32(st.st_mode)
      size = uint64(st.st_size)
      atime = uint32(st.st_atime)
      mtime = uint32(st.st_mtime)
      return fullAttrs(size, uid, gid, perms, atime, mtime)
  # Fallback (non-posix or stat failed): best effort from std/os.
  try:
    size = uint64(getFileSize(full))
  except CatchableError:
    discard
  try:
    mtime = uint32(getLastModificationTime(full).toUnix())
    atime = mtime
  except CatchableError:
    discard
  if dirExists(full):
    perms = 0o040755'u32
  else:
    perms = 0o100644'u32
  result = fullAttrs(size, uid, gid, perms, atime, mtime)

proc applyUmask(perms, umask: uint32): uint32 =
  perms and (not umask) and 0o777'u32

method openFile*(b: OsBackend, path: string, pflags: uint32,
    attrs: SftpAttrs): string =
  # Confined: following a link lands on a jailed target, so the
  # opened fd can never point outside the root.
  let full = b.resolveConfined(path)
  let wantRead = (pflags and OpenRead) != 0
  let wantWrite = (pflags and OpenWrite) != 0
  let wantAppend = (pflags and OpenAppend) != 0
  if not wantRead and not wantWrite:
    raise sftpError(FxFailure, "open needs read and/or write flag")
  let exists = fileExists(full) or dirExists(full)
  if dirExists(full):
    raise sftpError(FxFailure, "open on directory")
  if (pflags and OpenExcl) != 0 and (pflags and OpenCreat) != 0 and exists:
    raise sftpError(FxFailure, "file exists")
  if not exists and (pflags and OpenCreat) == 0:
    raise sftpError(FxNoSuchFile, "no such file: " & path)
  if not exists:
    createDir(full.parentDir)
    writeFile(full, "")
    var perms = 0o666'u32
    if (attrs.mask and AttrPermissions) != 0:
      perms = attrs.permissions and 0o777'u32
    when defined(posix):
      discard chmod(full.cstring, Mode(applyUmask(perms, b.umask)))
    else:
      discard trySetFilePermissions(full, {fpUserRead, fpUserWrite}, true)
  var fh: File
  let mode = if wantWrite: fmReadWriteExisting else: fmRead
  if not open(fh, full, mode):
    raise sftpError(FxPermissionDenied, "cannot open: " & path)
  if (pflags and OpenTrunc) != 0 and wantWrite:
    fh.close()
    try:
      writeFile(full, "")
    except CatchableError as e:
      raise sftpError(FxFailure, "truncate failed: " & e.msg)
    if not open(fh, full, mode):
      raise sftpError(FxFailure, "reopen after truncate failed")
  let h = b.allocHandle("f")
  b.files[h] = OpenFile(path: full, fh: fh, readable: wantRead,
    writable: wantWrite, append: wantAppend)
  result = h

method close*(b: OsBackend, handle: string) =
  if handle in b.files:
    try:
      b.files[handle].fh.close()
    except CatchableError:
      discard
    b.files.del(handle)
    return
  if handle in b.dirs:
    b.dirs.del(handle)
    return
  raise sftpError(FxFailure, "unknown handle")

method read*(b: OsBackend, handle: string, offset: uint64,
    len: uint32): seq[byte] =
  if handle notin b.files:
    raise sftpError(FxFailure, "unknown handle")
  let ent = b.files[handle]
  if not ent.readable:
    raise sftpError(FxPermissionDenied, "handle not readable")
  let size = uint64(getFileSize(ent.path))
  if offset >= size:
    raise sftpError(FxEof, "end of file")
  let n = min(uint64(len), size - offset)
  result = newSeq[byte](n)
  ent.fh.setFilePos(int64(offset))
  let got = ent.fh.readBytes(result, 0, int(n))
  result.setLen(got)

method write*(b: OsBackend, handle: string, offset: uint64,
    data: openArray[byte]) =
  if handle notin b.files:
    raise sftpError(FxFailure, "unknown handle")
  let ent = b.files[handle]
  if not ent.writable:
    raise sftpError(FxPermissionDenied, "handle not writable")
  var at = int64(offset)
  if ent.append:
    at = getFileSize(ent.path)
  ent.fh.setFilePos(at)
  var pos = 0
  while pos < data.len:
    let n = ent.fh.writeBytes(data, pos, data.len - pos)
    if n <= 0:
      raise sftpError(FxFailure, "short write")
    pos += n

method stat*(b: OsBackend, path: string): SftpAttrs =
  let full = b.resolveConfined(path)
  if not fileExists(full) and not dirExists(full):
    raise sftpError(FxNoSuchFile, "no such file: " & path)
  result = fileAttrs(full)

method lstat*(b: OsBackend, path: string): SftpAttrs =
  # The link itself: confine intermediate components, leave the
  # trailing link unresolved.
  let full = b.resolveConfined(path, followFinal = false)
  when defined(posix):
    var st: Stat
    if lstat(full.cstring, st) != 0:
      raise sftpError(FxNoSuchFile, "no such file: " & path)
    # Full st_mode including S_IFMT type bits (lstat: symlinks stay links).
    return fullAttrs(uint64(st.st_size), uint32(st.st_uid),
      uint32(st.st_gid), uint32(st.st_mode), uint32(st.st_atime),
      uint32(st.st_mtime))
  else:
    return b.stat(path)

method fstat*(b: OsBackend, handle: string): SftpAttrs =
  if handle notin b.files:
    raise sftpError(FxFailure, "unknown handle")
  result = fileAttrs(b.files[handle].path)

proc applySetstat(full: string, attrs: SftpAttrs) =
  if (attrs.mask and AttrSize) != 0:
    when defined(posix):
      if truncate(full.cstring, Off(attrs.size)) != 0:
        raise sftpError(FxFailure, "truncate failed")
    else:
      # No portable truncate: rewrite the prefix.
      try:
        let content = readFile(full)
        var outf = open(full, fmWrite)
        let n = min(content.len, int(attrs.size))
        if n > 0:
          discard outf.writeBytes(content.toOpenArrayByte(0, n - 1), 0, n)
        if int(attrs.size) > content.len:
          outf.setFilePos(int64(content.len))
          var pad = newSeq[byte](int(attrs.size) - content.len)
          discard outf.writeBytes(pad, 0, pad.len)
        outf.close()
      except CatchableError as e:
        raise sftpError(FxFailure, "setstat size: " & e.msg)
  if (attrs.mask and AttrPermissions) != 0:
    when defined(posix):
      if chmod(full.cstring, Mode(attrs.permissions and 0o7777'u32)) != 0:
        raise sftpError(FxPermissionDenied, "chmod failed")
    else:
      discard trySetFilePermissions(full, {fpUserRead, fpUserWrite}, true)
  if (attrs.mask and AttrAcmodtime) != 0:
    try:
      setLastModificationTime(full, fromUnix(int64(attrs.mtime)))
    except CatchableError as e:
      raise sftpError(FxFailure, "setstat mtime: " & e.msg)
  if (attrs.mask and AttrUidgid) != 0:
    when defined(posix):
      if chown(full.cstring, Uid(attrs.uid), Gid(attrs.gid)) != 0:
        raise sftpError(FxPermissionDenied, "chown failed")
    else:
      raise sftpError(FxOpUnsupported, "chown not supported")

method setstat*(b: OsBackend, path: string, attrs: SftpAttrs) =
  # SETSTAT follows links (chmod-like); confinement keeps it inside.
  let full = b.resolveConfined(path)
  if not fileExists(full) and not dirExists(full):
    raise sftpError(FxNoSuchFile, "no such file: " & path)
  applySetstat(full, attrs)

method fsetstat*(b: OsBackend, handle: string, attrs: SftpAttrs) =
  if handle notin b.files:
    raise sftpError(FxFailure, "unknown handle")
  applySetstat(b.files[handle].path, attrs)

method opendir*(b: OsBackend, path: string): string =
  let full = b.resolveConfined(path)
  if not dirExists(full):
    raise sftpError(FxNoSuchFile, "no such directory: " & path)
  var entries: seq[string] = @[]
  for kind, p in walkDir(full):
    entries.add(p.extractFilename())
  entries.sort(proc(a, b: string): int = cmp(a, b))
  let h = b.allocHandle("d")
  b.dirs[h] = OpenDir(path: full, entries: entries)
  result = h

method readdir*(b: OsBackend, handle: string): seq[SftpName] =
  if handle notin b.dirs:
    raise sftpError(FxFailure, "unknown handle")
  var d = b.dirs[handle]
  if d.pos >= d.entries.len:
    raise sftpError(FxEof, "end of directory")
  result = @[]
  let stop = min(d.pos + ReaddirChunk, d.entries.len)
  while d.pos < stop:
    let name = d.entries[d.pos]
    inc d.pos
    let full = d.path / name
    let a =
      try:
        fileAttrs(full, follow = false) # links listed as links
      except CatchableError:
        continue
    result.add(SftpName(filename: name, longname: formatLongname(name, a),
      attrs: a))
  b.dirs[handle] = d
  if result.len == 0:
    raise sftpError(FxEof, "end of directory")

method remove*(b: OsBackend, path: string) =
  # removeFile takes the link itself, so address it unresolved.
  let full = b.resolveConfined(path, followFinal = false)
  if not fileExists(full):
    raise sftpError(FxNoSuchFile, "no such file: " & path)
  try:
    removeFile(full)
  except CatchableError as e:
    raise sftpError(FxPermissionDenied, "remove failed: " & e.msg)

method mkdir*(b: OsBackend, path: string, attrs: SftpAttrs) =
  # mkdir takes the path itself (EEXIST on a link); no following.
  let full = b.resolveConfined(path, followFinal = false)
  if fileExists(full) or dirExists(full):
    raise sftpError(FxFailure, "path exists: " & path)
  try:
    createDir(full)
  except CatchableError as e:
    raise sftpError(FxPermissionDenied, "mkdir failed: " & e.msg)
  when defined(posix):
    var perms = applyUmask(0o777'u32, b.umask)
    if (attrs.mask and AttrPermissions) != 0:
      perms = attrs.permissions and 0o7777'u32
    discard chmod(full.cstring, Mode(perms))

method rmdir*(b: OsBackend, path: string) =
  let full = b.resolveConfined(path, followFinal = false)
  if not dirExists(full):
    raise sftpError(FxNoSuchFile, "no such directory: " & path)
  try:
    removeDir(full)
  except CatchableError as e:
    raise sftpError(FxPermissionDenied, "rmdir failed: " & e.msg)

method realpath*(b: OsBackend, path: string): string =
  # Canonicalize through links (spec behavior), still client-visible:
  # confined targets always map back inside the root.
  let full = b.resolveConfined(path)
  result = b.clientPath(full)

method rename*(b: OsBackend, oldpath, newpath: string) =
  # rename moves links themselves; address both ends unresolved.
  # symlinkExists covers dangling links, which rename must accept.
  let src = b.resolveConfined(oldpath, followFinal = false)
  let dst = b.resolveConfined(newpath, followFinal = false)
  if not fileExists(src) and not dirExists(src) and not symlinkExists(src):
    raise sftpError(FxNoSuchFile, "no such file: " & oldpath)
  try:
    createDir(dst.parentDir)
    moveFile(src, dst)
  except CatchableError as e:
    raise sftpError(FxPermissionDenied, "rename failed: " & e.msg)

method readlink*(b: OsBackend, path: string): string =
  # Address the link itself; the raw target is reported as-is
  # (spec-correct). Following it elsewhere stays jailed.
  let full = b.resolveConfined(path, followFinal = false)
  try:
    result = expandSymlink(full)
  except CatchableError as e:
    raise sftpError(FxNoSuchFile, "readlink failed: " & e.msg)

method symlink*(b: OsBackend, linkpath, targetpath: string) =
  # The link itself must live inside; the target is unrestricted
  # (following it is what stays jailed).
  let full = b.resolveConfined(linkpath, followFinal = false)
  try:
    createDir(full.parentDir)
    createSymlink(targetpath, full)
  except CatchableError as e:
    raise sftpError(FxPermissionDenied, "symlink failed: " & e.msg)

# ── Read-only wrapper (role enforcement) ─────────────────────────────────────

type
  ReadOnlyBackend* = ref object of SftpBackend
    ## Denies every mutating operation with FxPermissionDenied.
    ## Reads, stats and directory listings delegate to `inner`.
    inner*: SftpBackend

proc newReadOnlyBackend*(inner: SftpBackend): ReadOnlyBackend =
  ReadOnlyBackend(inner: inner)

method openFile*(b: ReadOnlyBackend, path: string, pflags: uint32,
    attrs: SftpAttrs): string =
  if (pflags and (OpenWrite or OpenAppend or OpenCreat or OpenTrunc or
      OpenExcl)) != 0:
    raise sftpError(FxPermissionDenied, "read-only filesystem")
  result = b.inner.openFile(path, pflags, attrs)

method close*(b: ReadOnlyBackend, handle: string) =
  b.inner.close(handle)

method read*(b: ReadOnlyBackend, handle: string, offset: uint64,
    len: uint32): seq[byte] =
  b.inner.read(handle, offset, len)

method write*(b: ReadOnlyBackend, handle: string, offset: uint64,
    data: openArray[byte]) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method stat*(b: ReadOnlyBackend, path: string): SftpAttrs =
  b.inner.stat(path)

method lstat*(b: ReadOnlyBackend, path: string): SftpAttrs =
  b.inner.lstat(path)

method fstat*(b: ReadOnlyBackend, handle: string): SftpAttrs =
  b.inner.fstat(handle)

method setstat*(b: ReadOnlyBackend, path: string, attrs: SftpAttrs) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method fsetstat*(b: ReadOnlyBackend, handle: string,
    attrs: SftpAttrs) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method opendir*(b: ReadOnlyBackend, path: string): string =
  b.inner.opendir(path)

method readdir*(b: ReadOnlyBackend, handle: string): seq[SftpName] =
  b.inner.readdir(handle)

method remove*(b: ReadOnlyBackend, path: string) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method mkdir*(b: ReadOnlyBackend, path: string, attrs: SftpAttrs) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method rmdir*(b: ReadOnlyBackend, path: string) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method realpath*(b: ReadOnlyBackend, path: string): string =
  b.inner.realpath(path)

method rename*(b: ReadOnlyBackend, oldpath, newpath: string) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

method readlink*(b: ReadOnlyBackend, path: string): string =
  b.inner.readlink(path)

method symlink*(b: ReadOnlyBackend, linkpath, targetpath: string) =
  raise sftpError(FxPermissionDenied, "read-only filesystem")

# ── Server ────────────────────────────────────────────────────────────────────

type
  SftpServer* = object
    ## One SFTP conversation on a channel. Feed channel DATA payloads
    ## with `sftpFeed`, ship `takeSftpOutbox` via `mux.sendData`.
    backend*: SftpBackend
    maxVersion*: uint32
    version*: uint32 ## negotiated version, 0 until INIT
    denyTypes*: set[byte] ## request types rejected as OpUnsupported
    buf*: seq[byte]
    outbox*: seq[seq[byte]]

proc initSftpServer*(backend: SftpBackend,
    maxVersion = SftpVersion3): SftpServer =
  result.backend = backend
  result.maxVersion = maxVersion

proc takeSftpOutbox*(s: var SftpServer): seq[seq[byte]] =
  result = s.outbox
  s.outbox = @[]

proc buildStatus(id, code: uint32, msg: string): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpStatus)
  w.writeUint32(id)
  w.writeUint32(code)
  w.writeString(msg)
  w.writeString("en")
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc buildHandle(id: uint32, handle: string): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpHandle)
  w.writeUint32(id)
  w.writeString(handle)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc buildData(id: uint32, data: openArray[byte]): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpData)
  w.writeUint32(id)
  w.writeString(data)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc buildName(id: uint32, names: openArray[SftpName]): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpName)
  w.writeUint32(id)
  w.writeUint32(uint32(names.len))
  for n in names:
    w.writeString(n.filename)
    w.writeString(n.longname)
    w.writeAttrs(n.attrs)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc buildAttrsResp(id: uint32, a: SftpAttrs): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpAttrs)
  w.writeUint32(id)
  w.writeAttrs(a)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc dispatch(s: var SftpServer, typ: byte, payload: openArray[byte]) =
  ## Handle one complete SFTP packet body (type byte + payload, length
  ## prefix already stripped). Appends exactly one response packet.
  if typ == SshFxpInit:
    var r = initReader(payload)
    let clientVersion = r.readUint32()
    # v4+ INIT may carry extension-data; tolerate and ignore it.
    s.version = min(clientVersion, s.maxVersion)
    var w = initWriter()
    let at = w.reserve(4)
    w.writeByte(SshFxpVersion)
    w.writeUint32(s.version)
    w.patchUint32At(at, uint32(w.len() - 4))
    s.outbox.add(w.toBytes())
    return
  if s.version == 0:
    raise sftpError(FxNoConnection, "INIT required first")
  var r = initReader(payload)
  let id = r.readUint32()
  try:
    if typ in s.denyTypes:
      raise sftpError(FxOpUnsupported, "Request denied")
    case typ
    of SshFxpOpen:
      let path = r.readStringStr()
      let pflags = r.readUint32()
      let attrs = r.readAttrs()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "OPEN trailing bytes")
      s.outbox.add(buildHandle(id, s.backend.openFile(path, pflags, attrs)))
    of SshFxpClose:
      let handle = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "CLOSE trailing bytes")
      s.backend.close(handle)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpRead:
      let handle = r.readStringStr()
      let offset = r.readUint64()
      let len = r.readUint32()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "READ trailing bytes")
      if len > MaxSftpRead:
        raise sftpError(FxBadMessage, "READ length too large")
      try:
        s.outbox.add(buildData(id, s.backend.read(handle, offset, len)))
      except SftpError as e:
        if e.code == FxEof:
          s.outbox.add(buildStatus(id, FxEof, "End of file"))
        else:
          raise e
    of SshFxpWrite:
      let handle = r.readStringStr()
      let offset = r.readUint64()
      let data = r.readString()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "WRITE trailing bytes")
      s.backend.write(handle, offset, data)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpLstat:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "LSTAT trailing bytes")
      s.outbox.add(buildAttrsResp(id, s.backend.lstat(path)))
    of SshFxpFstat:
      let handle = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "FSTAT trailing bytes")
      s.outbox.add(buildAttrsResp(id, s.backend.fstat(handle)))
    of SshFxpSetstat:
      let path = r.readStringStr()
      let attrs = r.readAttrs()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "SETSTAT trailing bytes")
      s.backend.setstat(path, attrs)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpFsetstat:
      let handle = r.readStringStr()
      let attrs = r.readAttrs()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "FSETSTAT trailing bytes")
      s.backend.fsetstat(handle, attrs)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpOpendir:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "OPENDIR trailing bytes")
      s.outbox.add(buildHandle(id, s.backend.opendir(path)))
    of SshFxpReaddir:
      let handle = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "READDIR trailing bytes")
      try:
        s.outbox.add(buildName(id, s.backend.readdir(handle)))
      except SftpError as e:
        if e.code == FxEof:
          s.outbox.add(buildStatus(id, FxEof, "End of directory"))
        else:
          raise e
    of SshFxpRemove:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "REMOVE trailing bytes")
      s.backend.remove(path)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpMkdir:
      let path = r.readStringStr()
      let attrs = r.readAttrs()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "MKDIR trailing bytes")
      s.backend.mkdir(path, attrs)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpRmdir:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "RMDIR trailing bytes")
      s.backend.rmdir(path)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpRealpath:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "REALPATH trailing bytes")
      let resolved = s.backend.realpath(path)
      let a =
        try:
          s.backend.stat(resolved)
        except SftpError:
          SftpAttrs()
      s.outbox.add(buildName(id, [SftpName(filename: resolved,
        longname: resolved, attrs: a)]))
    of SshFxpStat:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "STAT trailing bytes")
      s.outbox.add(buildAttrsResp(id, s.backend.stat(path)))
    of SshFxpRename:
      let oldpath = r.readStringStr()
      let newpath = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "RENAME trailing bytes")
      s.backend.rename(oldpath, newpath)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    of SshFxpReadlink:
      let path = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "READLINK trailing bytes")
      let target = s.backend.readlink(path)
      # READLINK answers NAME with the link target as filename.
      s.outbox.add(buildName(id, [SftpName(filename: target,
        longname: target, attrs: SftpAttrs())]))
    of SshFxpSymlink:
      # Wire order is linkpath then targetpath (filexfer-02 §6.10 has
      # them backwards; OpenBSD sftp-server uses linkpath first).
      let linkpath = r.readStringStr()
      let targetpath = r.readStringStr()
      if not r.isExhausted():
        raise sftpError(FxBadMessage, "SYMLINK trailing bytes")
      s.backend.symlink(linkpath, targetpath)
      s.outbox.add(buildStatus(id, FxOk, "Ok"))
    else:
      s.outbox.add(buildStatus(id, FxOpUnsupported, "Unsupported packet"))
  except SftpError as e:
    s.outbox.add(buildStatus(id, e.code, e.msg))
  except SshCodecError as e:
    s.outbox.add(buildStatus(id, FxBadMessage, "Malformed packet: " & e.msg))
  except CatchableError as e:
    # Backend bugs or OS errors must not kill the conversation.
    s.outbox.add(buildStatus(id, FxFailure, "Internal error: " & e.msg))

proc sftpFeed*(s: var SftpServer, data: openArray[byte]) =
  ## Feed raw channel DATA bytes. Raises SftpError on framing violations
  ## (oversize packet, INIT required); per-request failures become
  ## SSH_FXP_STATUS responses instead.
  let off = s.buf.len
  s.buf.setLen(off + data.len)
  if data.len > 0:
    copyMem(addr s.buf[off], unsafeAddr data[0], data.len)
  while true:
    if s.buf.len < 5:
      return
    let pktLen = (uint32(s.buf[0]) shl 24) or (uint32(s.buf[1]) shl 16) or
      (uint32(s.buf[2]) shl 8) or uint32(s.buf[3])
    if pktLen < 1 or pktLen > MaxSftpPacket:
      raise sftpError(FxConnectionLost, "bad SFTP packet length")
    if s.buf.len < int(4 + pktLen):
      return
    let typ = s.buf[4]
    # Dispatch from a view (no copy), then consume in place: shift the
    # remainder down and keep capacity, so a long session of small
    # packets reuses one buffer instead of reallocating per packet.
    let total = 4 + int(pktLen)
    s.dispatch(typ, s.buf.toOpenArray(5, total - 1))
    let left = s.buf.len - total
    if left > 0:
      copyMem(addr s.buf[0], addr s.buf[total], left)
    s.buf.setLen(left)
