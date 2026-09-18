import std/os
import std/unittest

import nssh/codec
import nssh/sftp

# ── client-side packet builders (test only) ───────────────────────────────────

proc pkt(typ: byte, id = 0'u32,
    body: proc(w: var Writer) {.closure.} = nil): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(typ)
  if typ != SshFxpInit and typ != SshFxpVersion:
    w.writeUint32(id)
  if body != nil:
    body(w)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc initPkt(version: uint32): seq[byte] =
  var w = initWriter()
  let at = w.reserve(4)
  w.writeByte(SshFxpInit)
  w.writeUint32(version)
  w.patchUint32At(at, uint32(w.len() - 4))
  result = w.toBytes()

proc noAttrs(): SftpAttrs = SftpAttrs()

type Decoded = object
  typ*: byte
  id*: uint32
  r*: Reader

proc decode(p: seq[byte]): Decoded =
  var r = initReader(p)
  let n = int(r.readUint32())
  check n == p.len - 4
  result.typ = r.readByte()
  if result.typ != SshFxpVersion:
    result.id = r.readUint32()
  result.r = r

proc readStatus(d: Decoded): uint32 =
  check d.typ == SshFxpStatus
  var r = d.r
  result = r.readUint32()
  discard r.readStringStr()
  discard r.readStringStr()
  check r.isExhausted()

proc readHandle(d: Decoded): string =
  check d.typ == SshFxpHandle
  var r = d.r
  result = r.readStringStr()
  check r.isExhausted()

proc withServer(root: string,
    body: proc(s: var SftpServer) {.closure.}) =
  var s = initSftpServer(newOsBackend(root))
  s.sftpFeed(initPkt(3))
  var v = decode(s.takeSftpOutbox()[0])
  check v.typ == SshFxpVersion
  check v.r.readUint32() == 3
  check v.r.isExhausted()
  body(s)
  check s.takeSftpOutbox().len == 0

proc tmpRoot(): string =
  result = getTempDir() / "nssh-sftp-" & $getCurrentProcessId()
  createDir(result)

# ── tests ─────────────────────────────────────────────────────────────────────

test "INIT negotiates version 3":
  var s = initSftpServer(newOsBackend(tmpRoot()))
  s.sftpFeed(initPkt(3))
  check s.version == 3
  var d = decode(s.takeSftpOutbox()[0])
  check d.typ == SshFxpVersion
  check d.r.readUint32() == 3

test "INIT above max negotiates down to server max":
  var s = initSftpServer(newOsBackend(tmpRoot()))
  s.sftpFeed(initPkt(9))
  check s.version == 3
  var d = decode(s.takeSftpOutbox()[0])
  check d.r.readUint32() == 3

test "request before INIT raises":
  var s = initSftpServer(newOsBackend(tmpRoot()))
  expect SftpError:
    s.sftpFeed(pkt(SshFxpRealpath, 1,
      proc(w: var Writer) {.closure.} = w.writeString("/")))

test "file round trip: mkdir, write, read, stat, rename, remove":
  let root = tmpRoot()
  withServer(root, proc(s: var SftpServer) {.closure.} =
    var id = 10'u32
    # MKDIR sub
    s.sftpFeed(pkt(SshFxpMkdir, id,
      proc(w: var Writer) {.closure.} =
        w.writeString("/sub")
        w.writeAttrs(noAttrs())))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
    # OPEN sub/f.txt for write+creat
    inc id
    s.sftpFeed(pkt(SshFxpOpen, id,
      proc(w: var Writer) {.closure.} =
        w.writeString("/sub/f.txt")
        w.writeUint32(OpenWrite or OpenCreat or OpenTrunc)
        w.writeAttrs(noAttrs())))
    let wh = readHandle(decode(s.takeSftpOutbox()[0]))
    # WRITE hello
    inc id
    s.sftpFeed(pkt(SshFxpWrite, id,
      proc(w: var Writer) {.closure.} =
        w.writeString(wh)
        w.writeUint64(0)
        w.writeString("hello")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
    # CLOSE
    inc id
    s.sftpFeed(pkt(SshFxpClose, id,
      proc(w: var Writer) {.closure.} = w.writeString(wh)))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
    # STAT size == 5
    inc id
    s.sftpFeed(pkt(SshFxpStat, id,
      proc(w: var Writer) {.closure.} = w.writeString("/sub/f.txt")))
    var st = decode(s.takeSftpOutbox()[0])
    check st.typ == SshFxpAttrs
    let a = st.r.readAttrs()
    check (a.mask and AttrSize) != 0
    check a.size == 5
    # OPEN for read, READ back
    inc id
    s.sftpFeed(pkt(SshFxpOpen, id,
      proc(w: var Writer) {.closure.} =
        w.writeString("/sub/f.txt")
        w.writeUint32(OpenRead)
        w.writeAttrs(noAttrs())))
    let rh = readHandle(decode(s.takeSftpOutbox()[0]))
    inc id
    s.sftpFeed(pkt(SshFxpRead, id,
      proc(w: var Writer) {.closure.} =
        w.writeString(rh)
        w.writeUint64(0)
        w.writeUint32(32)))
    var rd = decode(s.takeSftpOutbox()[0])
    check rd.typ == SshFxpData
    check rd.r.readStringStr() == "hello"
    # READ past EOF -> EOF status
    inc id
    s.sftpFeed(pkt(SshFxpRead, id,
      proc(w: var Writer) {.closure.} =
        w.writeString(rh)
        w.writeUint64(5)
        w.writeUint32(32)))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxEof
    inc id
    s.sftpFeed(pkt(SshFxpClose, id,
      proc(w: var Writer) {.closure.} = w.writeString(rh)))
    discard s.takeSftpOutbox()
    # RENAME + REMOVE + RMDIR
    inc id
    s.sftpFeed(pkt(SshFxpRename, id,
      proc(w: var Writer) {.closure.} =
        w.writeString("/sub/f.txt")
        w.writeString("/sub/g.txt")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
    check fileExists(root / "sub" / "g.txt")
    inc id
    s.sftpFeed(pkt(SshFxpRemove, id,
      proc(w: var Writer) {.closure.} = w.writeString("/sub/g.txt")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
    inc id
    s.sftpFeed(pkt(SshFxpRmdir, id,
      proc(w: var Writer) {.closure.} = w.writeString("/sub")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOk
  )
  removeDir(root)

test "opendir/readdir lists entries then EOF":
  let root = tmpRoot()
  createDir(root / "d")
  writeFile(root / "d" / "a.txt", "a")
  writeFile(root / "d" / "b.txt", "bb")
  withServer(root, proc(s: var SftpServer) {.closure.} =
    s.sftpFeed(pkt(SshFxpOpendir, 1,
      proc(w: var Writer) {.closure.} = w.writeString("/d")))
    let h = readHandle(decode(s.takeSftpOutbox()[0]))
    s.sftpFeed(pkt(SshFxpReaddir, 2,
      proc(w: var Writer) {.closure.} = w.writeString(h)))
    var d = decode(s.takeSftpOutbox()[0])
    check d.typ == SshFxpName
    let n = d.r.readUint32()
    check n == 2
    var names: seq[string] = @[]
    for _ in 0 ..< n:
      names.add(d.r.readStringStr())
      discard d.r.readStringStr()
      discard d.r.readAttrs()
    check "a.txt" in names
    check "b.txt" in names
    s.sftpFeed(pkt(SshFxpReaddir, 3,
      proc(w: var Writer) {.closure.} = w.writeString(h)))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxEof
  )
  removeDir(root)

test "missing file, bad handle, traversal denied":
  let root = tmpRoot()
  withServer(root, proc(s: var SftpServer) {.closure.} =
    s.sftpFeed(pkt(SshFxpStat, 1,
      proc(w: var Writer) {.closure.} = w.writeString("/nope")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxNoSuchFile
    s.sftpFeed(pkt(SshFxpRead, 2,
      proc(w: var Writer) {.closure.} =
        w.writeString("f999")
        w.writeUint64(0)
        w.writeUint32(8)))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxFailure
    s.sftpFeed(pkt(SshFxpOpen, 3,
      proc(w: var Writer) {.closure.} =
        w.writeString("/../evil.txt")
        w.writeUint32(OpenRead)
        w.writeAttrs(noAttrs())))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxPermissionDenied
    s.sftpFeed(pkt(SshFxpRealpath, 4,
      proc(w: var Writer) {.closure.} = w.writeString("/../evil")))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxPermissionDenied
  )
  removeDir(root)

test "split packet reassembles across feeds":
  let root = tmpRoot()
  var s = initSftpServer(newOsBackend(root))
  let full = initPkt(3)
  s.sftpFeed(full.toOpenArray(0, 3))
  check s.takeSftpOutbox().len == 0
  s.sftpFeed(full.toOpenArray(4, full.len - 1))
  check s.version == 3
  check s.takeSftpOutbox().len == 1
  removeDir(root)

test "oversize length prefix raises":
  var s = initSftpServer(newOsBackend(tmpRoot()))
  var w = initWriter()
  w.writeUint32(MaxSftpPacket + 1)
  w.writeByte(SshFxpInit)
  expect SftpError:
    s.sftpFeed(w.toBytes())

test "unknown packet type replies OP_UNSUPPORTED":
  let root = tmpRoot()
  withServer(root, proc(s: var SftpServer) {.closure.} =
    s.sftpFeed(pkt(200'u8, 7))
    check readStatus(decode(s.takeSftpOutbox()[0])) == FxOpUnsupported
  )
  removeDir(root)

test "realpath resolves to client-visible path":
  let root = tmpRoot()
  createDir(root / "sub")
  withServer(root, proc(s: var SftpServer) {.closure.} =
    s.sftpFeed(pkt(SshFxpRealpath, 1,
      proc(w: var Writer) {.closure.} = w.writeString("/sub")))
    var d = decode(s.takeSftpOutbox()[0])
    check d.typ == SshFxpName
    check d.r.readUint32() == 1
    check d.r.readStringStr() == "/sub"
  )
  removeDir(root)

test "read-only backend denies mutations, allows reads":
  let root = tmpRoot()
  writeFile(root / "ro.txt", "data")
  var s = initSftpServer(newReadOnlyBackend(newOsBackend(root)))
  s.sftpFeed(initPkt(3))
  discard s.takeSftpOutbox()
  s.sftpFeed(pkt(SshFxpOpen, 1,
    proc(w: var Writer) {.closure.} =
      w.writeString("/ro.txt")
      w.writeUint32(OpenWrite)
      w.writeAttrs(noAttrs())))
  check readStatus(decode(s.takeSftpOutbox()[0])) == FxPermissionDenied
  s.sftpFeed(pkt(SshFxpStat, 2,
    proc(w: var Writer) {.closure.} = w.writeString("/ro.txt")))
  var d = decode(s.takeSftpOutbox()[0])
  check d.typ == SshFxpAttrs
  check d.r.readAttrs().size == 4
  s.sftpFeed(pkt(SshFxpMkdir, 3,
    proc(w: var Writer) {.closure.} =
      w.writeString("/new")
      w.writeAttrs(noAttrs())))
  check readStatus(decode(s.takeSftpOutbox()[0])) == FxPermissionDenied
  removeDir(root)

test "denyTypes rejects listed requests":
  let root = tmpRoot()
  var s = initSftpServer(newOsBackend(root))
  s.denyTypes = {SshFxpRemove, SshFxpRename}
  s.sftpFeed(initPkt(3))
  discard s.takeSftpOutbox()
  writeFile(root / "x.txt", "x")
  s.sftpFeed(pkt(SshFxpRemove, 1,
    proc(w: var Writer) {.closure.} = w.writeString("/x.txt")))
  check readStatus(decode(s.takeSftpOutbox()[0])) == FxOpUnsupported
  check fileExists(root / "x.txt")
  removeDir(root)
