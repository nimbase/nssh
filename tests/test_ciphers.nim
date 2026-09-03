import std/unittest

import nssh/ciphers
import nssh/kex

proc hx(s: string): seq[byte] =
  proc hv(c: char): int =
    case c
    of '0'..'9': int(c) - 48
    of 'a'..'f': int(c) - 87
    of 'A'..'F': int(c) - 55
    else: raise newException(ValueError, "bad hex")
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(hv(s[2*i]) * 16 + hv(s[2*i+1]))

proc toArr4(b: seq[byte]): array[4, byte] =
  for i in 0 ..< 4: result[i] = b[i]

test "aes128-ctr NIST SP 800-38A F.5.1":
  var c = initCipher(ckAes128Ctr, hx("2b7e151628aed2a6abf7158809cf4f3c"),
                     hx("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"))
  let ct = c.ctrCrypt(hx("6bc1bee22e409f96e93d7e117393172a"))
  check ct == hx("874d6191b620e3261bef6864990db6ce")
  # stateful continuation: second block uses incremented counter
  let ct2 = c.ctrCrypt(hx("ae2d8a571e03ac9c9eb76fac45af8e51"))
  check ct2 == hx("9806f66b7970fdff8617187bb9fffdff")

test "aes-ctr stateful round trip across split calls":
  let key = hx("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hx("000102030405060708090a0b0c0d0e0f")
  var e = initCipher(ckAes128Ctr, key, iv)
  var d = initCipher(ckAes128Ctr, key, iv)
  let pt = hx("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45ef059c")
  let c1 = e.ctrCrypt(pt[0 ..< 16])
  let c2 = e.ctrCrypt(pt[16 ..< 32])
  check d.ctrCrypt(c1 & c2) == pt
  expect SshCipherError: # unaligned chunk rejected
    discard e.ctrCrypt(@[1'u8, 2'u8])

test "aes128-gcm seal/open round trip + tamper + counter":
  let key = hx("2b7e151628aed2a6abf7158809cf4f3c")
  let iv = hx("000102030405060708090a0b")
  var e = initCipher(ckAes128Gcm, key, iv)
  var d = initCipher(ckAes128Gcm, key, iv)
  let plen = toArr4(hx("00000010"))
  let pt = hx("050102030405060708090a0b0c0d0e0f")
  let (ct1, tag1) = e.gcmSealPacket(plen, pt)
  check ct1.len == pt.len
  check d.gcmOpenPacket(plen, ct1, tag1) == pt
  # counter advanced: same plaintext seals differently, opens in order
  let (ct2, tag2) = e.gcmSealPacket(plen, pt)
  check ct2 != ct1
  check d.gcmOpenPacket(plen, ct2, tag2) == pt
  # tampered tag / ciphertext / aad rejected
  var badTag = tag1
  badTag[0] = badTag[0] xor 1
  expect SshCipherError:
    discard d.gcmOpenPacket(plen, ct1, badTag)
  var badCt = ct1
  badCt[^1] = badCt[^1] xor 1
  expect SshCipherError:
    discard d.gcmOpenPacket(plen, badCt, tag1)
  var badLen = plen
  badLen[3] = badLen[3] xor 1
  expect SshCipherError:
    discard d.gcmOpenPacket(badLen, ct1, tag1)

test "chacha20-poly1305 seal/open round trip + tamper + seqno binding":
  var k1, k2: array[32, byte]
  for i in 0 ..< 32:
    k1[i] = byte(i)
    k2[i] = byte(0x80 + i)
  var key = newSeq[byte](64)
  for i in 0 ..< 32:
    key[i] = k1[i]
    key[32 + i] = k2[i]
  let c = initCipher(ckChacha20Poly1305, key, @[])
  let plen = toArr4(hx("00000018"))
  let payload = hx("060102030405060708090a0b0c0d0e0f1011121314151617")
  let encLen = c.chachaSealLength(7, plen)
  check encLen != plen # length actually encrypted
  check c.chachaOpenLength(7, encLen) == plen
  let (ct, _) = c.chachaSealPayload(7, payload)
  let tag = c.chachaTag(7, encLen, ct)
  check c.chachaOpenAndVerify(7, encLen, ct, tag) == payload
  # wrong seqno fails everywhere
  check c.chachaOpenLength(8, encLen) != plen
  expect SshCipherError:
    discard c.chachaOpenAndVerify(8, encLen, ct, tag)
  # tampered length / payload / tag rejected
  var badLen = encLen
  badLen[0] = badLen[0] xor 1
  expect SshCipherError:
    discard c.chachaOpenAndVerify(7, badLen, ct, tag)
  var badCt = ct
  badCt[0] = badCt[0] xor 1
  expect SshCipherError:
    discard c.chachaOpenAndVerify(7, encLen, badCt, tag)
  var badTag = tag
  badTag[15] = badTag[15] xor 1
  expect SshCipherError:
    discard c.chachaOpenAndVerify(7, encLen, ct, badTag)

test "hmac-sha2 mac round trip incl etm + verify":
  let key = hx("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
  let data = hx("4869205468657265")
  let m256 = computeMac(mkHmacSha256, key, 3, data)
  check m256.len == 32
  check verifyMac(mkHmacSha256, key, 3, data, m256)
  check not verifyMac(mkHmacSha256, key, 4, data, m256) # seqno bound
  let m512 = computeMac(mkHmacSha512Etm, key, 3, data)
  check m512.len == 64
  check verifyMac(mkHmacSha512Etm, key, 3, data, m512)
  check verifyMac(mkNone, @[], 0, data, @[])

test "session key schedule mirrors client/server":
  let K = hx("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf")
  var H: array[32, byte]
  for i in 0 ..< 32: H[i] = byte(i * 7)
  let sid = H
  let cli = newSessionKeys(K, H, sid, ckAes128Ctr, mkHmacSha256, true)
  let srv = newSessionKeys(K, H, sid, ckAes128Ctr, mkHmacSha256, false)
  # traffic keys cross-match: client->server == server<-client
  var a = cli.toPeer.cipher
  var b = srv.fromPeer.cipher
  let pt = hx("00112233445566778899aabbccddeeff")
  check b.ctrCrypt(a.ctrCrypt(pt)) == pt
  check cli.toPeer.macKey == srv.fromPeer.macKey
  check cli.fromPeer.macKey == srv.toPeer.macKey
  # chacha 64-byte key splits deterministically
  let cc = newSessionKeys(K, H, sid, ckChacha20Poly1305, mkNone, true)
  check cc.toPeer.cipher.chaK1 != cc.toPeer.cipher.chaK2
