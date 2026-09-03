import std/unittest
import std/strutils

import nssh/hostkeys

proc hx(s: string): array[32, byte] =
  proc hv(c: char): int =
    case c
    of '0'..'9': int(c) - 48
    of 'a'..'f': int(c) - 87
    of 'A'..'F': int(c) - 55
    else: raise newException(ValueError, "bad hex")
  for i in 0 ..< 32:
    result[i] = byte(hv(s[2*i]) * 16 + hv(s[2*i+1]))

proc hx64(s: string): array[64, byte] =
  proc hv(c: char): int =
    case c
    of '0'..'9': int(c) - 48
    of 'a'..'f': int(c) - 87
    of 'A'..'F': int(c) - 55
    else: raise newException(ValueError, "bad hex")
  for i in 0 ..< 64:
    result[i] = byte(hv(s[2*i]) * 16 + hv(s[2*i+1]))

test "ed25519 RFC 8032 TEST 1":
  let seed = hx("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
  let pub = hx("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
  let sig = hx64("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
  let kp = edKeyFromSeed(seed)
  check kp.pubkey == pub
  check edSign(kp, @[]) == sig
  check edVerify(pub, @[], sig)

test "ed25519 generated round trip + tamper":
  let kp = generateEdKey()
  let msg = @[byte(1), 2, 3, 4, 5]
  let sig = edSign(kp, msg)
  check edVerify(kp.pubkey, msg, sig)
  var bad = sig
  bad[0] = bad[0] xor 1
  check not edVerify(kp.pubkey, msg, bad)
  check not edVerify(kp.pubkey, @[byte(1), 2, 3, 4, 6], sig)

test "pub blob + signature blob round trip":
  let kp = generateEdKey()
  let blob = encodePubBlob(kp.pubkey)
  check parsePubBlob(blob) == kp.pubkey
  let sig = edSign(kp, @[byte(9)])
  let sblob = encodeSignature(sig)
  check parseSignature(sblob) == sig
  expect SshKeyError:
    discard parsePubBlob(@[byte(0), 0, 0, 1, 2])

test "authorized_keys line round trip + fingerprint":
  let kp = generateEdKey()
  let line = encodeAuthorizedKeysLine(kp.pubkey, "test@nssh")
  check line.startsWith("ssh-ed25519 ")
  check line.endsWith("test@nssh")
  let parsed = parseAuthorizedKeysLine(line)
  check parsed.pubkey == kp.pubkey
  check parsed.comment == "test@nssh"
  let fp = fingerprintSha256(kp.pubkey)
  check fp.startsWith("SHA256:")
  check fp.len == 7 + 43 # unpadded base64 of 32 bytes
  expect SshKeyError:
    discard parseAuthorizedKeysLine("# just a comment")
  expect SshKeyError:
    discard parseAuthorizedKeysLine("ssh-rsa AAAA junk")
