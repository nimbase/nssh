import std/unittest

import nssh/kex
import nssh/codec

test "powmod small vectors (python-verified)":
  check powModBE(@[5'u8], @[3'u8], @[13'u8]) == @[8'u8]
  check powModBE(@[2'u8], @[10'u8], @[3'u8, 232'u8]) == @[24'u8] # 2^10 mod 1000
  check powModBE(@[2'u8], @[1'u8, 0'u8], @[101'u8]) == @[37'u8] # 2^256 mod 101
  check modBE(@[100'u8], @[7'u8]) == @[2'u8]
  check mulModBE(@[7'u8, 8'u8], @[9'u8], @[100'u8]) == @[0'u8] # 1800*9=16200
  check mulModBE(@[7'u8, 8'u8], @[9'u8], @[101'u8]) == @[40'u8]
  check mulModBE(@[48'u8, 57'u8], @[26'u8, 133'u8], @[1'u8, 134'u8, 160'u8]) == @[39'u8, 221'u8] # 12345*6789=83810205 mod 100000=10205
  check modBE(@[63'u8, 72'u8], @[100'u8]) == @[0'u8] # shift-subtract regression: 100<<7 must be [50,0]

test "DH toy group agrees":
  let p = @[23'u8]
  let a = @[6'u8]
  let b = @[15'u8]
  let A = dhPublic(a, p)
  let B = dhPublic(b, p)
  check dhShared(B, a, p) == dhShared(A, b, p)
  expect SshKexError:
    discard dhShared(@[0'u8], a, p)

test "group14 prime size + g^a sanity":
  let p = group14Prime()
  check p.len == 256
  check p[0] == 0xFF'u8
  let pub = dhPublic(@[2'u8], p)
  check pub == @[4'u8]

test "x25519 RFC 7748 section 6.1 DH vector":
  let sPrivA = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
  let sPubA = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
  let sPrivB = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
  let sPubB = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
  let sOut = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
  proc hx(s: string): array[32, byte] =
    for i in 0 ..< 32:
      let hi = s[2*i]
      let lo = s[2*i+1]
      proc hv(c: char): int =
        case c
        of '0'..'9': int(c) - 48
        of 'a'..'f': int(c) - 87
        of 'A'..'F': int(c) - 55
        else: 0
      result[i] = byte(hv(hi) * 16 + hv(lo))
  var privA, pubB: array[32, byte]
  for i in 0 ..< 32:
    privA[i] = hx(sPrivA)[i]
    pubB[i] = hx(sPubB)[i]
  # pubkey derivation both sides
  check x25519Public(privA) == hx(sPubA)
  check x25519Public(hx(sPrivB)) == hx(sPubB)
  # shared secret both directions
  check x25519Shared(privA, pubB) == hx(sOut)
  check x25519Shared(hx(sPrivB), hx(sPubA)) == hx(sOut)
  # symmetry with generated keys
  let k1 = x25519GenKey()
  let k2 = x25519GenKey()
  check x25519Shared(k1.priv, k2.pub) == x25519Shared(k2.priv, k1.pub)

test "curve25519 exchange hash is deterministic + 32 bytes":
  var cE, sE: array[32, byte]
  for i in 0 ..< 32:
    cE[i] = byte(i)
    sE[i] = byte(32 + i)
  let h1 = curve25519ExchangeHash("SSH-2.0-a", "SSH-2.0-b",
    @[byte(20), 1], @[byte(20), 2], @[byte(9), 9], cE, sE, @[byte(0x42)])
  let h2 = curve25519ExchangeHash("SSH-2.0-a", "SSH-2.0-b",
    @[byte(20), 1], @[byte(20), 2], @[byte(9), 9], cE, sE, @[byte(0x42)])
  check h1 == h2
  check h1.len == 32

test "dh exchange hash + deriveKey expansion":
  let h = dhExchangeHash("SSH-2.0-a", "SSH-2.0-b",
    @[byte(20)], @[byte(20)], @[byte(1)], @[byte(2)], @[byte(3)], @[byte(4)])
  check h.len == 32
  var sid: array[32, byte]
  for i in 0 ..< 32: sid[i] = h[i]
  let k1 = deriveKey(@[byte(5)], h, sid, 'A', 32)
  let k2 = deriveKey(@[byte(5)], h, sid, 'B', 32)
  check k1.len == 32
  check k1 != k2
  let kLong = deriveKey(@[byte(5)], h, sid, 'A', 64)
  check kLong[0 ..< 32] == k1 # first block prefix
