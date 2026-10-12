// MD4 (RFC 1320). Needed only for the NT password hash used by NTLM.
// Implemented here because CryptoKit doesn't ship it and CommonCrypto's is deprecated.

enum MD4 {
    static func hash(_ message: [UInt8]) -> [UInt8] {
        var a0: UInt32 = 0x6745_2301, b0: UInt32 = 0xefcd_ab89
        var c0: UInt32 = 0x98ba_dcfe, d0: UInt32 = 0x1032_5476

        let padded = mdPad(message)
        for chunk in stride(from: 0, to: padded.count, by: 64) {
            var x = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 { x[i] = readLE32(padded, chunk + i * 4) }
            var a = a0, b = b0, c = c0, d = d0

            func f(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (~x & z) }
            func g(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { (x & y) | (x & z) | (y & z) }
            func h(_ x: UInt32, _ y: UInt32, _ z: UInt32) -> UInt32 { x ^ y ^ z }

            for i in [0, 4, 8, 12] {
                a = rotl(a &+ f(b, c, d) &+ x[i], 3)
                d = rotl(d &+ f(a, b, c) &+ x[i + 1], 7)
                c = rotl(c &+ f(d, a, b) &+ x[i + 2], 11)
                b = rotl(b &+ f(c, d, a) &+ x[i + 3], 19)
            }
            for i in [0, 1, 2, 3] {
                a = rotl(a &+ g(b, c, d) &+ x[i] &+ 0x5a82_7999, 3)
                d = rotl(d &+ g(a, b, c) &+ x[i + 4] &+ 0x5a82_7999, 5)
                c = rotl(c &+ g(d, a, b) &+ x[i + 8] &+ 0x5a82_7999, 9)
                b = rotl(b &+ g(c, d, a) &+ x[i + 12] &+ 0x5a82_7999, 13)
            }
            for i in [0, 2, 1, 3] {
                a = rotl(a &+ h(b, c, d) &+ x[i] &+ 0x6ed9_eba1, 3)
                d = rotl(d &+ h(a, b, c) &+ x[i + 8] &+ 0x6ed9_eba1, 9)
                c = rotl(c &+ h(d, a, b) &+ x[i + 4] &+ 0x6ed9_eba1, 11)
                b = rotl(b &+ h(c, d, a) &+ x[i + 12] &+ 0x6ed9_eba1, 15)
            }
            a0 = a0 &+ a; b0 = b0 &+ b; c0 = c0 &+ c; d0 = d0 &+ d
        }
        return [a0, b0, c0, d0].flatMap(le32Bytes)
    }
}

// MARK: - Shared helpers for the MD-family hashes

@inline(__always) func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 { (x << n) | (x >> (32 - n)) }

@inline(__always) func readLE32(_ b: [UInt8], _ i: Int) -> UInt32 {
    UInt32(b[i]) | UInt32(b[i + 1]) << 8 | UInt32(b[i + 2]) << 16 | UInt32(b[i + 3]) << 24
}

@inline(__always) func le32Bytes(_ v: UInt32) -> [UInt8] {
    [UInt8(v & 0xff), UInt8((v >> 8) & 0xff), UInt8((v >> 16) & 0xff), UInt8(v >> 24)]
}

/// Merkle–Damgård padding shared by MD4 and MD5 (little-endian bit length).
func mdPad(_ message: [UInt8]) -> [UInt8] {
    var p = message
    let bitLength = UInt64(message.count) &* 8
    p.append(0x80)
    while p.count % 64 != 56 { p.append(0) }
    for i in 0..<8 { p.append(UInt8((bitLength >> (8 * UInt64(i))) & 0xff)) }
    return p
}
