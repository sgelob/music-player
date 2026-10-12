// MD5 (RFC 1321) and HMAC-MD5 (RFC 2104), as required by NTLMv2.
// Pure Swift so the package has no platform crypto dependency (and builds on Linux for tests).

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

enum MD5 {
    private static let s: [UInt32] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]
    private static let k: [UInt32] = (0..<64).map { i in
        UInt32(truncatingIfNeeded: Int64(abs(sin(Double(i + 1))) * 4_294_967_296.0))
    }

    static func hash(_ message: [UInt8]) -> [UInt8] {
        var a0: UInt32 = 0x6745_2301, b0: UInt32 = 0xefcd_ab89
        var c0: UInt32 = 0x98ba_dcfe, d0: UInt32 = 0x1032_5476

        let padded = mdPad(message)
        for chunk in stride(from: 0, to: padded.count, by: 64) {
            var m = [UInt32](repeating: 0, count: 16)
            for i in 0..<16 { m[i] = readLE32(padded, chunk + i * 4) }
            var a = a0, b = b0, c = c0, d = d0
            for i in 0..<64 {
                var f: UInt32
                let g: Int
                switch i {
                case 0..<16: f = (b & c) | (~b & d); g = i
                case 16..<32: f = (d & b) | (~d & c); g = (5 * i + 1) % 16
                case 32..<48: f = b ^ c ^ d; g = (3 * i + 5) % 16
                default: f = c ^ (b | ~d); g = (7 * i) % 16
                }
                f = f &+ a &+ k[i] &+ m[g]
                a = d; d = c; c = b
                b = b &+ rotl(f, s[i])
            }
            a0 = a0 &+ a; b0 = b0 &+ b; c0 = c0 &+ c; d0 = d0 &+ d
        }
        return [a0, b0, c0, d0].flatMap(le32Bytes)
    }

    static func hmac(key: [UInt8], message: [UInt8]) -> [UInt8] {
        var k = key.count > 64 ? hash(key) : key
        k += [UInt8](repeating: 0, count: 64 - k.count)
        let inner = hash(k.map { $0 ^ 0x36 } + message)
        return hash(k.map { $0 ^ 0x5c } + inner)
    }
}
