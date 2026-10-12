import Foundation

/// Little-endian byte builder for SMB/NTLM wire structures.
struct ByteWriter {
    private(set) var bytes: [UInt8] = []

    var count: Int { bytes.count }

    mutating func u8(_ v: UInt8) { bytes.append(v) }
    mutating func u16(_ v: UInt16) { bytes += [UInt8(v & 0xff), UInt8(v >> 8)] }
    mutating func u32(_ v: UInt32) { bytes += le32Bytes(v) }
    mutating func u64(_ v: UInt64) { u32(UInt32(v & 0xffff_ffff)); u32(UInt32(v >> 32)) }
    mutating func append(_ b: [UInt8]) { bytes += b }
    mutating func zeros(_ n: Int) { bytes += [UInt8](repeating: 0, count: n) }

    /// Overwrites a previously written UInt16 (used for back-patching offsets/lengths).
    mutating func set16(_ v: UInt16, at i: Int) {
        bytes[i] = UInt8(v & 0xff); bytes[i + 1] = UInt8(v >> 8)
    }
}

/// Bounds-checked little-endian reader. Every read throws instead of trapping, because the
/// input comes from the network.
struct ByteReader {
    let bytes: [UInt8]
    var offset: Int

    init(_ bytes: [UInt8], offset: Int = 0) {
        self.bytes = bytes
        self.offset = offset
    }

    var remaining: Int { bytes.count - offset }

    mutating func u8() throws -> UInt8 {
        try need(1); defer { offset += 1 }
        return bytes[offset]
    }

    mutating func u16() throws -> UInt16 {
        try need(2); defer { offset += 2 }
        return UInt16(bytes[offset]) | UInt16(bytes[offset + 1]) << 8
    }

    mutating func u32() throws -> UInt32 {
        try need(4); defer { offset += 4 }
        return readLE32(bytes, offset)
    }

    mutating func u64() throws -> UInt64 {
        let lo = try u32(), hi = try u32()
        return UInt64(hi) << 32 | UInt64(lo)
    }

    mutating func take(_ n: Int) throws -> [UInt8] {
        try need(n); defer { offset += n }
        return Array(bytes[offset..<offset + n])
    }

    mutating func skip(_ n: Int) throws { try need(n); offset += n }

    func slice(_ start: Int, _ length: Int) throws -> [UInt8] {
        guard start >= 0, length >= 0, start + length <= bytes.count else { throw SMBError.malformedResponse }
        return Array(bytes[start..<start + length])
    }

    private func need(_ n: Int) throws {
        guard n >= 0, offset + n <= bytes.count else { throw SMBError.malformedResponse }
    }
}

extension String {
    var utf16LE: [UInt8] { utf16.flatMap { [UInt8($0 & 0xff), UInt8($0 >> 8)] } }

    init(utf16LE bytes: [UInt8]) {
        let units = stride(from: 0, to: bytes.count - 1, by: 2).map { UInt16(bytes[$0]) | UInt16(bytes[$0 + 1]) << 8 }
        self = String(decoding: units, as: UTF16.self)
    }
}

extension Array where Element == UInt8 {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        var out = [UInt8]()
        var chars = hex.makeIterator()
        while let a = chars.next() {
            guard let b = chars.next(), let v = UInt8(String([a, b]), radix: 16) else { return nil }
            out.append(v)
        }
        self = out
    }
}
