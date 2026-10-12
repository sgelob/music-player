import Foundation

/// NTLM challenge/response computation (MS-NLMP).
///
/// AirPort Time Capsules run an old SMB1 server. Depending on firmware it accepts NTLMv2 or only
/// NTLMv1, so the client supports both and tries v2 first.
public enum NTLMVersion: String, Codable, CaseIterable, Sendable {
    case v2, v1
}

enum NTLM {
    static func ntHash(password: String) -> [UInt8] { MD4.hash(password.utf16LE) }

    // MARK: v1

    /// DESL(): the 16-byte hash is zero-padded to 21 bytes and split into three DES keys.
    static func desl(_ hash16: [UInt8], _ challenge: [UInt8]) -> [UInt8] {
        let k = hash16 + [UInt8](repeating: 0, count: 5)
        return (0..<3).flatMap { i in
            DES.encryptBlock(key: DES.expandKey(Array(k[i * 7..<i * 7 + 7])), block: challenge)
        }
    }

    static func v1Response(password: String, serverChallenge: [UInt8]) -> [UInt8] {
        desl(ntHash(password: password), serverChallenge)
    }

    // MARK: v2

    static func ntowfv2(password: String, user: String, domain: String) -> [UInt8] {
        MD5.hmac(key: ntHash(password: password), message: (user.uppercased() + domain).utf16LE)
    }

    /// Returns (LMv2 response, NTLMv2 response).
    static func v2Responses(
        password: String, user: String, domain: String,
        serverChallenge: [UInt8], clientChallenge: [UInt8],
        timestamp: UInt64, targetInfo: [UInt8]
    ) -> (lm: [UInt8], nt: [UInt8]) {
        let key = ntowfv2(password: password, user: user, domain: domain)
        var blob = ByteWriter()
        blob.u8(1); blob.u8(1); blob.zeros(6)
        blob.u64(timestamp)
        blob.append(clientChallenge)
        blob.zeros(4)
        blob.append(targetInfo)
        blob.zeros(4)
        let proof = MD5.hmac(key: key, message: serverChallenge + blob.bytes)
        let lm = MD5.hmac(key: key, message: serverChallenge + clientChallenge) + clientChallenge
        return (lm, proof + blob.bytes)
    }

    /// Windows FILETIME: 100ns ticks since 1601-01-01.
    static func fileTime(_ date: Date = Date()) -> UInt64 {
        UInt64((date.timeIntervalSince1970 + 11_644_473_600) * 10_000_000)
    }

    static func randomBytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255) } }

    // MARK: NTLMSSP messages (for SMB1 "extended security")

    static let signature: [UInt8] = Array("NTLMSSP".utf8) + [0]

    struct Flags {
        static let unicode: UInt32 = 0x0000_0001
        static let requestTarget: UInt32 = 0x0000_0004
        static let ntlm: UInt32 = 0x0000_0200
        static let alwaysSign: UInt32 = 0x0000_8000
        static let extendedSessionSecurity: UInt32 = 0x0008_0000
        static let targetInfo: UInt32 = 0x0080_0000
        static let bits128: UInt32 = 0x2000_0000
        static let bits56: UInt32 = 0x8000_0000
    }

    static func negotiateFlags(for version: NTLMVersion) -> UInt32 {
        var f = Flags.unicode | Flags.requestTarget | Flags.ntlm | Flags.alwaysSign | Flags.bits128 | Flags.bits56
        // ESS changes how v1 responses are computed; we only want plain v1, so request it for v2 only.
        if version == .v2 { f |= Flags.extendedSessionSecurity | Flags.targetInfo }
        return f
    }

    static func negotiateMessage(version: NTLMVersion) -> [UInt8] {
        var w = ByteWriter()
        w.append(signature)
        w.u32(1)
        w.u32(negotiateFlags(for: version))
        w.zeros(16) // empty domain + workstation
        return w.bytes
    }

    struct Challenge {
        var flags: UInt32
        var serverChallenge: [UInt8]
        var targetInfo: [UInt8]
    }

    static func parseChallenge(_ msg: [UInt8]) throws -> Challenge {
        guard msg.count >= 32, Array(msg[0..<8]) == signature else { throw SMBError.malformedResponse }
        var r = ByteReader(msg, offset: 8)
        guard try r.u32() == 2 else { throw SMBError.malformedResponse }
        _ = try r.take(8) // target name
        let flags = try r.u32()
        let challenge = try r.take(8)
        var targetInfo: [UInt8] = []
        if msg.count >= 48 {
            try r.skip(8)
            let len = Int(try r.u16()); _ = try r.u16()
            let off = Int(try r.u32())
            targetInfo = (try? r.slice(off, len)) ?? []
        }
        return Challenge(flags: flags, serverChallenge: challenge, targetInfo: targetInfo)
    }

    static func authenticateMessage(
        challenge: Challenge, version: NTLMVersion,
        user: String, password: String, domain: String, workstation: String
    ) -> [UInt8] {
        let lm: [UInt8], nt: [UInt8]
        switch version {
        case .v2:
            (lm, nt) = v2Responses(
                password: password, user: user, domain: domain,
                serverChallenge: challenge.serverChallenge, clientChallenge: randomBytes(8),
                timestamp: fileTime(), targetInfo: challenge.targetInfo)
        case .v1:
            nt = v1Response(password: password, serverChallenge: challenge.serverChallenge)
            lm = nt
        }
        let fields: [[UInt8]] = [lm, nt, domain.utf16LE, user.utf16LE, workstation.utf16LE, []]
        let headerSize = 64
        var w = ByteWriter()
        w.append(signature)
        w.u32(3)
        var offset = headerSize
        for field in fields {
            w.u16(UInt16(field.count)); w.u16(UInt16(field.count)); w.u32(UInt32(offset))
            offset += field.count
        }
        w.u32(negotiateFlags(for: version) & challenge.flags | Flags.unicode)
        for field in fields { w.append(field) }
        return w.bytes
    }
}
