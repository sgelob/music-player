/// Minimal SPNEGO (RFC 4178) wrapping for NTLMSSP tokens.
///
/// Only the two shapes SMB1 extended-security session setup needs are produced. Responses are
/// not fully DER-parsed: the NTLMSSP token is located by its signature, which is robust against
/// the slightly different encodings servers produce.
enum SPNEGO {
    private static let spnegoOID: [UInt8] = [0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02]
    private static let ntlmOID: [UInt8] = [0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a]

    static func der(_ tag: UInt8, _ content: [UInt8]) -> [UInt8] {
        let n = content.count
        let length: [UInt8]
        switch n {
        case ..<0x80: length = [UInt8(n)]
        case ..<0x100: length = [0x81, UInt8(n)]
        default: length = [0x82, UInt8(n >> 8), UInt8(n & 0xff)]
        }
        return [tag] + length + content
    }

    /// GSS InitialContextToken { spnego OID, NegTokenInit { mechTypes [NTLMSSP], mechToken } }
    static func negTokenInit(ntlmToken: [UInt8]) -> [UInt8] {
        let mechTypes = der(0xa0, der(0x30, ntlmOID))
        let mechToken = der(0xa2, der(0x04, ntlmToken))
        let negTokenInit = der(0xa0, der(0x30, mechTypes + mechToken))
        return der(0x60, spnegoOID + negTokenInit)
    }

    /// NegTokenResp { responseToken }
    static func negTokenResp(ntlmToken: [UInt8]) -> [UInt8] {
        der(0xa1, der(0x30, der(0xa2, der(0x04, ntlmToken))))
    }

    /// Finds the embedded NTLMSSP message in a server security blob (or the blob itself if raw).
    static func extractNTLM(_ blob: [UInt8]) -> [UInt8]? {
        let sig = NTLM.signature
        guard blob.count >= sig.count else { return nil }
        for i in 0...(blob.count - sig.count) where blob[i] == 0x4e && Array(blob[i..<i + sig.count]) == sig {
            return Array(blob[i...])
        }
        return nil
    }
}
