import XCTest
@testable import TimeCapsuleKit

final class CryptoTests: XCTestCase {
    func testMD4() {
        XCTAssertEqual(MD4.hash([]).hex, "31d6cfe0d16ae931b73c59d7e0c089c0")
        XCTAssertEqual(MD4.hash(Array("abc".utf8)).hex, "a448017aaf21d8525fc10ae87aa6729d")
        XCTAssertEqual(MD4.hash(Array("12345678901234567890123456789012345678901234567890123456789012345678901234567890".utf8)).hex,
                       "e33b4ddc9c38f2199c3e7b164fcc0536")
    }

    func testMD5() {
        XCTAssertEqual(MD5.hash([]).hex, "d41d8cd98f00b204e9800998ecf8427e")
        XCTAssertEqual(MD5.hash(Array("The quick brown fox jumps over the lazy dog".utf8)).hex,
                       "9e107d9d372bb6826bd81d3542a419d6")
    }

    func testHMACMD5() {
        XCTAssertEqual(MD5.hmac(key: [UInt8](repeating: 0x0b, count: 16), message: Array("Hi There".utf8)).hex,
                       "9294727a3638bb1c13f48ef8158bfc9d")
    }

    func testDES() {
        let out = DES.encryptBlock(key: [UInt8](hex: "133457799BBCDFF1")!, block: [UInt8](hex: "0123456789ABCDEF")!)
        XCTAssertEqual(out.hex, "85e813540f0ab405")
    }
}

/// Test vectors from MS-NLMP section 4.2.
final class NTLMTests: XCTestCase {
    let serverChallenge = [UInt8](hex: "0123456789abcdef")!
    let clientChallenge = [UInt8](repeating: 0xaa, count: 8)

    func testNTHash() {
        XCTAssertEqual(NTLM.ntHash(password: "Password").hex, "a4f49c406510bdcab6824ee7c30fd852")
    }

    func testV1() {
        XCTAssertEqual(NTLM.v1Response(password: "Password", serverChallenge: serverChallenge).hex,
                       "67c43011f30298a2ad35ece64f16331c44bdbed927841f94")
    }

    func testV2() {
        XCTAssertEqual(NTLM.ntowfv2(password: "Password", user: "User", domain: "Domain").hex,
                       "0c868a403bfd7a93a3001ef22ef02e3f")
        var info = ByteWriter()
        info.u16(2); info.u16(12); info.append("Domain".utf16LE)
        info.u16(1); info.u16(12); info.append("Server".utf16LE)
        info.u32(0)
        let (lm, nt) = NTLM.v2Responses(
            password: "Password", user: "User", domain: "Domain",
            serverChallenge: serverChallenge, clientChallenge: clientChallenge,
            timestamp: 0, targetInfo: info.bytes)
        XCTAssertEqual(lm.hex, "86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
        XCTAssertEqual(Array(nt.prefix(16)).hex, "68cd0ab851e51c96aabc927bebef6a1c")
    }

    func testSPNEGORoundTrip() {
        let token = NTLM.negotiateMessage(version: .v2)
        let wrapped = SPNEGO.negTokenInit(ntlmToken: token)
        XCTAssertEqual(SPNEGO.extractNTLM(wrapped), token)
    }

    func testPaths() {
        XCTAssertEqual(SMB1Session.smbPath(""), "\\")
        XCTAssertEqual(SMB1Session.smbPath("Music/Artist/"), "\\Music\\Artist")
    }
}
