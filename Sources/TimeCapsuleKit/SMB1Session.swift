import Foundation

public struct SMBCredentials: Hashable, Sendable {
    public var user: String
    public var password: String
    public var domain: String

    public init(user: String, password: String, domain: String = "") {
        self.user = user
        self.password = password
        self.domain = domain
    }
}

/// How a server was successfully authenticated, so reconnects skip the trial and error.
public struct SMBAuthMethod: Hashable, Codable, Sendable, CustomStringConvertible {
    public var extendedSecurity: Bool
    public var ntlm: NTLMVersion

    public init(extendedSecurity: Bool, ntlm: NTLMVersion) {
        self.extendedSecurity = extendedSecurity
        self.ntlm = ntlm
    }

    public static let allInPreferenceOrder: [SMBAuthMethod] = [
        .init(extendedSecurity: true, ntlm: .v2),
        .init(extendedSecurity: false, ntlm: .v2),
        .init(extendedSecurity: false, ntlm: .v1),
        .init(extendedSecurity: true, ntlm: .v1),
    ]

    public var description: String { "NTLM\(ntlm.rawValue)\(extendedSecurity ? "+NTLMSSP" : "")" }
}

public struct SMBShare: Hashable, Sendable {
    public var name: String
    public var comment: String
    public var isDisk: Bool
}

public struct SMBDirectoryEntry: Hashable, Sendable {
    public var name: String
    public var isDirectory: Bool
    public var size: UInt64
    public var modified: Date
}

public struct SMBFileHandle: Hashable, Sendable {
    let fid: UInt16
    public let size: UInt64
}

/// One SMB1 ("NT LM 0.12") session over one TCP connection. Synchronous and not thread-safe:
/// `SMBClient` owns it on a serial queue. Implements just what a read-only media browser needs.
///
/// Why SMB1: AirPort Time Capsules only speak SMB1 (and AFP), and iOS's own SMB client dropped
/// SMB1, which is why the Files app can't open a Time Capsule.
public final class SMB1Session {
    public let host: String
    public let port: UInt16

    private let transport: Transport
    private var uid: UInt16 = 0
    private var tid: UInt16 = 0
    private var nextMID: UInt16 = 1
    private let pid = UInt16.random(in: 1...0xfffe)

    // Negotiated parameters
    private var extendedSecurity = false
    private var userLevelSecurity = true
    private var encryptPasswords = true
    private var serverChallenge: [UInt8] = []
    private var serverSecurityBlob: [UInt8] = []
    private var maxBufferSize = 4356
    private var maxMpx = 1
    private var capabilities: UInt32 = 0
    private var credentials: SMBCredentials?

    public private(set) var connectedShare: String?

    private enum Cmd {
        static let close: UInt8 = 0x04
        static let transaction: UInt8 = 0x25
        static let echo: UInt8 = 0x2B
        static let readAndX: UInt8 = 0x2E
        static let transaction2: UInt8 = 0x32
        static let treeDisconnect: UInt8 = 0x71
        static let negotiate: UInt8 = 0x72
        static let sessionSetupAndX: UInt8 = 0x73
        static let logoffAndX: UInt8 = 0x74
        static let treeConnectAndX: UInt8 = 0x75
        static let ntCreateAndX: UInt8 = 0xA2
    }

    private enum Cap {
        static let unicode: UInt32 = 0x0004
        static let largeFiles: UInt32 = 0x0008
        static let ntSMBs: UInt32 = 0x0010
        static let ntStatus: UInt32 = 0x0040
        static let largeReadX: UInt32 = 0x4000
        static let extendedSecurity: UInt32 = 0x8000_0000
    }

    public init(host: String, port: UInt16 = 445, timeout: TimeInterval = 15) throws {
        self.host = host
        self.port = port
        transport = try Transport(host: host, port: port, timeout: timeout)
    }

    deinit { transport.close() }

    // MARK: - Session lifecycle

    /// Connects (trying port 445, then 139) and authenticates, trying each auth method in turn
    /// on a fresh connection until one works.
    public static func open(
        host: String, port: UInt16? = nil, credentials: SMBCredentials,
        methods: [SMBAuthMethod] = SMBAuthMethod.allInPreferenceOrder, timeout: TimeInterval = 15
    ) throws -> (SMB1Session, SMBAuthMethod) {
        var lastError: SMBError?
        var resolvedPort = port
        for method in methods {
            let session: SMB1Session
            if let p = resolvedPort {
                session = try SMB1Session(host: host, port: p, timeout: timeout)
            } else {
                do {
                    session = try SMB1Session(host: host, port: 445, timeout: timeout)
                } catch SMBError.connectionFailed {
                    session = try SMB1Session(host: host, port: 139, timeout: timeout)
                }
                resolvedPort = session.port
            }
            do {
                try session.negotiate(extendedSecurity: method.extendedSecurity)
                // The server picks the mode; skip methods it effectively already covered.
                if session.extendedSecurity != method.extendedSecurity,
                   methods.contains(.init(extendedSecurity: session.extendedSecurity, ntlm: method.ntlm)) {
                    continue
                }
                try session.login(credentials, ntlm: method.ntlm)
                return (session, .init(extendedSecurity: session.extendedSecurity, ntlm: method.ntlm))
            } catch let error as SMBError {
                // Servers reject methods they don't allow in different ways (e.g. Samba answers
                // INVALID_PARAMETER to NTLMv2 without NTLMSSP), so any failure means "try the next".
                // Report a wrong password over a rejected method.
                if lastError != .authenticationFailed { lastError = error }
                if case .unsupportedServer = error { throw error }
            }
        }
        throw lastError ?? .authenticationFailed
    }

    func negotiate(extendedSecurity wantExtended: Bool) throws {
        let dialects: [UInt8] = [0x02] + Array("NT LM 0.12".utf8) + [0]
        let resp = try roundTrip(Cmd.negotiate, words: [], bytes: dialects, extendedSecurity: wantExtended)
        var r = ByteReader(resp.words)
        guard resp.words.count >= 34, try r.u16() == 0 else {
            throw SMBError.unsupportedServer("server doesn't speak NT LM 0.12")
        }
        let securityMode = try r.u8()
        userLevelSecurity = securityMode & 0x01 != 0
        encryptPasswords = securityMode & 0x02 != 0
        if securityMode & 0x08 != 0 {
            throw SMBError.unsupportedServer("server requires SMB signing")
        }
        maxMpx = max(1, Int(try r.u16()))
        _ = try r.u16() // max VCs
        maxBufferSize = Int(try r.u32())
        _ = try r.u32() // max raw
        _ = try r.u32() // session key
        capabilities = try r.u32()
        _ = try r.u64() // system time
        _ = try r.u16() // time zone
        let challengeLength = Int(try r.u8())

        extendedSecurity = capabilities & Cap.extendedSecurity != 0 && resp.flags2 & Flags2.extendedSecurity != 0
        if extendedSecurity {
            serverSecurityBlob = resp.bytes.count > 16 ? Array(resp.bytes[16...]) : []
        } else {
            serverChallenge = Array(resp.bytes.prefix(challengeLength))
        }
    }

    func login(_ creds: SMBCredentials, ntlm: NTLMVersion) throws {
        credentials = creds
        uid = 0
        if extendedSecurity {
            try loginExtended(creds, ntlm: ntlm)
        } else {
            try loginBasic(creds, ntlm: ntlm)
        }
    }

    private var clientCaps: UInt32 {
        Cap.unicode | Cap.largeFiles | Cap.ntSMBs | Cap.ntStatus | Cap.largeReadX
    }

    private func loginBasic(_ c: SMBCredentials, ntlm: NTLMVersion) throws {
        var lm: [UInt8] = [], nt: [UInt8] = []
        if userLevelSecurity, encryptPasswords {
            switch ntlm {
            case .v1:
                nt = NTLM.v1Response(password: c.password, serverChallenge: serverChallenge)
                lm = nt
            case .v2:
                // Minimal target info (just MsvAvEOL); the server only uses it inside the HMAC.
                (lm, nt) = NTLM.v2Responses(
                    password: c.password, user: c.user, domain: c.domain,
                    serverChallenge: serverChallenge, clientChallenge: NTLM.randomBytes(8),
                    timestamp: NTLM.fileTime(), targetInfo: [0, 0, 0, 0])
            }
        } else if userLevelSecurity {
            lm = Array(c.password.utf8) + [0] // plaintext; only if the server asks for it
        }

        var w = ByteWriter()
        w.u8(0xFF); w.u8(0); w.u16(0) // no AndX
        w.u16(UInt16(min(maxBufferSize, 0xFFFF)))
        w.u16(UInt16(min(maxMpx, 50)))
        w.u16(0) // VC number
        w.u32(0) // session key
        w.u16(UInt16(lm.count))
        w.u16(UInt16(nt.count))
        w.u32(0)
        w.u32(clientCaps)

        var b = ByteWriter()
        b.append(lm); b.append(nt)
        let start = 32 + 1 + w.count + 2
        if (start + b.count) % 2 == 1 { b.u8(0) }
        for s in [c.user, c.domain, "iOS", "TimeCapsuleMusic"] { b.append(s.utf16LE + [0, 0]) }

        let resp = try roundTrip(Cmd.sessionSetupAndX, words: w.bytes, bytes: b.bytes, allowStatus: [])
        uid = resp.uid
    }

    private func loginExtended(_ c: SMBCredentials, ntlm: NTLMVersion) throws {
        let first = try sessionSetupExtended(blob: SPNEGO.negTokenInit(ntlmToken: NTLM.negotiateMessage(version: ntlm)))
        guard first.status == NTStatus.moreProcessingRequired else { throw SMBError.authenticationFailed }
        uid = first.uid
        guard let challengeMsg = SPNEGO.extractNTLM(securityBlob(first)) else { throw SMBError.malformedResponse }
        let challenge = try NTLM.parseChallenge(challengeMsg)
        let auth = NTLM.authenticateMessage(
            challenge: challenge, version: ntlm, user: c.user, password: c.password,
            domain: c.domain, workstation: "IOS")
        _ = try sessionSetupExtended(blob: SPNEGO.negTokenResp(ntlmToken: auth))
    }

    private func sessionSetupExtended(blob: [UInt8]) throws -> Response {
        var w = ByteWriter()
        w.u8(0xFF); w.u8(0); w.u16(0)
        w.u16(UInt16(min(maxBufferSize, 0xFFFF)))
        w.u16(UInt16(min(maxMpx, 50)))
        w.u16(0)
        w.u32(0)
        w.u16(UInt16(blob.count))
        w.u32(0)
        w.u32(clientCaps | Cap.extendedSecurity)

        var b = ByteWriter()
        b.append(blob)
        if (32 + 1 + w.count + 2 + b.count) % 2 == 1 { b.u8(0) }
        for s in ["iOS", "TimeCapsuleMusic"] { b.append(s.utf16LE + [0, 0]) }
        return try roundTrip(Cmd.sessionSetupAndX, words: w.bytes, bytes: b.bytes,
                             allowStatus: [NTStatus.moreProcessingRequired])
    }

    private func securityBlob(_ resp: Response) -> [UInt8] {
        guard resp.words.count >= 8 else { return [] }
        let len = Int(resp.words[6]) | Int(resp.words[7]) << 8
        return Array(resp.bytes.prefix(len))
    }

    public func connectShare(_ share: String) throws {
        try treeConnect(share, service: "?????")
        connectedShare = share
    }

    private func treeConnect(_ share: String, service: String) throws {
        var password: [UInt8] = [0]
        if !userLevelSecurity, let c = credentials {
            // Share-level security: the password goes with the tree connect instead.
            password = encryptPasswords
                ? NTLM.v1Response(password: c.password, serverChallenge: serverChallenge)
                : Array(c.password.utf8) + [0]
        }
        var w = ByteWriter()
        w.u8(0xFF); w.u8(0); w.u16(0)
        w.u16(0x0008) // extended response
        w.u16(UInt16(password.count))
        var b = ByteWriter()
        b.append(password)
        if (32 + 1 + w.count + 2 + b.count) % 2 == 1 { b.u8(0) }
        b.append("\\\\\(host.uppercased())\\\(share)".utf16LE + [0, 0])
        b.append(Array(service.utf8) + [0])
        do {
            let resp = try roundTrip(Cmd.treeConnectAndX, words: w.bytes, bytes: b.bytes)
            tid = resp.tid
        } catch SMBError.status(NTStatus.badNetworkName, _) {
            throw SMBError.shareNotFound(share)
        }
    }

    public func disconnect() {
        if tid != 0 { _ = try? roundTrip(Cmd.treeDisconnect, words: [], bytes: []) }
        if uid != 0 { _ = try? roundTrip(Cmd.logoffAndX, words: [0xFF, 0, 0, 0], bytes: []) }
        tid = 0; uid = 0
        transport.close()
    }

    /// Cheap liveness check.
    public func echo() throws {
        var w = ByteWriter(); w.u16(1)
        _ = try roundTrip(Cmd.echo, words: w.bytes, bytes: [0x54, 0x43])
    }

    // MARK: - Shares

    /// Lists shares with the RAP NetShareEnum call over \PIPE\LANMAN, the call old SMB1 servers
    /// support. Leaves the session connected to whatever share it was on before.
    public func listShares() throws -> [SMBShare] {
        let previousTID = tid
        try treeConnect("IPC$", service: "?????")
        defer {
            _ = try? roundTrip(Cmd.treeDisconnect, words: [], bytes: [])
            tid = previousTID
        }
        let bufferSize: UInt16 = 0x1000
        var params = ByteWriter()
        params.u16(0) // NetShareEnum
        params.append(Array("WrLeh".utf8) + [0])
        params.append(Array("B13BWz".utf8) + [0])
        params.u16(1) // info level
        params.u16(bufferSize)
        let (rp, rd) = try transaction(
            Cmd.transaction, setup: [], name: "\\PIPE\\LANMAN".utf16LE + [0, 0],
            params: params.bytes, data: [], maxParams: 8, maxData: bufferSize)
        var r = ByteReader(rp)
        let status = try r.u16()
        guard status == 0 || status == 234 else { throw SMBError.status(UInt32(status), command: Cmd.transaction) }
        let converter = Int(try r.u16())
        let count = Int(try r.u16())
        var shares: [SMBShare] = []
        let data = ByteReader(rd)
        for i in 0..<count {
            let entry = try data.slice(i * 20, 20)
            let name = String(decoding: entry[0..<13].prefix { $0 != 0 }, as: UTF8.self)
            let type = UInt16(entry[14]) | UInt16(entry[15]) << 8
            let remarkOffset = (Int(entry[16]) | Int(entry[17]) << 8) - converter
            var comment = ""
            if remarkOffset >= 0, remarkOffset < rd.count {
                comment = String(decoding: rd[remarkOffset...].prefix { $0 != 0 }, as: UTF8.self)
            }
            shares.append(SMBShare(name: name, comment: comment, isDisk: type & 0xFF == 0))
        }
        return shares
    }

    // MARK: - Directories

    public func listDirectory(_ path: String) throws -> [SMBDirectoryEntry] {
        let pattern = Self.smbPath(path) == "\\" ? "\\*" : Self.smbPath(path) + "\\*"
        let level: UInt16 = 0x0101 // SMB_FIND_FILE_DIRECTORY_INFO
        let attributes: UInt16 = 0x0016 // include hidden, system and directories
        let maxData = UInt16(clamping: max(4096, min(maxBufferSize - 512, 60 * 1024)))

        var p = ByteWriter()
        p.u16(attributes); p.u16(1024); p.u16(0x0002) // close at end of search
        p.u16(level); p.u32(0)
        p.append(pattern.utf16LE + [0, 0])

        var entries: [SMBDirectoryEntry] = []
        let rp: [UInt8], rd: [UInt8]
        do {
            (rp, rd) = try transaction(Cmd.transaction2, setup: [0x0001], name: nil,
                                       params: p.bytes, data: [], maxParams: 10, maxData: maxData)
        } catch SMBError.status(let s, _) where s == NTStatus.noSuchFile || s == NTStatus.noMoreFiles {
            return []
        } catch SMBError.status(let s, _) where s == NTStatus.objectNameNotFound || s == NTStatus.objectPathNotFound {
            throw SMBError.notFound(path)
        }
        var r = ByteReader(rp)
        let sid = try r.u16()
        _ = try r.u16()
        var endOfSearch = try r.u16() != 0
        var lastName = try Self.parseDirectoryInfo(rd, into: &entries)

        while !endOfSearch, let resumeName = lastName {
            var n = ByteWriter()
            n.u16(sid); n.u16(1024); n.u16(level); n.u32(0)
            n.u16(0x0002 | 0x0008) // close at end, continue from last
            n.append(resumeName.utf16LE + [0, 0])
            let (np, nd): ([UInt8], [UInt8])
            do {
                (np, nd) = try transaction(Cmd.transaction2, setup: [0x0002], name: nil,
                                           params: n.bytes, data: [], maxParams: 8, maxData: maxData)
            } catch SMBError.status(NTStatus.noMoreFiles, _) { break }
            var nr = ByteReader(np)
            let count = try nr.u16()
            endOfSearch = try nr.u16() != 0
            lastName = try Self.parseDirectoryInfo(nd, into: &entries)
            if count == 0 { break }
        }
        return entries.filter { $0.name != "." && $0.name != ".." }
    }

    /// Parses SMB_FIND_FILE_DIRECTORY_INFO records; returns the last file name (resume point).
    private static func parseDirectoryInfo(_ data: [UInt8], into entries: inout [SMBDirectoryEntry]) throws -> String? {
        var offset = 0
        var last: String?
        while offset + 64 <= data.count {
            var r = ByteReader(data, offset: offset)
            let next = Int(try r.u32())
            _ = try r.u32() // file index
            _ = try r.u64() // created
            _ = try r.u64() // accessed
            let written = try r.u64()
            _ = try r.u64() // changed
            let size = try r.u64()
            _ = try r.u64() // allocation
            let attrs = try r.u32()
            let nameLength = Int(try r.u32())
            // Tolerate a record cut off at the buffer limit: keep what parsed rather than fail the folder.
            guard nameLength <= r.remaining else { break }
            var nameBytes = try r.take(nameLength)
            while nameBytes.count >= 2, nameBytes.suffix(2) == [0, 0] { nameBytes.removeLast(2) }
            let name = String(utf16LE: nameBytes)
            entries.append(SMBDirectoryEntry(
                name: name, isDirectory: attrs & 0x10 != 0, size: size, modified: Self.date(fromFileTime: written)))
            last = name
            if next == 0 { break }
            offset += next
        }
        return last
    }

    static func date(fromFileTime t: UInt64) -> Date {
        Date(timeIntervalSince1970: Double(t) / 10_000_000 - 11_644_473_600)
    }

    // MARK: - Files

    public func open(_ path: String) throws -> SMBFileHandle {
        let name = Self.smbPath(path).utf16LE
        var w = ByteWriter()
        w.u8(0xFF); w.u8(0); w.u16(0)
        w.u8(0) // reserved
        w.u16(UInt16(name.count))
        w.u32(0) // flags
        w.u32(0) // root dir
        w.u32(0x0012_0089) // read data, read EA, read attributes, read control, synchronize
        w.u64(0) // allocation size
        w.u32(0) // attributes
        w.u32(0x0000_0003) // share read | write
        w.u32(1) // FILE_OPEN
        w.u32(0x0000_0040) // FILE_NON_DIRECTORY_FILE
        w.u32(2) // impersonation
        w.u8(0)
        var b = ByteWriter()
        if (32 + 1 + w.count + 2) % 2 == 1 { b.u8(0) }
        b.append(name + [0, 0])
        let resp: Response
        do {
            resp = try roundTrip(Cmd.ntCreateAndX, words: w.bytes, bytes: b.bytes)
        } catch SMBError.status(let s, _) where s == NTStatus.objectNameNotFound || s == NTStatus.objectPathNotFound {
            throw SMBError.notFound(path)
        } catch SMBError.status(NTStatus.accessDenied, _) {
            throw SMBError.accessDenied
        }
        var r = ByteReader(resp.words, offset: 5)
        let fid = try r.u16()
        r.offset = 55
        let size = try r.u64()
        return SMBFileHandle(fid: fid, size: size)
    }

    /// Largest payload a single READ_ANDX may return.
    public var maxReadSize: Int {
        capabilities & Cap.largeReadX != 0 ? 60 * 1024 : max(1024, maxBufferSize - 64)
    }

    /// Reads up to `length` bytes, keeping several READ_ANDX requests in flight to hide Wi-Fi
    /// latency. Returns fewer bytes only at end of file.
    public func read(_ file: SMBFileHandle, offset: UInt64, length: Int) throws -> [UInt8] {
        let end = min(file.size, offset + UInt64(length))
        guard end > offset else { return [] }
        let chunk = UInt64(maxReadSize)
        let window = max(1, min(maxMpx - 1, 8))

        var pending: [UInt16: UInt64] = [:] // MID -> offset
        var pieces: [UInt64: [UInt8]] = [:]
        var nextOffset = offset
        while nextOffset < end || !pending.isEmpty {
            while pending.count < window, nextOffset < end {
                let count = min(chunk, end - nextOffset)
                let mid = try sendRead(file, offset: nextOffset, count: Int(count))
                pending[mid] = nextOffset
                nextOffset += count
            }
            let resp = try receive()
            guard let at = pending.removeValue(forKey: resp.mid) else { continue }
            if resp.status == NTStatus.endOfFile { pieces[at] = []; continue }
            try check(resp, allowStatus: [])
            pieces[at] = try readPayload(resp)
        }
        var out: [UInt8] = []
        out.reserveCapacity(Int(end - offset))
        for key in pieces.keys.sorted() {
            guard key == offset + UInt64(out.count) else { break } // short read: stop at the gap
            out += pieces[key]!
        }
        return out
    }

    private func sendRead(_ file: SMBFileHandle, offset: UInt64, count: Int) throws -> UInt16 {
        var w = ByteWriter()
        w.u8(0xFF); w.u8(0); w.u16(0)
        w.u16(file.fid)
        w.u32(UInt32(offset & 0xffff_ffff))
        w.u16(UInt16(count & 0xffff))
        w.u16(UInt16(count & 0xffff))
        w.u32(UInt32(count >> 16)) // MaxCountHigh
        w.u16(0)
        w.u32(UInt32(offset >> 32))
        return try send(Cmd.readAndX, words: w.bytes, bytes: [])
    }

    private func readPayload(_ resp: Response) throws -> [UInt8] {
        var r = ByteReader(resp.words, offset: 10)
        let lengthLow = Int(try r.u16())
        let dataOffset = Int(try r.u16())
        let lengthHigh = Int(try r.u16())
        let length = lengthHigh << 16 | lengthLow
        return try ByteReader(resp.raw).slice(dataOffset, length)
    }

    public func close(_ file: SMBFileHandle) throws {
        var w = ByteWriter()
        w.u16(file.fid)
        w.u32(0xFFFF_FFFF)
        _ = try roundTrip(Cmd.close, words: w.bytes, bytes: [])
    }

    /// "Music/Artist" -> "\Music\Artist"
    static func smbPath(_ path: String) -> String {
        let parts = path.split(whereSeparator: { $0 == "/" || $0 == "\\" })
        return "\\" + parts.joined(separator: "\\")
    }

    // MARK: - Transactions

    /// SMB_COM_TRANSACTION / TRANSACTION2. Requests are always sent in one piece; responses may
    /// arrive in several and are reassembled by displacement.
    private func transaction(
        _ command: UInt8, setup: [UInt16], name: [UInt8]?,
        params: [UInt8], data: [UInt8], maxParams: UInt16, maxData: UInt16
    ) throws -> ([UInt8], [UInt8]) {
        let wordCount = 14 + setup.count
        let bytesStart = 32 + 1 + wordCount * 2 + 2
        var b = ByteWriter()
        if let name {
            if bytesStart % 2 == 1 { b.u8(0) }
            b.append(name)
        }
        while (bytesStart + b.count) % 4 != 0 { b.u8(0) }
        let paramOffset = bytesStart + b.count
        b.append(params)
        while (bytesStart + b.count) % 4 != 0 { b.u8(0) }
        let dataOffset = bytesStart + b.count
        b.append(data)

        var w = ByteWriter()
        w.u16(UInt16(params.count)); w.u16(UInt16(data.count))
        w.u16(maxParams); w.u16(maxData)
        w.u8(0); w.u8(0) // max setup, reserved
        w.u16(0) // flags
        w.u32(0) // timeout
        w.u16(0)
        w.u16(UInt16(params.count)); w.u16(UInt16(paramOffset))
        w.u16(UInt16(data.count)); w.u16(UInt16(data.isEmpty ? 0 : dataOffset))
        w.u8(UInt8(setup.count)); w.u8(0)
        for s in setup { w.u16(s) }

        let mid = try send(command, words: w.bytes, bytes: b.bytes)
        var outParams: [UInt8]?, outData: [UInt8]?
        var gotParams = 0, gotData = 0
        while true {
            let resp = try receive()
            guard resp.mid == mid else { continue }
            try check(resp, allowStatus: [NTStatus.noMoreFiles])
            var r = ByteReader(resp.words)
            let totalParams = Int(try r.u16()), totalData = Int(try r.u16())
            _ = try r.u16()
            let pCount = Int(try r.u16()), pOff = Int(try r.u16()), pDisp = Int(try r.u16())
            let dCount = Int(try r.u16()), dOff = Int(try r.u16()), dDisp = Int(try r.u16())
            if outParams == nil {
                outParams = [UInt8](repeating: 0, count: totalParams)
                outData = [UInt8](repeating: 0, count: totalData)
            }
            let raw = ByteReader(resp.raw)
            if pCount > 0 {
                guard pDisp + pCount <= outParams!.count else { throw SMBError.malformedResponse }
                outParams!.replaceSubrange(pDisp..<pDisp + pCount, with: try raw.slice(pOff, pCount))
                gotParams += pCount
            }
            if dCount > 0 {
                guard dDisp + dCount <= outData!.count else { throw SMBError.malformedResponse }
                outData!.replaceSubrange(dDisp..<dDisp + dCount, with: try raw.slice(dOff, dCount))
                gotData += dCount
            }
            if gotParams >= totalParams && gotData >= totalData { break }
        }
        return (outParams ?? [], outData ?? [])
    }

    // MARK: - Messages

    private enum Flags2 {
        static let longNames: UInt16 = 0x0001
        static let extendedSecurity: UInt16 = 0x0800
        static let ntStatus: UInt16 = 0x4000
        static let unicode: UInt16 = 0x8000
    }

    struct Response {
        var command: UInt8
        var status: UInt32
        var flags2: UInt16
        var tid: UInt16
        var uid: UInt16
        var mid: UInt16
        var words: [UInt8]
        var bytes: [UInt8]
        var raw: [UInt8]
    }

    @discardableResult
    private func send(_ command: UInt8, words: [UInt8], bytes: [UInt8], extendedSecurity: Bool? = nil) throws -> UInt16 {
        let mid = nextMID
        nextMID = nextMID == 0xFFFE ? 1 : nextMID + 1
        var flags2 = Flags2.longNames | Flags2.ntStatus | Flags2.unicode
        if extendedSecurity ?? self.extendedSecurity { flags2 |= Flags2.extendedSecurity }

        var m = ByteWriter()
        m.append([0xFF, 0x53, 0x4D, 0x42]) // \xFFSMB
        m.u8(command)
        m.u32(0) // status
        m.u8(0x18) // case-insensitive, canonicalized paths
        m.u16(flags2)
        m.u16(0) // PID high
        m.zeros(8) // security features
        m.u16(0)
        m.u16(tid)
        m.u16(pid)
        m.u16(uid)
        m.u16(mid)
        m.u8(UInt8(words.count / 2))
        m.append(words)
        m.u16(UInt16(bytes.count))
        m.append(bytes)
        try transport.send(m.bytes)
        return mid
    }

    private func receive() throws -> Response {
        let raw = try transport.receive()
        guard raw.count >= 35, Array(raw[0..<4]) == [0xFF, 0x53, 0x4D, 0x42] else {
            if raw.count >= 4, Array(raw[0..<4]) == [0xFE, 0x53, 0x4D, 0x42] {
                throw SMBError.unsupportedServer("server answered with SMB2")
            }
            throw SMBError.malformedResponse
        }
        var r = ByteReader(raw)
        try r.skip(4)
        let command = try r.u8()
        let status = try r.u32()
        _ = try r.u8()
        let flags2 = try r.u16()
        try r.skip(12)
        let tid = try r.u16()
        _ = try r.u16()
        let uid = try r.u16()
        let mid = try r.u16()
        let wordCount = Int(try r.u8())
        let words = try r.take(wordCount * 2)
        let byteCount = Int(try r.u16())
        let bytes = try r.take(min(byteCount, r.remaining))
        return Response(command: command, status: status, flags2: flags2, tid: tid, uid: uid, mid: mid,
                        words: words, bytes: bytes, raw: raw)
    }

    private func roundTrip(
        _ command: UInt8, words: [UInt8], bytes: [UInt8],
        allowStatus: Set<UInt32> = [], extendedSecurity: Bool? = nil
    ) throws -> Response {
        let mid = try send(command, words: words, bytes: bytes, extendedSecurity: extendedSecurity)
        while true {
            let resp = try receive()
            guard resp.mid == mid else { continue }
            try check(resp, allowStatus: allowStatus)
            return resp
        }
    }

    private func check(_ resp: Response, allowStatus: Set<UInt32>) throws {
        guard resp.status != NTStatus.success, !allowStatus.contains(resp.status) else { return }
        switch resp.status {
        case NTStatus.logonFailure, NTStatus.wrongPassword, NTStatus.noSuchUser, NTStatus.accountRestriction:
            throw SMBError.authenticationFailed
        case NTStatus.accessDenied where resp.command == Cmd.sessionSetupAndX:
            throw SMBError.authenticationFailed
        default:
            throw SMBError.status(resp.status, command: resp.command)
        }
    }
}
