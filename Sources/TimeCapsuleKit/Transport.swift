import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

/// Blocking TCP socket carrying SMB over "direct TCP" (port 445) or NetBIOS session service (139).
/// Both use the same 4-byte length framing; port 139 additionally needs a session request.
///
/// All calls block, so the owner must only use it from a dedicated serial queue.
final class Transport {
    private var fd: Int32 = -1
    private let timeout: TimeInterval

    init(host: String, port: UInt16, timeout: TimeInterval) throws {
        self.timeout = timeout
        fd = try Self.connect(host: host, port: port, timeout: timeout)
        if port == 139 { try netbiosSessionRequest(host: host) }
    }

    deinit { close() }

    func close() {
        if fd >= 0 {
            #if canImport(Darwin)
            Darwin.close(fd)
            #else
            Glibc.close(fd)
            #endif
            fd = -1
        }
    }

    // MARK: Framing

    func send(_ message: [UInt8]) throws {
        let n = message.count
        try writeAll([0, UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)] + message)
    }

    func receive() throws -> [UInt8] {
        while true {
            let header = try readExactly(4)
            let length = Int(header[1] & 0x01) << 16 | Int(header[2]) << 8 | Int(header[3])
            let body = try readExactly(length)
            if header[0] == 0x85 { continue } // NetBIOS keep-alive
            return body
        }
    }

    // MARK: Socket plumbing

    private static func connect(host: String, port: UInt16, timeout: TimeInterval) throws -> Int32 {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Darwin)
        hints.ai_socktype = SOCK_STREAM
        #else
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #endif
        var result: UnsafeMutablePointer<addrinfo>?
        let rc = getaddrinfo(host, String(port), &hints, &result)
        guard rc == 0, let first = result else {
            throw SMBError.connectionFailed("can't find \"\(host)\" on the network")
        }
        defer { freeaddrinfo(first) }

        var lastError = "no addresses"
        var ai: UnsafeMutablePointer<addrinfo>? = first
        while let a = ai {
            defer { ai = a.pointee.ai_next }
            let s = socket(a.pointee.ai_family, a.pointee.ai_socktype, a.pointee.ai_protocol)
            if s < 0 { continue }
            if connectWithTimeout(s, a.pointee.ai_addr, a.pointee.ai_addrlen, timeout) {
                configure(s, timeout: timeout)
                return s
            }
            lastError = String(cString: strerror(errno))
            #if canImport(Darwin)
            Darwin.close(s)
            #else
            Glibc.close(s)
            #endif
        }
        throw SMBError.connectionFailed("\(host):\(port) – \(lastError)")
    }

    private static func connectWithTimeout(
        _ s: Int32, _ addr: UnsafeMutablePointer<sockaddr>?, _ len: socklen_t, _ timeout: TimeInterval
    ) -> Bool {
        let flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)
        defer { _ = fcntl(s, F_SETFL, flags) }
        if Foundation.connect(s, addr, len) == 0 { return true }
        guard errno == EINPROGRESS else { return false }
        var pfd = pollfd(fd: s, events: Int16(POLLOUT), revents: 0)
        guard poll(&pfd, 1, Int32(timeout * 1000)) == 1 else { errno = ETIMEDOUT; return false }
        var err: Int32 = 0
        var errLen = socklen_t(MemoryLayout<Int32>.size)
        getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &errLen)
        if err != 0 { errno = err; return false }
        return true
    }

    private static func configure(_ s: Int32, timeout: TimeInterval) {
        var one: Int32 = 1
        setsockopt(s, Int32(IPPROTO_TCP), TCP_NODELAY, &one, socklen_t(MemoryLayout<Int32>.size))
        #if canImport(Darwin)
        setsockopt(s, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        #endif
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var buf: Int32 = 1 << 20
        setsockopt(s, SOL_SOCKET, SO_RCVBUF, &buf, socklen_t(MemoryLayout<Int32>.size))
    }

    private func writeAll(_ data: [UInt8]) throws {
        guard fd >= 0 else { throw SMBError.connectionClosed }
        var sent = 0
        try data.withUnsafeBytes { raw in
            while sent < data.count {
                #if canImport(Darwin)
                let n = Darwin.send(fd, raw.baseAddress! + sent, data.count - sent, 0)
                #else
                let n = Glibc.send(fd, raw.baseAddress! + sent, data.count - sent, Int32(MSG_NOSIGNAL))
                #endif
                if n < 0 {
                    if errno == EINTR { continue }
                    throw errno == EAGAIN || errno == EWOULDBLOCK ? SMBError.timeout : SMBError.connectionClosed
                }
                sent += n
            }
        }
    }

    private func readExactly(_ count: Int) throws -> [UInt8] {
        guard fd >= 0 else { throw SMBError.connectionClosed }
        var buffer = [UInt8](repeating: 0, count: count)
        var got = 0
        try buffer.withUnsafeMutableBytes { raw in
            while got < count {
                let n = recv(fd, raw.baseAddress! + got, count - got, 0)
                if n == 0 { throw SMBError.connectionClosed }
                if n < 0 {
                    if errno == EINTR { continue }
                    throw errno == EAGAIN || errno == EWOULDBLOCK ? SMBError.timeout : SMBError.connectionClosed
                }
                got += n
            }
        }
        return buffer
    }

    // MARK: NetBIOS (port 139 only)

    private func netbiosSessionRequest(host: String) throws {
        // Try the server's own name first, then the "*SMBSERVER" wildcard most servers accept.
        let label = host.split(separator: ".").first.map(String.init) ?? host
        let candidates = label.first?.isNumber == true ? ["*SMBSERVER"] : [label, "*SMBSERVER"]
        for (i, name) in candidates.enumerated() {
            if i > 0 { // the server hangs up after a negative response
                close()
                fd = try Self.connect(host: host, port: 139, timeout: timeout)
            }
            let payload = Self.netbiosName(name, suffix: 0x20) + Self.netbiosName("TCMUSIC", suffix: 0x00)
            let n = payload.count
            try writeAll([0x81, 0, UInt8(n >> 8), UInt8(n & 0xff)] + payload)
            let header = try readExactly(4)
            let length = Int(header[2]) << 8 | Int(header[3])
            _ = try readExactly(length)
            if header[0] == 0x82 { return }
        }
        throw SMBError.connectionFailed("NetBIOS session refused")
    }

    /// RFC 1001 first-level encoding of a 16-byte NetBIOS name.
    static func netbiosName(_ name: String, suffix: UInt8) -> [UInt8] {
        var raw = Array(name.uppercased().utf8.prefix(15))
        raw += [UInt8](repeating: 0x20, count: 15 - raw.count)
        raw.append(suffix)
        if name == "*SMBSERVER" { raw = Array("*SMBSERVER".utf8) + [UInt8](repeating: 0x20, count: 5) + [0x20] }
        var out: [UInt8] = [32]
        for b in raw { out += [0x41 + (b >> 4), 0x41 + (b & 0x0f)] }
        out.append(0)
        return out
    }
}
