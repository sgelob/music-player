import Foundation

/// Thread-safe async front end for `SMB1Session`.
///
/// Owns a single connection on a private serial queue, connects lazily, remembers which auth
/// method worked, and transparently reconnects once when the Time Capsule drops an idle session.
public final class SMBClient: @unchecked Sendable {
    public struct Server: Hashable, Codable, Sendable {
        public var host: String
        public var share: String
        public var user: String
        public var domain: String
        /// nil = try 445, then 139.
        public var port: UInt16?

        public init(host: String, share: String, user: String, domain: String = "", port: UInt16? = nil) {
            self.host = host
            self.share = share
            self.user = user
            self.domain = domain
            self.port = port
        }
    }

    public let server: Server
    private let password: String
    private let queue = DispatchQueue(label: "TimeCapsuleKit.SMBClient")
    private let timeout: TimeInterval

    // Only touched on `queue`.
    private var session: SMB1Session?
    private var generation = 0
    public private(set) var authMethod: SMBAuthMethod?

    public init(server: Server, password: String, authMethod: SMBAuthMethod? = nil, timeout: TimeInterval = 15) {
        self.server = server
        self.password = password
        self.authMethod = authMethod
        self.timeout = timeout
    }

    deinit { session?.disconnect() }

    // MARK: Public API

    /// Connects and authenticates without opening a share. Returns the method that worked.
    @discardableResult
    public func login() async throws -> SMBAuthMethod {
        try await run(needsShare: false) { _ in }
        return authMethod!
    }

    public func listShares() async throws -> [SMBShare] {
        try await run(needsShare: false) { try $0.listShares() }
    }

    public func listDirectory(_ path: String) async throws -> [SMBDirectoryEntry] {
        try await run { try $0.listDirectory(path) }
    }

    /// Downloads a file to `destination`, calling `progress(bytesDone, totalBytes)` as it goes.
    /// Survives one dropped connection per chunk by reopening the file at the current offset.
    public func download(
        _ path: String, to destination: URL, chunkSize: Int = 1 << 20,
        progress: @Sendable (UInt64, UInt64) -> Void = { _, _ in }
    ) async throws {
        guard FileManager.default.createFile(atPath: destination.path, contents: nil) else {
            throw CocoaError(.fileWriteUnknown)
        }
        let out = try FileHandle(forWritingTo: destination)
        defer { try? out.close() }

        let state = OpenFile()
        defer { queue.async { [weak self] in self?.closeIfCurrent(state) } }
        var offset: UInt64 = 0
        var total = UInt64.max
        while offset < total {
            try Task.checkCancellation()
            let (bytes, size) = try await run { s -> ([UInt8], UInt64) in
                let handle = try self.handle(for: path, state: state, session: s)
                return (try s.read(handle, offset: offset, length: chunkSize), handle.size)
            }
            total = size
            if bytes.isEmpty, offset < total { throw SMBError.malformedResponse }
            try out.write(contentsOf: bytes)
            offset += UInt64(bytes.count)
            progress(offset, total)
        }
    }

    public func disconnect() {
        queue.async {
            self.session?.disconnect()
            self.session = nil
        }
    }

    // MARK: Internals

    private final class OpenFile: @unchecked Sendable {
        var handle: SMBFileHandle?
        var generation = -1
    }

    private func handle(for path: String, state: OpenFile, session: SMB1Session) throws -> SMBFileHandle {
        if let h = state.handle, state.generation == generation { return h }
        let h = try session.open(path)
        state.handle = h
        state.generation = generation
        return h
    }

    private func closeIfCurrent(_ state: OpenFile) {
        if let h = state.handle, state.generation == generation { try? session?.close(h) }
    }

    private func run<T>(needsShare: Bool = true, _ body: @escaping (SMB1Session) throws -> T) async throws -> T {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                cont.resume(with: Result { try self.runOnQueue(needsShare: needsShare, body) })
            }
        }
    }

    private func runOnQueue<T>(needsShare: Bool, _ body: (SMB1Session) throws -> T) throws -> T {
        var retried = false
        while true {
            let reused = session != nil
            do {
                let s = try connectedSession(needsShare: needsShare)
                return try body(s)
            } catch let error as SMBError where error.isConnectionLevel && reused && !retried {
                // Stale connection (Time Capsules drop idle clients): reconnect once and retry.
                session?.disconnect()
                session = nil
                retried = true
            } catch let error as SMBError where error.isConnectionLevel {
                session?.disconnect()
                session = nil
                throw error
            }
        }
    }

    private func connectedSession(needsShare: Bool) throws -> SMB1Session {
        if session == nil {
            let creds = SMBCredentials(user: server.user, password: password, domain: server.domain)
            let methods = authMethod.map { known in [known] + SMBAuthMethod.allInPreferenceOrder.filter { $0 != known } }
                ?? SMBAuthMethod.allInPreferenceOrder
            let (s, method) = try SMB1Session.open(
                host: server.host, port: server.port, credentials: creds, methods: methods, timeout: timeout)
            session = s
            authMethod = method
            generation += 1
        }
        if needsShare, session!.connectedShare == nil {
            try session!.connectShare(server.share)
        }
        return session!
    }
}
