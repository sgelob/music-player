import Foundation

public enum SMBError: Error, Equatable, LocalizedError {
    case connectionFailed(String)
    case connectionClosed
    case timeout
    case malformedResponse
    case unsupportedServer(String)
    case authenticationFailed
    case shareNotFound(String)
    case accessDenied
    case notFound(String)
    case status(UInt32, command: UInt8)

    public var errorDescription: String? {
        switch self {
        case .connectionFailed(let why): return "Couldn't connect: \(why)"
        case .connectionClosed: return "The Time Capsule closed the connection."
        case .timeout: return "The Time Capsule stopped responding."
        case .malformedResponse: return "The Time Capsule sent a response this app doesn't understand."
        case .unsupportedServer(let why): return "Unsupported server: \(why)"
        case .authenticationFailed: return "Wrong user name or password."
        case .shareNotFound(let share): return "There's no disk called \"\(share)\" on this Time Capsule."
        case .accessDenied: return "Access denied."
        case .notFound(let path): return "\"\(path)\" doesn't exist."
        case .status(let s, let cmd): return String(format: "Server error 0x%08X (command 0x%02X)", s, cmd)
        }
    }

    /// Errors after which the TCP session is unusable and a reconnect is needed.
    public var isConnectionLevel: Bool {
        switch self {
        case .connectionFailed, .connectionClosed, .timeout, .malformedResponse: return true
        default: return false
        }
    }
}

/// NTSTATUS codes the client cares about.
enum NTStatus {
    static let success: UInt32 = 0x0000_0000
    static let moreProcessingRequired: UInt32 = 0xC000_0016
    static let noMoreFiles: UInt32 = 0x8000_0006
    static let noSuchFile: UInt32 = 0xC000_000F
    static let objectNameNotFound: UInt32 = 0xC000_0034
    static let objectPathNotFound: UInt32 = 0xC000_003A
    static let logonFailure: UInt32 = 0xC000_006D
    static let accountRestriction: UInt32 = 0xC000_006E
    static let wrongPassword: UInt32 = 0xC000_006A
    static let noSuchUser: UInt32 = 0xC000_0064
    static let accessDenied: UInt32 = 0xC000_0022
    static let badNetworkName: UInt32 = 0xC000_00CC
    static let invalidParameter: UInt32 = 0xC000_000D
    static let notSupported: UInt32 = 0xC000_00BB
    static let endOfFile: UInt32 = 0xC000_0011
}
