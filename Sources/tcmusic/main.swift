import Foundation
import TimeCapsuleKit

// Tiny CLI for testing TimeCapsuleKit against a real server from a Mac or Linux box.
//   swift run tcmusic <host[:port]> <user> <password> shares
//   swift run tcmusic <host> <user> <password> ls <share> [path]
//   swift run tcmusic <host> <user> <password> get <share> <path> <local-file>
// Set TC_AUTH=v1|v2|v1-basic|v2-basic to force one auth method.

let args = CommandLine.arguments
guard args.count >= 5 else {
    print("usage: tcmusic <host> <user> <password> shares | ls <share> [path] | get <share> <path> <out>")
    exit(2)
}
let (user, password, command) = (args[2], args[3], args[4])
let hostParts = args[1].split(separator: ":")
let host = String(hostParts[0])
let port = hostParts.count > 1 ? UInt16(hostParts[1]) : nil
let forced: SMBAuthMethod? = ProcessInfo.processInfo.environment["TC_AUTH"].flatMap { s in
    let ntlm: NTLMVersion = s.hasPrefix("v1") ? .v1 : .v2
    return SMBAuthMethod(extendedSecurity: !s.hasSuffix("-basic"), ntlm: ntlm)
}

func client(share: String) -> SMBClient {
    SMBClient(server: .init(host: host, share: share, user: user, port: port), password: password, authMethod: forced)
}

do {
    switch command {
    case "shares":
        let c = client(share: "")
        for s in try await c.listShares() { print("\(s.isDisk ? "disk" : "    ")  \(s.name)  \(s.comment)") }
        print("auth: \(c.authMethod!)")
    case "ls":
        let c = client(share: args[5])
        for e in try await c.listDirectory(args.count > 6 ? args[6] : "") {
            print(e.isDirectory ? "d" : "-", String(e.size).padding(toLength: 12, withPad: " ", startingAt: 0), e.name)
        }
        print("auth: \(c.authMethod!)")
    case "get":
        let c = client(share: args[5])
        let start = Date()
        let out = URL(fileURLWithPath: args[7])
        try await c.download(args[6], to: out)
        let size = (try FileManager.default.attributesOfItem(atPath: out.path)[.size] as? UInt64) ?? 0
        let secs = Date().timeIntervalSince(start)
        print(String(format: "%llu bytes in %.2fs (%.1f MB/s), auth: %@", size, secs, Double(size) / secs / 1e6,
                     c.authMethod!.description))
    case "reconnect-test": // lists, waits for the server to drop us, lists again
        let c = client(share: args[5])
        print("first:", try await c.listDirectory("").count)
        try await Task.sleep(nanoseconds: 4_000_000_000)
        print("second:", try await c.listDirectory("").count)
    default:
        print("unknown command \(command)"); exit(2)
    }
} catch {
    print("error: \(error.localizedDescription) [\(error)]")
    exit(1)
}
