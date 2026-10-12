import Foundation
import Observation
import TimeCapsuleKit

/// App-wide state: which Time Capsule we use, the live SMB client, and the player.
@MainActor @Observable
final class AppModel {
    struct SavedServer: Codable, Equatable {
        var server: SMBClient.Server
        var authMethod: SMBAuthMethod?

        var keychainAccount: String { "\(server.user)@\(server.host)" }
    }

    private(set) var saved: SavedServer?
    private(set) var client: SMBClient?
    let player = Player()

    private static let defaultsKey = "savedServer"

    init() {
        if let data = UserDefaults.standard.data(forKey: Self.defaultsKey),
           let saved = try? JSONDecoder().decode(SavedServer.self, from: data),
           let password = Keychain.password(for: saved.keychainAccount) {
            use(saved, password: password)
        }
    }

    var isConfigured: Bool { client != nil }

    /// Logs in without picking a disk yet. Returns the client (for listing disks) on success.
    func testLogin(host: String, user: String, password: String) async throws -> (SMBClient, [SMBShare]) {
        let probe = SMBClient(server: .init(host: host, share: "", user: user), password: password)
        try await probe.login()
        // Not every server supports listing disks; the UI falls back to typing the name.
        let shares = (try? await probe.listShares())?.filter { $0.isDisk && !$0.name.hasSuffix("$") } ?? []
        return (probe, shares)
    }

    /// Verifies the disk opens, then saves everything and switches the app over to it.
    func finishSetup(probe: SMBClient, share: String, password: String) async throws {
        var server = probe.server
        server.share = share
        let client = SMBClient(server: server, password: password, authMethod: probe.authMethod)
        _ = try await client.listDirectory("")
        probe.disconnect()

        let saved = SavedServer(server: server, authMethod: client.authMethod)
        Keychain.setPassword(password, for: saved.keychainAccount)
        if let data = try? JSONEncoder().encode(saved) {
            UserDefaults.standard.set(data, forKey: Self.defaultsKey)
        }
        self.saved = saved
        self.client = client
        player.client = client
    }

    func signOut() {
        player.stop()
        client?.disconnect()
        if let saved { Keychain.deletePassword(for: saved.keychainAccount) }
        UserDefaults.standard.removeObject(forKey: Self.defaultsKey)
        saved = nil
        client = nil
        player.client = nil
    }

    private func use(_ saved: SavedServer, password: String) {
        self.saved = saved
        let client = SMBClient(server: saved.server, password: password, authMethod: saved.authMethod)
        self.client = client
        player.client = client
    }
}
