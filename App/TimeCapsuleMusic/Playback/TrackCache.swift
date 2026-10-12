import CryptoKit
import Foundation
import TimeCapsuleKit

/// Copies tracks from the Time Capsule into Caches/Tracks before playback.
///
/// Playing from a local file keeps AVPlayer (and AirPlay) on the most reliable path: seeking is
/// instant and a Wi-Fi hiccup can't stall playback mid-song. Files stay cached for replay, and the
/// oldest are evicted beyond `budget`.
actor TrackCache {
    static let shared = TrackCache()

    let directory: URL
    var budget: Int64 = 3_000_000_000

    init() {
        directory = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("Tracks", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func cachedURL(for track: Track, on server: SMBClient.Server) -> URL? {
        let url = localURL(for: track, on: server)
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize,
              UInt64(size) == track.size else { return nil }
        return url
    }

    /// Returns a local copy of the track, downloading it if needed. Honors task cancellation.
    func file(for track: Track, client: SMBClient, progress: @escaping @Sendable (Double) -> Void) async throws -> URL {
        if let url = cachedURL(for: track, on: client.server) {
            touch(url)
            progress(1)
            return url
        }
        let destination = localURL(for: track, on: client.server)
        let partial = directory.appendingPathComponent(UUID().uuidString + ".part")
        defer { try? FileManager.default.removeItem(at: partial) }

        try await client.download(track.path, to: partial) { done, total in
            progress(total == 0 ? 1 : Double(done) / Double(total))
        }
        try Task.checkCancellation()
        try? FileManager.default.removeItem(at: destination)
        try FileManager.default.moveItem(at: partial, to: destination)
        evictIfNeeded(keeping: destination)
        return destination
    }

    func clear() {
        try? FileManager.default.removeItem(at: directory)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    func totalSize() -> Int64 {
        files().reduce(0) { $0 + $1.size }
    }

    // MARK: Internals

    /// Stable file name per server+path; keeps the extension so AVFoundation knows the format.
    private func localURL(for track: Track, on server: SMBClient.Server) -> URL {
        let key = "\(server.host)/\(server.share)/\(track.path)"
        let digest = SHA256.hash(data: Data(key.utf8)).prefix(16).map { String(format: "%02x", $0) }.joined()
        return directory.appendingPathComponent(digest).appendingPathExtension(track.fileExtension)
    }

    private func touch(_ url: URL) {
        try? FileManager.default.setAttributes([.modificationDate: Date()], ofItemAtPath: url.path)
    }

    private func files() -> [(url: URL, size: Int64, date: Date)] {
        let keys: [URLResourceKey] = [.fileSizeKey, .contentModificationDateKey]
        let urls = (try? FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: keys)) ?? []
        return urls.compactMap { url in
            guard url.pathExtension != "part", let v = try? url.resourceValues(forKeys: Set(keys)) else { return nil }
            return (url, Int64(v.fileSize ?? 0), v.contentModificationDate ?? .distantPast)
        }
    }

    private func evictIfNeeded(keeping keep: URL) {
        var all = files().sorted { $0.date < $1.date }
        var total = all.reduce(0) { $0 + $1.size }
        while total > budget, let oldest = all.first {
            all.removeFirst()
            if oldest.url == keep { continue }
            try? FileManager.default.removeItem(at: oldest.url)
            total -= oldest.size
        }
    }
}
