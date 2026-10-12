import Foundation
import TimeCapsuleKit

/// A playable file on the Time Capsule.
struct Track: Identifiable, Hashable, Sendable {
    var path: String
    var size: UInt64

    var id: String { path }
    var fileName: String { (path as NSString).lastPathComponent }
    var displayName: String { (fileName as NSString).deletingPathExtension }
    var fileExtension: String { (fileName as NSString).pathExtension.lowercased() }
}

enum Library {
    /// Formats AVFoundation can play on iOS. (No Ogg/Opus/WMA.)
    static let audioExtensions: Set<String> = [
        "mp3", "m4a", "m4b", "aac", "alac", "flac", "wav", "aif", "aiff", "aifc", "caf", "mp4",
    ]

    static func isAudio(_ name: String) -> Bool {
        audioExtensions.contains((name as NSString).pathExtension.lowercased())
    }

    /// Folders first, then audio files, each in Finder order. Hides dotfiles (.DS_Store,
    /// AppleDouble "._" files) and non-audio files.
    static func visibleEntries(_ entries: [SMBDirectoryEntry]) -> [SMBDirectoryEntry] {
        entries
            .filter { !$0.name.hasPrefix(".") && ($0.isDirectory || isAudio($0.name)) }
            .sorted {
                if $0.isDirectory != $1.isDirectory { return $0.isDirectory }
                return $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
    }

    static func join(_ folder: String, _ name: String) -> String {
        folder.isEmpty ? name : folder + "/" + name
    }
}
