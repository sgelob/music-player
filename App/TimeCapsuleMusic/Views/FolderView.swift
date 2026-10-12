import SwiftUI
import TimeCapsuleKit

/// One folder on the Time Capsule: subfolders to drill into, audio files to play.
struct FolderView: View {
    let path: String

    @Environment(AppModel.self) private var model
    @Environment(Player.self) private var player
    @State private var entries: [SMBDirectoryEntry]?
    @State private var errorMessage: String?
    @State private var showSettings = false

    private var tracks: [Track] {
        (entries ?? []).filter { !$0.isDirectory }.map { Track(path: Library.join(path, $0.name), size: $0.size) }
    }

    private var title: String {
        path.isEmpty ? (model.saved?.server.share ?? "Music") : (path as NSString).lastPathComponent
    }

    var body: some View {
        Group {
            if let entries {
                if entries.isEmpty {
                    ContentUnavailableView("No Music Here", systemImage: "music.note",
                                           description: Text("This folder has no subfolders or audio files."))
                } else {
                    list(entries)
                }
            } else if let errorMessage {
                ContentUnavailableView {
                    Label("Can't Open Folder", systemImage: "wifi.exclamationmark")
                } description: {
                    Text(errorMessage)
                } actions: {
                    Button("Try Again") { Task { await load() } }
                }
            } else {
                ProgressView()
            }
        }
        .navigationTitle(title)
        .toolbar {
            if path.isEmpty {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showSettings = true } label: { Image(systemName: "gearshape") }
                }
            }
        }
        .sheet(isPresented: $showSettings) { SettingsView() }
        .task { if entries == nil { await load() } }
        .refreshable { await load() }
    }

    private func list(_ entries: [SMBDirectoryEntry]) -> some View {
        let tracks = self.tracks
        return List {
            if !tracks.isEmpty {
                Section {
                    HStack(spacing: 12) {
                        Button { player.play(tracks) } label: {
                            Label("Play", systemImage: "play.fill").frame(maxWidth: .infinity)
                        }
                        Button { player.shuffle(tracks) } label: {
                            Label("Shuffle", systemImage: "shuffle").frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.bordered)
                    .listRowBackground(Color.clear)
                    .listRowInsets(EdgeInsets())
                }
            }
            Section {
                ForEach(entries, id: \.name) { entry in
                    if entry.isDirectory {
                        NavigationLink(value: Library.join(path, entry.name)) {
                            Label(entry.name, systemImage: "folder")
                        }
                    } else {
                        let trackPath = Library.join(path, entry.name)
                        Button {
                            if let i = tracks.firstIndex(where: { $0.path == trackPath }) { player.play(tracks, startingAt: i) }
                        } label: {
                            TrackRow(name: (entry.name as NSString).deletingPathExtension,
                                     size: entry.size, path: trackPath)
                        }
                        .tint(.primary)
                    }
                }
            }
        }
    }

    private func load() async {
        guard let client = model.client else { return }
        do {
            entries = Library.visibleEntries(try await client.listDirectory(path))
            errorMessage = nil
        } catch {
            if entries == nil { errorMessage = error.localizedDescription }
        }
    }
}

private struct TrackRow: View {
    let name: String
    let size: UInt64
    let path: String
    @Environment(Player.self) private var player

    var body: some View {
        let isCurrent = player.current?.path == path
        HStack(spacing: 12) {
            Image(systemName: isCurrent ? (player.isPlaying ? "speaker.wave.2.fill" : "speaker.fill") : "music.note")
                .foregroundStyle(isCurrent ? Color.accentColor : .secondary)
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).lineLimit(2)
                Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            if let progress = player.downloadProgress[path] {
                Text(progress, format: .percent.precision(.fractionLength(0)))
                    .font(.caption.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
        }
    }
}
