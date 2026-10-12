import SwiftUI

struct NowPlayingView: View {
    @Environment(Player.self) private var player
    @Environment(\.dismiss) private var dismiss
    @State private var scrubbing: Double?

    var body: some View {
        VStack(spacing: 24) {
            Capsule().fill(.tertiary).frame(width: 40, height: 5).padding(.top, 8)

            ArtworkView(image: player.artwork, size: nil)
                .frame(maxWidth: 340)
                .shadow(radius: 12, y: 6)
                .padding(.horizontal, 24)

            VStack(spacing: 4) {
                Text(player.title).font(.title3.weight(.semibold)).multilineTextAlignment(.center)
                Text([player.artist, player.album].filter { !$0.isEmpty }.joined(separator: " — "))
                    .foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
            .lineLimit(2)
            .padding(.horizontal)

            if player.isLoading {
                VStack(spacing: 6) {
                    if let p = player.current.flatMap({ player.downloadProgress[$0.path] }) {
                        ProgressView(value: p)
                    } else {
                        ProgressView()
                    }
                    Text("Loading from Time Capsule…").font(.caption).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 32)
            } else {
                VStack(spacing: 4) {
                    Slider(
                        value: Binding(get: { scrubbing ?? player.currentTime }, set: { scrubbing = $0 }),
                        in: 0...max(player.duration, 1),
                        onEditingChanged: { editing in
                            if !editing, let target = scrubbing {
                                player.seek(to: target)
                                scrubbing = nil
                            }
                        }
                    )
                    HStack {
                        Text(format(scrubbing ?? player.currentTime))
                        Spacer()
                        Text("-" + format(max(player.duration - (scrubbing ?? player.currentTime), 0)))
                    }
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                }
                .padding(.horizontal, 32)
            }

            if let error = player.errorMessage {
                Text(error).font(.footnote).foregroundStyle(.red).padding(.horizontal)
            }

            HStack(spacing: 48) {
                Button { player.previous() } label: { Image(systemName: "backward.fill") }
                Button { player.togglePlayPause() } label: {
                    Image(systemName: player.isPlaying ? "pause.fill" : "play.fill").font(.system(size: 44))
                }
                Button { player.next() } label: { Image(systemName: "forward.fill") }
                    .disabled(!player.hasNext)
            }
            .font(.title)
            .tint(.primary)

            HStack {
                Spacer()
                AirPlayButton().frame(width: 44, height: 44)
                Spacer()
            }

            if let index = player.index {
                Text("\(index + 1) of \(player.queue.count)").font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .presentationDragIndicator(.hidden)
    }

    private func format(_ seconds: Double) -> String {
        guard seconds.isFinite else { return "0:00" }
        let s = Int(seconds)
        return s >= 3600 ? String(format: "%d:%02d:%02d", s / 3600, s / 60 % 60, s % 60) : String(format: "%d:%02d", s / 60, s % 60)
    }
}
