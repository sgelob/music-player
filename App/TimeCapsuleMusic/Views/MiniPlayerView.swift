import SwiftUI

struct MiniPlayerView: View {
    @Environment(Player.self) private var player

    var body: some View {
        HStack(spacing: 12) {
            ArtworkView(image: player.artwork, size: 44)
            VStack(alignment: .leading, spacing: 2) {
                Text(player.title).font(.subheadline.weight(.semibold)).lineLimit(1)
                Group {
                    if player.isLoading {
                        if let p = player.current.flatMap({ player.downloadProgress[$0.path] }) {
                            Text("Loading from Time Capsule… \(Int(p * 100))%")
                        } else {
                            Text("Loading from Time Capsule…")
                        }
                    } else if let error = player.errorMessage {
                        Text(error).foregroundStyle(.red)
                    } else {
                        Text(player.artist)
                    }
                }
                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer(minLength: 0)
            AirPlayButton().frame(width: 32, height: 32)
            Button { player.togglePlayPause() } label: {
                Image(systemName: player.isPlaying ? "pause.fill" : "play.fill").font(.title3)
                    .frame(width: 32, height: 32)
            }
            Button { player.next() } label: {
                Image(systemName: "forward.fill").font(.title3).frame(width: 32, height: 32)
            }
            .disabled(!player.hasNext)
        }
        .tint(.primary)
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 14))
        .padding(.horizontal, 8)
        .contentShape(Rectangle())
    }
}

struct ArtworkView: View {
    let image: UIImage?
    let size: CGFloat?

    var body: some View {
        Group {
            if let image {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                ZStack {
                    Rectangle().fill(.quaternary)
                    Image(systemName: "music.note").font(.system(size: (size ?? 240) * 0.4)).foregroundStyle(.secondary)
                }
            }
        }
        .frame(width: size, height: size)
        .aspectRatio(1, contentMode: .fit)
        .clipShape(RoundedRectangle(cornerRadius: (size ?? 240) > 100 ? 12 : 6))
    }
}
