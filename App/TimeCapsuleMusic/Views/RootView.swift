import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(Player.self) private var player
    @State private var showNowPlaying = false

    var body: some View {
        if model.isConfigured {
            NavigationStack {
                FolderView(path: "")
                    .navigationDestination(for: String.self) { FolderView(path: $0) }
            }
            .safeAreaInset(edge: .bottom) {
                if player.current != nil {
                    MiniPlayerView()
                        .onTapGesture { showNowPlaying = true }
                }
            }
            .sheet(isPresented: $showNowPlaying) {
                NowPlayingView()
            }
        } else {
            ConnectView()
        }
    }
}
