import SwiftUI

@main
struct TimeCapsuleMusicApp: App {
    @State private var model = AppModel()

    var body: some Scene {
        WindowGroup {
            RootView()
                .environment(model)
                .environment(model.player)
        }
    }
}
