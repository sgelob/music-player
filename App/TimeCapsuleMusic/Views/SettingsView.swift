import SwiftUI

struct SettingsView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @State private var cacheSize: Int64?

    var body: some View {
        NavigationStack {
            Form {
                if let saved = model.saved {
                    Section("Time Capsule") {
                        LabeledContent("Address", value: saved.server.host)
                        LabeledContent("Disk", value: saved.server.share)
                        LabeledContent("User", value: saved.server.user)
                        if let auth = saved.authMethod { LabeledContent("Sign-in", value: auth.description) }
                    }
                }
                Section {
                    LabeledContent("Downloaded songs") {
                        if let cacheSize {
                            Text(ByteCountFormatter.string(fromByteCount: cacheSize, countStyle: .file))
                        } else {
                            ProgressView()
                        }
                    }
                    Button("Clear Downloaded Songs") {
                        Task {
                            await TrackCache.shared.clear()
                            cacheSize = 0
                        }
                    }
                } footer: {
                    Text("Songs are copied to this iPhone before they play, so seeking is instant and Wi-Fi hiccups don't interrupt playback. The oldest are removed automatically after 3 GB.")
                }
                Section {
                    Button("Disconnect From Time Capsule", role: .destructive) {
                        model.signOut()
                        dismiss()
                    }
                }
            }
            .navigationTitle("Settings")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
            .task { cacheSize = await TrackCache.shared.totalSize() }
        }
    }
}
