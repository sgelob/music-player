import SwiftUI
import TimeCapsuleKit

/// First-run setup: find the Time Capsule, log in, pick the disk.
struct ConnectView: View {
    @Environment(AppModel.self) private var model
    @State private var browser = BonjourBrowser()

    @State private var host = ""
    @State private var user = "admin"
    @State private var password = ""
    @State private var share = "Data"

    @State private var probe: SMBClient?
    @State private var shares: [SMBShare] = []
    @State private var isWorking = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    if browser.devices.isEmpty {
                        HStack(spacing: 12) {
                            ProgressView()
                            Text("Looking for Time Capsules…").foregroundStyle(.secondary)
                        }
                    }
                    ForEach(browser.devices) { device in
                        Button {
                            host = device.host
                            probe = nil
                        } label: {
                            HStack {
                                Label(device.name, systemImage: device.isTimeMachineDisk ? "externaldrive.connected.to.line.below" : "server.rack")
                                Spacer()
                                if host == device.host { Image(systemName: "checkmark") }
                            }
                        }
                        .tint(.primary)
                    }
                } header: {
                    Text("On this network")
                }

                Section {
                    TextField("Address, e.g. Time-Capsule.local or 10.0.1.1", text: $host)
                        .textContentType(.URL)
                        .keyboardType(.URL)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    TextField("User name", text: $user)
                        .textContentType(.username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                } header: {
                    Text("Time Capsule")
                } footer: {
                    Text("Use the disk or base station password set in AirPort Utility. With a disk password, any user name works. Your password is stored in the Keychain.")
                }

                if probe == nil {
                    Section {
                        Button(action: connect) {
                            HStack {
                                Text("Connect")
                                if isWorking { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(host.trimmingCharacters(in: .whitespaces).isEmpty || isWorking)
                    }
                } else {
                    Section {
                        if shares.isEmpty {
                            TextField("Disk name", text: $share)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                        } else {
                            Picker("Disk", selection: $share) {
                                ForEach(shares, id: \.name) { Text($0.name).tag($0.name) }
                            }
                        }
                        Button(action: finish) {
                            HStack {
                                Text("Open Music")
                                if isWorking { Spacer(); ProgressView() }
                            }
                        }
                        .disabled(share.isEmpty || isWorking)
                    } header: {
                        Text("Disk")
                    } footer: {
                        Text(shares.isEmpty ? "Couldn't list the disks automatically. The built-in disk is usually called “Data”." : "")
                    }
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Connect")
            .onAppear { browser.start() }
            .onDisappear { browser.stop() }
            .onChange(of: host) { probe = nil }
            .onChange(of: user) { probe = nil }
            .onChange(of: password) { probe = nil }
        }
    }

    private func connect() {
        isWorking = true
        errorMessage = nil
        Task {
            defer { isWorking = false }
            do {
                let (client, found) = try await model.testLogin(
                    host: host.trimmingCharacters(in: .whitespaces), user: user, password: password)
                shares = found
                if let first = found.first, !found.contains(where: { $0.name == share }) { share = first.name }
                probe = client
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }

    private func finish() {
        guard let probe else { return }
        isWorking = true
        errorMessage = nil
        Task {
            defer { isWorking = false }
            do {
                try await model.finishSetup(probe: probe, share: share, password: password)
            } catch {
                errorMessage = error.localizedDescription
            }
        }
    }
}
