import Foundation
import Observation

/// Finds Time Capsules (and other SMB servers) on the local network so the user doesn't have to
/// know the address. Time Capsules advertise `_adisk._tcp` (Time Machine) and `_smb._tcp`.
@MainActor @Observable
final class BonjourBrowser {
    struct Device: Identifiable, Hashable {
        var name: String
        var host: String
        var isTimeMachineDisk: Bool
        var id: String { host }
    }

    private(set) var devices: [Device] = []
    @ObservationIgnored private var helper: Helper?

    func start() {
        guard helper == nil else { return }
        let helper = Helper { [weak self] device in
            MainActor.assumeIsolated { self?.add(device) }
        }
        self.helper = helper
        helper.start()
    }

    func stop() {
        helper?.stop()
        helper = nil
    }

    private func add(_ device: Device) {
        if let i = devices.firstIndex(where: { $0.host == device.host }) {
            devices[i].isTimeMachineDisk = devices[i].isTimeMachineDisk || device.isTimeMachineDisk
        } else {
            devices.append(device)
        }
        devices.sort { ($0.isTimeMachineDisk ? 0 : 1, $0.name) < ($1.isTimeMachineDisk ? 0 : 1, $1.name) }
    }

    /// NetService delegate plumbing (callbacks arrive on the main run loop).
    private final class Helper: NSObject, NetServiceBrowserDelegate, NetServiceDelegate {
        private let onFound: (Device) -> Void
        private var browsers: [NetServiceBrowser] = []
        private var resolving: Set<NetService> = []

        init(onFound: @escaping (Device) -> Void) {
            self.onFound = onFound
        }

        func start() {
            for type in ["_adisk._tcp.", "_smb._tcp."] {
                let b = NetServiceBrowser()
                b.delegate = self
                b.searchForServices(ofType: type, inDomain: "local.")
                browsers.append(b)
            }
        }

        func stop() {
            browsers.forEach { $0.stop() }
            resolving.forEach { $0.stop() }
            browsers = []
            resolving = []
        }

        func netServiceBrowser(_ browser: NetServiceBrowser, didFind service: NetService, moreComing: Bool) {
            resolving.insert(service)
            service.delegate = self
            service.resolve(withTimeout: 5)
        }

        func netServiceDidResolveAddress(_ sender: NetService) {
            resolving.remove(sender)
            guard var host = sender.hostName else { return }
            if host.hasSuffix(".") { host.removeLast() }
            onFound(Device(name: sender.name, host: host, isTimeMachineDisk: sender.type.hasPrefix("_adisk")))
        }

        func netService(_ sender: NetService, didNotResolve errorDict: [String: NSNumber]) {
            resolving.remove(sender)
        }
    }
}
