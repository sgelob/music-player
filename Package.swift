// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "TimeCapsuleKit",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "TimeCapsuleKit", targets: ["TimeCapsuleKit"]),
    ],
    targets: [
        // Pure-Swift SMB1 (CIFS) client. No dependencies, builds on iOS, macOS and Linux.
        .target(name: "TimeCapsuleKit"),
        // Command-line tool for poking at a share from a Mac/Linux box: `swift run tcmusic --help`.
        .executableTarget(name: "tcmusic", dependencies: ["TimeCapsuleKit"]),
        .testTarget(name: "TimeCapsuleKitTests", dependencies: ["TimeCapsuleKit"]),
    ]
)
