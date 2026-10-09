// swift-tools-version:5.9
import PackageDescription

// The File Provider extension's logic that needs no FileProvider framework: the daemon's version
// token, the provider-root protocol client, and the operation log. The extension target compiles
// these sources directly; `swift test` runs them without Finder.
let package = Package(
    name: "FileProviderCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "FileProviderCore", targets: ["FileProviderCore"])],
    targets: [
        .target(name: "FileProviderCore"),
        .testTarget(name: "FileProviderCoreTests", dependencies: ["FileProviderCore"]),
    ]
)
