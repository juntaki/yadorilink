// swift-tools-version: 6.0
//
// Views, view models and the client protocol for the YadoriLink macOS app.
// Nothing in this package links the Rust core, so `swift test` and Xcode
// Previews run without building Rust. The app target supplies the live
// client; this package ships a fake with fixture states.

import PackageDescription

let package = Package(
    name: "YadoriLinkUI",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "YadoriLinkModel", targets: ["YadoriLinkModel"]),
        .library(name: "YadoriLinkFixtures", targets: ["YadoriLinkFixtures"]),
        .library(name: "YadoriLinkUI", targets: ["YadoriLinkUI"]),
    ],
    targets: [
        // Product types and the client protocol. The type, field and case
        // names match what the generated binding will use, so swapping the
        // fake for the binding is mechanical.
        .target(name: "YadoriLinkModel"),
        // A scripted, in-memory client with fixture states for tests and
        // Previews.
        .target(name: "YadoriLinkFixtures", dependencies: ["YadoriLinkModel"]),
        .target(
            name: "YadoriLinkUI",
            dependencies: ["YadoriLinkModel", "YadoriLinkFixtures"]
        ),
        .testTarget(
            name: "YadoriLinkUITests",
            dependencies: ["YadoriLinkUI", "YadoriLinkModel", "YadoriLinkFixtures"]
        ),
    ]
)
