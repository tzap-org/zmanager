// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "ZManager",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(
            name: "ZManagerFFI",
            targets: ["ZManagerFFI"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "zmanagerFFI",
            path: "dist/swift/zmanagerFFI.xcframework"
        ),
        .target(
            name: "ZManagerFFI",
            dependencies: ["zmanagerFFI"],
            path: "dist/swift/Sources/ZManagerFFI",
            linkerSettings: [
                .linkedLibrary("AppleArchive"),
                .linkedLibrary("bz2"),
                .linkedLibrary("z"),
                .linkedLibrary("iconv"),
                .linkedLibrary("xml2"),
                .linkedLibrary("c++"),
                .linkedFramework("CoreFoundation")
            ]
        )
    ]
)
