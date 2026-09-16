// swift-tools-version:5.3
import PackageDescription

let package = Package(
  name: "tauri-plugin-secure-keystore",
  platforms: [
    .iOS(.v13)
  ],
  products: [
    .library(
      name: "tauri-plugin-secure-keystore",
      type: .static,
      targets: ["tauri-plugin-secure-keystore"])
  ],
  dependencies: [
    .package(name: "Tauri", path: "../.tauri/tauri-api")
  ],
  targets: [
    .target(
      name: "tauri-plugin-secure-keystore",
      dependencies: [
        .byName(name: "Tauri")
      ],
      path: "Sources")
  ]
)
