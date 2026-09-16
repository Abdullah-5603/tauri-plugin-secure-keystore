import Security
import Tauri
import UIKit
import WebKit

struct SetItemArgs: Decodable {
  let key: String
  let value: String
}

struct ItemKeyArgs: Decodable {
  let key: String
}

/// Encrypted key-value storage backed by the iOS Keychain. Items are stored
/// with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable without
/// a biometric/passcode prompt (matching the Android Keystore backend, which
/// deliberately skips `setUserAuthenticationRequired(true)` — see the
/// README), but never synced to iCloud or any other device, and inaccessible
/// before the device's first unlock since boot.
///
/// Items are namespaced by the app's own bundle identifier as the Keychain
/// `kSecAttrService`, so multiple apps using this plugin on the same device
/// never collide.
class SecureKeystorePlugin: Plugin {
  private var service: String {
    Bundle.main.bundleIdentifier ?? "tauri-plugin-secure-keystore"
  }

  private func query(forKey key: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
  }

  @objc public func setItem(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(SetItemArgs.self)
    guard let data = args.value.data(using: .utf8) else {
      invoke.reject("Failed to encode value as UTF-8")
      return
    }

    // Delete any existing item first so re-adding always succeeds, rather
    // than needing a separate update-vs-add branch.
    SecItemDelete(query(forKey: args.key) as CFDictionary)

    var newItem = query(forKey: args.key)
    newItem[kSecValueData as String] = data
    newItem[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly

    let status = SecItemAdd(newItem as CFDictionary, nil)
    guard status == errSecSuccess else {
      invoke.reject("Keychain error: \(status)")
      return
    }

    invoke.resolve()
  }

  @objc public func getItem(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ItemKeyArgs.self)

    var lookupQuery = query(forKey: args.key)
    lookupQuery[kSecReturnData as String] = true
    lookupQuery[kSecMatchLimit as String] = kSecMatchLimitOne

    var result: AnyObject?
    let status = SecItemCopyMatching(lookupQuery as CFDictionary, &result)

    // Leave "value" absent — the Rust side's Option<String> deserializes a
    // missing key as None.
    var response: JsonObject = [:]
    switch status {
    case errSecItemNotFound:
      break
    case errSecSuccess:
      guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
        invoke.reject("Failed to decode stored value as UTF-8")
        return
      }
      response["value"] = value
    default:
      invoke.reject("Keychain error: \(status)")
      return
    }

    invoke.resolve(response)
  }

  @objc public func deleteItem(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ItemKeyArgs.self)
    let status = SecItemDelete(query(forKey: args.key) as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
      invoke.reject("Keychain error: \(status)")
      return
    }
    invoke.resolve()
  }
}

@_cdecl("init_plugin_secure_keystore")
func initPlugin() -> Plugin {
  return SecureKeystorePlugin()
}
