import LocalAuthentication
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

/// Encrypted key-value storage backed by the iOS Keychain. Plain
/// (`setItem`/`getItem`) items are stored with
/// `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`: readable without a
/// biometric/passcode prompt (matching the Android Keystore backend, which
/// deliberately skips `setUserAuthenticationRequired(true)` — see the
/// README), but never synced to iCloud or any other device, and inaccessible
/// before the device's first unlock since boot.
///
/// Apps that *do* want a prompt for a given item can opt in per-call with
/// `requireAuth: "os"` (see `setItemAuth`/`getItemAuth` below), which stores
/// the item behind `kSecAccessControl` with `.userPresence` — Face ID,
/// Touch ID, or the device passcode as iOS's own built-in fallback. This is
/// opt-in and per-item; the plain path's behavior is unchanged.
///
/// Items are namespaced by the app's own bundle identifier as the Keychain
/// `kSecAttrService`, so multiple apps using this plugin on the same device
/// never collide.
class SecureKeystorePlugin: Plugin {
  private var service: String {
    Bundle.main.bundleIdentifier ?? "tauri-plugin-secure-keystore"
  }

  // requireAuth: "os" items live under a separate kSecAttrService so they
  // never share a Keychain entry with a plain item of the same key name.
  private var authService: String {
    "\(service).secure_keystore_auth"
  }

  private func query(forKey key: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: key,
    ]
  }

  private func authQuery(forKey key: String) -> [String: Any] {
    [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: authService,
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

  @objc public func setItemAuth(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(SetItemArgs.self)
    guard let data = args.value.data(using: .utf8) else {
      invoke.reject("Failed to encode value as UTF-8")
      return
    }

    SecItemDelete(authQuery(forKey: args.key) as CFDictionary)

    guard
      let accessControl = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
        [.userPresence],
        nil
      )
    else {
      invoke.reject(
        "Failed to create an access-controlled Keychain entry; does this device have a passcode set? requireAuth: \"os\" requires one"
      )
      return
    }

    var newItem = authQuery(forKey: args.key)
    newItem[kSecValueData as String] = data
    newItem[kSecAttrAccessControl as String] = accessControl

    let status = SecItemAdd(newItem as CFDictionary, nil)
    guard status == errSecSuccess else {
      invoke.reject("Keychain error: \(status)")
      return
    }

    invoke.resolve()
  }

  @objc public func getItemAuth(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ItemKeyArgs.self)

    let context = LAContext()
    context.localizedReason = "Authenticate to access this secure item"

    var lookupQuery = authQuery(forKey: args.key)
    lookupQuery[kSecReturnData as String] = true
    lookupQuery[kSecMatchLimit as String] = kSecMatchLimitOne
    lookupQuery[kSecUseAuthenticationContext as String] = context

    var result: AnyObject?
    let status = SecItemCopyMatching(lookupQuery as CFDictionary, &result)

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
    case errSecUserCanceled:
      invoke.reject("Authentication was canceled")
      return
    case errSecAuthFailed:
      invoke.reject("Authentication failed")
      return
    default:
      invoke.reject("Keychain error: \(status)")
      return
    }

    invoke.resolve(response)
  }

  @objc public func deleteItemAuth(_ invoke: Invoke) throws {
    let args = try invoke.parseArgs(ItemKeyArgs.self)
    let status = SecItemDelete(authQuery(forKey: args.key) as CFDictionary)
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
