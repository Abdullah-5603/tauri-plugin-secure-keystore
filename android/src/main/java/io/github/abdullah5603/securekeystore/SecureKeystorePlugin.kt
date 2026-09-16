package io.github.abdullah5603.securekeystore

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@InvokeArg
class ItemKeyArgs {
    lateinit var key: String
}

@InvokeArg
class SetItemArgs {
    lateinit var key: String
    lateinit var value: String
}

/**
 * Encrypted key-value storage backed by the Android Keystore. The AES key
 * is hardware-backed where available and non-exportable, and is
 * deliberately created WITHOUT `setUserAuthenticationRequired(true)` — many
 * apps need to read stored values silently (e.g. on a cold start) without a
 * biometric prompt, and not every device has biometrics or even a screen
 * lock enrolled. If you need the stronger "requires biometrics" guarantee,
 * this plugin is not that — see the README for the trade-off this makes.
 *
 * The key alias and preferences file are namespaced by the app's own
 * package name, so multiple apps using this plugin on the same device
 * never collide.
 */
@TauriPlugin
class SecureKeystorePlugin(private val activity: Activity) : Plugin(activity) {
    private val androidKeyStore = "AndroidKeyStore"
    private val ivSuffix = "_iv"

    private val namespace: String
        get() = activity.applicationContext.packageName

    private val keyAlias: String
        get() = "$namespace.secure_keystore_key"

    private val prefs: SharedPreferences
        get() = activity.applicationContext.getSharedPreferences(
            "$namespace.secure_keystore",
            Context.MODE_PRIVATE
        )

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(androidKeyStore)
        keyStore.load(null)

        (keyStore.getKey(keyAlias, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(false)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    @Command
    fun setItem(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SetItemArgs::class.java)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
            val ciphertext = cipher.doFinal(args.value.toByteArray(Charsets.UTF_8))

            prefs.edit()
                .putString(args.key, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                .putString(args.key + ivSuffix, Base64.encodeToString(cipher.iv, Base64.NO_WRAP))
                .apply()

            invoke.resolve()
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }

    @Command
    fun getItem(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ItemKeyArgs::class.java)
            val encoded = prefs.getString(args.key, null)
            val ivEncoded = prefs.getString(args.key + ivSuffix, null)

            val result = JSObject()
            if (encoded == null || ivEncoded == null) {
                // Leave "value" absent — the Rust side's Option<String>
                // deserializes a missing key as None.
                invoke.resolve(result)
                return
            }

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val iv = Base64.decode(ivEncoded, Base64.NO_WRAP)
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(128, iv))
            val plaintext = cipher.doFinal(Base64.decode(encoded, Base64.NO_WRAP))

            result.put("value", String(plaintext, Charsets.UTF_8))
            invoke.resolve(result)
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }

    @Command
    fun deleteItem(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ItemKeyArgs::class.java)
            prefs.edit()
                .remove(args.key)
                .remove(args.key + ivSuffix)
                .apply()
            invoke.resolve()
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }
}
