package io.github.abdullah5603.securekeystore

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
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
 * used for the plain (`setItem`/`getItem`) path is hardware-backed where
 * available and non-exportable, and is deliberately created WITHOUT
 * `setUserAuthenticationRequired(true)` — many apps need to read stored
 * values silently (e.g. on a cold start) without a biometric prompt, and not
 * every device has biometrics or even a screen lock enrolled.
 *
 * Apps that *do* want a prompt for a given item can opt in per-call with
 * `requireAuth: "os"` (see `setItemAuth`/`getItemAuth` below), which uses a
 * second, separate Keystore key that Android itself refuses to unlock
 * without a fresh `BiometricPrompt` authentication — biometric, with
 * PIN/pattern/password as the OS's own built-in fallback. This is opt-in and
 * per-item; the plain path's behavior is unchanged.
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

    private val authKeyAlias: String
        get() = "$namespace.secure_keystore_auth_key"

    private val prefs: SharedPreferences
        get() = activity.applicationContext.getSharedPreferences(
            "$namespace.secure_keystore",
            Context.MODE_PRIVATE
        )

    // requireAuth: "os" items live in a separate preferences file so they
    // never share a storage slot with a plain item of the same key name.
    private val authPrefs: SharedPreferences
        get() = activity.applicationContext.getSharedPreferences(
            "$namespace.secure_keystore_auth",
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

    /**
     * Like `getOrCreateKey`, but the key can only be used once the user has
     * just authenticated with `BiometricPrompt` — Android enforces this at
     * the Keystore level, not just in this plugin's own logic.
     */
    private fun getOrCreateAuthKey(): SecretKey {
        val keyStore = KeyStore.getInstance(androidKeyStore)
        keyStore.load(null)

        (keyStore.getKey(authKeyAlias, null) as? SecretKey)?.let { return it }

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, androidKeyStore)
        val specBuilder = KeyGenParameterSpec.Builder(
            authKeyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // API 30+: the key accepts either a class-3 biometric or the
            // device credential (PIN/pattern/password) as proof of
            // authentication, matching BiometricPrompt's own
            // BIOMETRIC_STRONG | DEVICE_CREDENTIAL below. `0` = no grace
            // period; every single use re-prompts.
            specBuilder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        } else {
            // Pre-API-30, a key can't accept both biometric and device
            // credential at once, so this falls back to biometric-only;
            // see `allowedAuthenticators` below.
            @Suppress("DEPRECATION")
            specBuilder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        keyGenerator.init(specBuilder.build())
        return keyGenerator.generateKey()
    }

    private val allowedAuthenticators: Int
        get() = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    /**
     * Shows the system BiometricPrompt (biometric, or PIN/pattern/password
     * on API 30+) bound to `cipher` via a `CryptoObject`, then runs
     * [onSuccess] with the now-authenticated cipher. Rejects [invoke] on any
     * failure, cancellation, or if no biometric/device credential is
     * enrolled at all.
     */
    private fun authenticateThenRun(invoke: Invoke, cipher: Cipher, onSuccess: (Cipher) -> Unit) {
        val fragmentActivity = activity as? FragmentActivity
        if (fragmentActivity == null) {
            invoke.reject("requireAuth: \"os\" needs a FragmentActivity host")
            return
        }

        val canAuth = BiometricManager.from(activity).canAuthenticate(allowedAuthenticators)
        if (canAuth != BiometricManager.BIOMETRIC_SUCCESS) {
            invoke.reject(
                "No biometric or device credential is enrolled on this device " +
                    "(BiometricManager code $canAuth); requireAuth: \"os\" cannot be used " +
                    "until the user sets one up, or use requireAuth: \"password\" instead"
            )
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate")
            .setSubtitle("Confirm your identity to access this secure item")
            .setAllowedAuthenticators(allowedAuthenticators)
            .build()

        fragmentActivity.runOnUiThread {
            val executor = ContextCompat.getMainExecutor(activity)
            val prompt = BiometricPrompt(
                fragmentActivity,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        val authedCipher = result.cryptoObject?.cipher
                        if (authedCipher == null) {
                            invoke.reject("Authentication succeeded but no crypto object was returned")
                            return
                        }
                        try {
                            onSuccess(authedCipher)
                        } catch (ex: Exception) {
                            invoke.reject(ex.message)
                        }
                    }

                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        invoke.reject("Authentication error: $errString")
                    }

                    override fun onAuthenticationFailed() {
                        // A single failed attempt (e.g. wrong fingerprint);
                        // the prompt stays open for retries, so don't
                        // reject invoke here — only a terminal error or
                        // success should resolve it.
                    }
                }
            )
            prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
        }
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

    @Command
    fun setItemAuth(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(SetItemArgs::class.java)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateAuthKey())

            authenticateThenRun(invoke, cipher) { authedCipher ->
                val ciphertext = authedCipher.doFinal(args.value.toByteArray(Charsets.UTF_8))
                authPrefs.edit()
                    .putString(args.key, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
                    .putString(args.key + ivSuffix, Base64.encodeToString(authedCipher.iv, Base64.NO_WRAP))
                    .apply()
                invoke.resolve()
            }
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }

    @Command
    fun getItemAuth(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ItemKeyArgs::class.java)
            val encoded = authPrefs.getString(args.key, null)
            val ivEncoded = authPrefs.getString(args.key + ivSuffix, null)

            if (encoded == null || ivEncoded == null) {
                invoke.resolve(JSObject())
                return
            }

            val iv = Base64.decode(ivEncoded, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateAuthKey(), GCMParameterSpec(128, iv))

            authenticateThenRun(invoke, cipher) { authedCipher ->
                val plaintext = authedCipher.doFinal(Base64.decode(encoded, Base64.NO_WRAP))
                val result = JSObject()
                result.put("value", String(plaintext, Charsets.UTF_8))
                invoke.resolve(result)
            }
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }

    @Command
    fun deleteItemAuth(invoke: Invoke) {
        try {
            val args = invoke.parseArgs(ItemKeyArgs::class.java)
            authPrefs.edit()
                .remove(args.key)
                .remove(args.key + ivSuffix)
                .apply()
            invoke.resolve()
        } catch (ex: Exception) {
            invoke.reject(ex.message)
        }
    }
}
