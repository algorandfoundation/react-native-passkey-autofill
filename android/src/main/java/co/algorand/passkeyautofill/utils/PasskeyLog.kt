package co.algorand.passkeyautofill.utils

import android.content.Context
import android.content.pm.ApplicationInfo
import android.util.Log

/**
 * The one place this module writes to logcat.
 *
 * Passkey ceremonies handle material that must never reach a log: request and
 * response JSON (the assertion response carries PRF output), credential ids,
 * user ids and handles, challenges, ciphers and other crypto objects,
 * signatures, keys. Anything able to read logcat — a privileged local app,
 * ADB, a rooted device, an MDM or a support log collector — would otherwise
 * see it. So:
 *
 * - [d] and [i] are emitted only when the host app is debuggable
 *   (`FLAG_DEBUGGABLE`). A release build strips them entirely, and an
 *   uninitialised logger behaves like a release build.
 * - [w] and [e] are always emitted, because operators need failures. Their
 *   messages must be fixed strings plus non-sensitive fields (a scheme name,
 *   a boolean, a count, a class name) — never a payload.
 *
 * Every other file goes through this object; `LoggingPolicyTest` fails the
 * build on a raw `android.util.Log` import anywhere else in the module.
 */
object PasskeyLog {
    @Volatile
    private var debuggable: Boolean? = null

    /** Records whether the host app is debuggable. Cheap and idempotent. */
    fun init(context: Context) {
        debuggable = (context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
    }

    /** Whether debug/info lines are emitted. Unknown reads as release. */
    val isDebugEnabled: Boolean
        get() = debuggable == true

    fun d(tag: String, message: String) {
        if (isDebugEnabled) Log.d(tag, message)
    }

    fun i(tag: String, message: String) {
        if (isDebugEnabled) Log.i(tag, message)
    }

    fun w(tag: String, message: String, throwable: Throwable? = null) {
        if (throwable == null) Log.w(tag, message) else Log.w(tag, message, throwable)
    }

    fun e(tag: String, message: String, throwable: Throwable? = null) {
        if (throwable == null) Log.e(tag, message) else Log.e(tag, message, throwable)
    }
}
