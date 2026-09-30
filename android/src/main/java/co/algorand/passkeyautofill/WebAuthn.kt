package co.algorand.passkeyautofill

import android.content.Context
import android.util.Base64
import java.nio.ByteBuffer
import java.util.UUID

/**
 * WebAuthn attestation helpers.
 *
 * The AndroidX credentials library (`AuthenticatorAttestationResponse`) always emits an
 * all-zero AAGUID. To present the same authenticator identity as the iOS provider and the
 * native Pera apps, we splice a configured AAGUID into the attestationObject after AndroidX
 * builds it. The value is injected by the Expo config plugin (`aaguid` prop) as the
 * `passkey_autofill_aaguid` string resource.
 */
object WebAuthn {
    private const val AAGUID_RESOURCE = "passkey_autofill_aaguid"
    private const val AAGUID_LENGTH = 16

    // authData layout: rpIdHash(32) + flags(1) + signCount(4) then attestedCredentialData,
    // which begins with the 16-byte AAGUID.
    private const val AAGUID_OFFSET_IN_AUTH_DATA = 37

    private const val BASE64_FLAGS = Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING

    private val ZERO_AAGUID = ByteArray(AAGUID_LENGTH)

    /** Returns the configured AAGUID bytes, or null when unset/blank/all-zero/malformed. */
    fun configuredAaguid(context: Context): ByteArray? {
        val resId = context.resources.getIdentifier(AAGUID_RESOURCE, "string", context.packageName)
        if (resId == 0) return null
        val raw = context.getString(resId).trim()
        if (raw.isEmpty()) return null
        val bytes = try {
            uuidToBytes(UUID.fromString(raw))
        } catch (e: IllegalArgumentException) {
            return null
        }
        return if (bytes.contentEquals(ZERO_AAGUID)) null else bytes
    }

    /**
     * Overwrites the 16-byte AAGUID inside the attestationObject's authData with [aaguid].
     * Returns the re-encoded (base64url, no padding) attestationObject.
     */
    fun injectAaguid(attestationObjectB64Url: String, aaguid: ByteArray): String {
        require(aaguid.size == AAGUID_LENGTH) { "AAGUID must be $AAGUID_LENGTH bytes" }
        val bytes = Base64.decode(attestationObjectB64Url, BASE64_FLAGS)
        val authDataStart = findAuthDataContentStart(bytes)
        val offset = authDataStart + AAGUID_OFFSET_IN_AUTH_DATA
        require(offset + AAGUID_LENGTH <= bytes.size) {
            "attestationObject is too short to contain an AAGUID"
        }
        System.arraycopy(aaguid, 0, bytes, offset, AAGUID_LENGTH)
        return Base64.encodeToString(bytes, BASE64_FLAGS)
    }

    /**
     * Extracts the raw `authData` bytes from a base64url-encoded attestationObject.
     * Returns null when the structure cannot be parsed.
     */
    fun extractAuthData(attestationObjectBytes: ByteArray): ByteArray? {
        return try {
            val c = Cursor(attestationObjectBytes)
            val (major, count) = readHead(c)
            require(major == 5) { "attestationObject is not a CBOR map" }
            repeat(count.toInt()) {
                val key = readTextString(c)
                if (key == "authData") {
                    val (valueMajor, valueLen) = readHead(c)
                    require(valueMajor == 2) { "authData is not a CBOR byte string" }
                    val s = c.pos
                    return attestationObjectBytes.copyOfRange(s, s + valueLen.toInt())
                }
                skipItem(c)
            }
            null
        } catch (e: Exception) {
            null
        }
    }

    private fun uuidToBytes(uuid: UUID): ByteArray =
        ByteBuffer.allocate(AAGUID_LENGTH)
            .putLong(uuid.mostSignificantBits)
            .putLong(uuid.leastSignificantBits)
            .array()

    // --- Minimal CBOR reader: locate the "authData" byte-string value in the top-level map ---

    private class Cursor(val buf: ByteArray) {
        var pos = 0
    }

    private fun findAuthDataContentStart(buf: ByteArray): Int {
        val c = Cursor(buf)
        val (major, count) = readHead(c)
        require(major == 5) { "attestationObject is not a CBOR map" }
        repeat(count.toInt()) {
            val key = readTextString(c)
            if (key == "authData") {
                val (valueMajor, valueLen) = readHead(c)
                require(valueMajor == 2) { "authData is not a CBOR byte string" }
                val start = c.pos
                c.pos += valueLen.toInt()
                return start
            }
            skipItem(c)
        }
        throw IllegalArgumentException("authData not found in attestationObject")
    }

    /** Reads a CBOR item head, returning (majorType, argument) and advancing the cursor. */
    private fun readHead(c: Cursor): Pair<Int, Long> {
        val initial = c.buf[c.pos].toInt() and 0xff
        c.pos += 1
        val major = initial ushr 5
        val additional = initial and 0x1f
        val argument = when {
            additional < 24 -> additional.toLong()
            additional == 24 -> readUInt(c, 1)
            additional == 25 -> readUInt(c, 2)
            additional == 26 -> readUInt(c, 4)
            additional == 27 -> readUInt(c, 8)
            else -> throw IllegalArgumentException("Unsupported CBOR additional info: $additional")
        }
        return Pair(major, argument)
    }

    private fun readUInt(c: Cursor, byteCount: Int): Long {
        var value = 0L
        repeat(byteCount) {
            value = (value shl 8) or (c.buf[c.pos].toLong() and 0xff)
            c.pos += 1
        }
        return value
    }

    private fun readTextString(c: Cursor): String {
        val (major, length) = readHead(c)
        require(major == 3) { "Expected a CBOR text-string map key" }
        val value = String(c.buf, c.pos, length.toInt(), Charsets.UTF_8)
        c.pos += length.toInt()
        return value
    }

    private fun skipItem(c: Cursor) {
        val (major, argument) = readHead(c)
        when (major) {
            0, 1 -> Unit // unsigned/negative integer: value is the head argument
            2, 3 -> c.pos += argument.toInt() // byte/text string
            4 -> repeat(argument.toInt()) { skipItem(c) } // array
            5 -> repeat(argument.toInt()) { skipItem(c); skipItem(c) } // map: key + value
            6 -> skipItem(c) // tag: skip the tagged item
            7 -> Unit // simple value / float: width already consumed by readHead
            else -> throw IllegalArgumentException("Unsupported CBOR major type: $major")
        }
    }
}
