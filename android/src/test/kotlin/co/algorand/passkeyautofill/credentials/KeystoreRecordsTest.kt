package co.algorand.passkeyautofill.credentials

import android.util.Base64
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for [KeystoreRecords] — the shared record-format ownership object.
 *
 * `android.util.Base64` is stubbed to delegate to `java.util.Base64`, the same
 * technique `WebAuthnTest` uses, so this exercises the real parsing/sealing
 * logic without needing a device or Robolectric.
 */
class KeystoreRecordsTest {

    @Before
    fun setUp() {
        mockkStatic(Base64::class)
        every { Base64.encodeToString(any<ByteArray>(), any<Int>()) } answers {
            encoder(secondArg()).encodeToString(firstArg<ByteArray>())
        }
        every { Base64.decode(any<String>(), any<Int>()) } answers {
            decoder(secondArg()).decode(firstArg<String>())
        }
    }

    @After
    fun tearDown() {
        unmockkStatic(Base64::class)
    }

    private fun encoder(flags: Int): java.util.Base64.Encoder {
        val encoder = if (flags and Base64.URL_SAFE != 0) {
            java.util.Base64.getUrlEncoder()
        } else {
            java.util.Base64.getEncoder()
        }
        return if (flags and Base64.NO_PADDING != 0) encoder.withoutPadding() else encoder
    }

    private fun decoder(flags: Int): java.util.Base64.Decoder =
        if (flags and Base64.URL_SAFE != 0) java.util.Base64.getUrlDecoder() else java.util.Base64.getDecoder()

    // --- `{"$u8": base64}` metadata byte wrapping ---------------------------

    @Test
    fun wrapBytesThenUnwrapBytesRoundTrips() {
        val bytes = byteArrayOf(1, 2, 3, 4, 5, -1, 0, 127)
        val wrapped = KeystoreRecords.wrapBytes(bytes)
        assertTrue(wrapped.has("\$u8"))
        assertArrayEquals(bytes, KeystoreRecords.unwrapBytes(wrapped))
    }

    @Test
    fun unwrapBytesReturnsNullForALegacyNumberArray() {
        // The legacy `KeyData` encoding never uses the `{"$u8": ...}` wrapper;
        // callers fall back to reading a plain JSON array themselves.
        val legacyShape = JSONArray(listOf(1, 2, 3))
        assertNull(KeystoreRecords.unwrapBytes(legacyShape))
        assertNull(KeystoreRecords.unwrapBytes(null))
    }

    // --- New-layout material sealing (self round trip) ----------------------

    @Test
    fun sealMaterialThenOpenMaterialRoundTrips() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val material = byteArrayOf(10, 20, 30, 40, 50)
        val sealed = KeystoreRecords.sealMaterial(masterKey, material)

        // The new envelope has no `tag` field: the GCM tag is appended to
        // `content`, exactly like the JS `sealData`.
        val envelope = JSONObject(sealed)
        assertTrue(envelope.has("iv"))
        assertTrue(envelope.has("content"))
        assertFalse(envelope.has("tag"))

        assertArrayEquals(material, KeystoreRecords.openMaterial(masterKey, sealed))
    }

    @Test
    fun sealEnvelopeProducesADistinctIvEveryCall() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val first = KeystoreRecords.sealEnvelope(masterKey, "same-plaintext")
        val second = KeystoreRecords.sealEnvelope(masterKey, "same-plaintext")
        assertTrue(first != second)
    }

    @Test
    fun openEnvelopeFailsWithTheWrongMasterKey() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val otherKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val sealed = KeystoreRecords.sealEnvelope(masterKey, "secret-message")
        try {
            KeystoreRecords.openEnvelope(otherKey, sealed)
            org.junit.Assert.fail("expected decryption to fail with the wrong key")
        } catch (_: Exception) {
            // expected: GCM tag verification fails.
        }
    }

    // --- Cross-language fixtures ---------------------------------------------
    //
    // Both vectors below were produced by actually running the JS storage
    // package's own crypto functions (not reimplemented from the spec), so
    // these tests prove cross-language interoperability rather than mere
    // self-consistency:
    //
    //  - `NEW_ENVELOPE_JSON` was produced by calling `sealData` from
    //    `wallet-provider-extensions/keystore/react-native/src/storage/crypto.ts`
    //    directly (via that package's own vitest runner), sealing
    //    `RAW_MATERIAL_B64` (base64 of `RAW_MATERIAL_HEX`) with `MASTER_KEY_HEX`.
    //  - `LEGACY_ENVELOPE_JSON` was produced with Node's built-in
    //    `crypto.createCipheriv("aes-256-gcm", ...)`, mirroring the OLD
    //    `react-native-quick-crypto`-based sealing scheme (tag split into its
    //    own field) that `openData`'s legacy branch (and this module's own
    //    legacy record support) must keep reading.

    private val masterKeyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
    private val rawMaterialHex = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    private val newEnvelopeJson =
        """{"iv":"JiabLQaF4Yg7cHc7","content":"NfM0LTxKtEZX/KxSR7ZJ/UlOCg3GLca2ZPdPiEs+GkPJ3WY3LJP6Tw=="}"""
    private val legacyEnvelopeJson =
        """{"iv":"BwcHBwcHBwcHBwcH","tag":"vFx9xuSdfBWXN3YPFyyWvg==","content":"Yw/BPQx2+oej/mHl9A=="}"""

    private fun hexToBytes(hex: String): ByteArray {
        val out = ByteArray(hex.length / 2)
        for (i in out.indices) {
            out[i] = ((Character.digit(hex[2 * i], 16) shl 4) + Character.digit(hex[2 * i + 1], 16)).toByte()
        }
        return out
    }

    @Test
    fun opensMaterialSealedByTheRealJsSealData() {
        val masterKey = hexToBytes(masterKeyHex)
        val expectedRawMaterial = hexToBytes(rawMaterialHex)

        val opened = KeystoreRecords.openMaterial(masterKey, newEnvelopeJson)

        assertArrayEquals(expectedRawMaterial, opened)
    }

    @Test
    fun opensTheLegacyIvTagContentEnvelopeProducedByNodeCrypto() {
        val masterKey = hexToBytes(masterKeyHex)

        val opened = KeystoreRecords.openEnvelope(masterKey, legacyEnvelopeJson)

        assertEquals("legacy-secret", opened)
    }

    // --- Legacy flat-record decoding -----------------------------------------

    /**
     * Builds a legacy flat record payload exactly the way the pre-split
     * `CredentialRepository`/`commit()` did: `base64url(JSON.stringify(KeyData))`
     * sealed with the legacy `{iv, tag, content}` envelope.
     */
    private fun legacyFlatRecordPayload(masterKey: ByteArray, keyData: JSONObject): String {
        val base64urlJson = Base64.encodeToString(
            keyData.toString().toByteArray(Charsets.UTF_8),
            Base64.URL_SAFE or Base64.NO_WRAP,
        )

        val iv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(masterKey, "AES"), GCMParameterSpec(128, iv))
        val encryptedWithTag = cipher.doFinal(base64urlJson.toByteArray(Charsets.UTF_8))
        val tagSize = 16
        val content = encryptedWithTag.copyOfRange(0, encryptedWithTag.size - tagSize)
        val tag = encryptedWithTag.copyOfRange(encryptedWithTag.size - tagSize, encryptedWithTag.size)

        val envelope = JSONObject()
        envelope.put("iv", Base64.encodeToString(iv, Base64.NO_WRAP))
        envelope.put("tag", Base64.encodeToString(tag, Base64.NO_WRAP))
        envelope.put("content", Base64.encodeToString(content, Base64.NO_WRAP))
        return envelope.toString()
    }

    @Test
    fun decodesALegacyFlatRecordSealedWithTheLegacyEnvelope() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val keyData = JSONObject()
        keyData.put("id", "legacy-credential-id")
        keyData.put("type", "hd-derived-p256")
        keyData.put("publicKey", JSONArray(listOf(1, 2, 3)))
        keyData.put("privateKey", JSONArray(listOf(9, 8, 7)))
        val metadata = JSONObject()
        metadata.put("origin", "https://example.com")
        keyData.put("metadata", metadata)

        val payload = legacyFlatRecordPayload(masterKey, keyData)
        val decoded = KeystoreRecords.decodeLegacyRecord(payload, masterKey)

        assertEquals("legacy-credential-id", decoded.getString("id"))
        assertEquals("hd-derived-p256", decoded.getString("type"))
        assertEquals("https://example.com", decoded.getJSONObject("metadata").getString("origin"))
        assertArrayEquals(byteArrayOf(1, 2, 3), jsonArrayToBytes(decoded.getJSONArray("publicKey")))
        assertArrayEquals(byteArrayOf(9, 8, 7), jsonArrayToBytes(decoded.getJSONArray("privateKey")))
    }

    private fun jsonArrayToBytes(array: JSONArray): ByteArray {
        val bytes = ByteArray(array.length())
        for (i in 0 until array.length()) bytes[i] = array.getInt(i).toByte()
        return bytes
    }

    // --- Passkey vs. wallet-owned record discrimination (used by `clearCredentials`) ---

    @Test
    fun recognisesThisModulesOwnPasskeyTypes() {
        assertTrue(KeystoreRecords.isPasskeyRecordType("hd-derived-p256"))
        assertTrue(KeystoreRecords.isPasskeyRecordType("xhd-derived-p256"))
    }

    @Test
    fun clearingLeavesWalletOwnedRecordsAlone() {
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }

        // A full round trip through the NEW layout for one of this module's own
        // credentials, plus the wallet's own records in the SAME instance.
        val ourId = "our-credential-id"
        val ourMetadata = JSONObject()
        ourMetadata.put("id", ourId)
        ourMetadata.put("type", "hd-derived-p256")
        ourMetadata.put("publicKey", KeystoreRecords.wrapBytes(byteArrayOf(4, 5, 6)))

        val store = mutableMapOf(
            // Ours: metadata + sealed material.
            KeystoreRecords.metadataKey(ourId) to ourMetadata.toString(),
            KeystoreRecords.materialKey(ourId) to
                KeystoreRecords.sealMaterial(masterKey, byteArrayOf(7, 7, 7)),
            // The wallet's: an XHD root and a derived ed25519 key, new layout.
            KeystoreRecords.metadataKey("wallet-root") to
                JSONObject().put("id", "wallet-root").put("type", "hd-root-key").toString(),
            KeystoreRecords.materialKey("wallet-root") to
                KeystoreRecords.sealMaterial(masterKey, ByteArray(96) { it.toByte() }),
            KeystoreRecords.metadataKey("wallet-account") to
                JSONObject().put("id", "wallet-account").put("type", "hd-derived-ed25519").toString(),
            // The wallet's seed, still in the legacy flat layout.
            "wallet-seed" to legacyFlatRecordPayload(
                masterKey,
                JSONObject().put("id", "wallet-seed").put("type", "seed"),
            ),
            // Ours, still in the legacy flat layout.
            "our-legacy-credential" to legacyFlatRecordPayload(
                masterKey,
                JSONObject().put("id", "our-legacy-credential").put("type", "hd-derived-p256"),
            ),
        )

        val removable = KeystoreRecords.keysToRemoveForClear(
            store.keys.toTypedArray(),
            masterKey,
        ) { store[it] }

        assertEquals(
            setOf(
                KeystoreRecords.metadataKey(ourId),
                KeystoreRecords.materialKey(ourId),
                "our-legacy-credential",
            ),
            removable.toSet(),
        )

        // Simulate the sweep and check the wallet's records survived intact.
        removable.forEach { store.remove(it) }
        assertEquals(
            setOf(
                KeystoreRecords.metadataKey("wallet-root"),
                KeystoreRecords.materialKey("wallet-root"),
                KeystoreRecords.metadataKey("wallet-account"),
                "wallet-seed",
            ),
            store.keys,
        )
        assertArrayEquals(
            ByteArray(96) { it.toByte() },
            KeystoreRecords.openMaterial(masterKey, store.getValue(KeystoreRecords.materialKey("wallet-root"))),
        )
    }

    @Test
    fun clearingSkipsLegacyRecordsWhenNoMasterKeyIsAvailable() {
        // Without a master key a legacy record cannot be decoded, so its type is
        // unknown; leaving it alone is the only safe answer.
        val masterKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val store = mapOf(
            "our-legacy-credential" to legacyFlatRecordPayload(
                masterKey,
                JSONObject().put("id", "our-legacy-credential").put("type", "hd-derived-p256"),
            ),
        )

        val removable = KeystoreRecords.keysToRemoveForClear(
            store.keys.toTypedArray(),
            masterKey = null,
        ) { store[it] }

        assertTrue(removable.isEmpty())
    }

    // --- Root selection -----------------------------------------------------

    @Test
    fun readsTheSchemeFromMetadata() {
        val mainKey = JSONObject().put("type", "hd-root-key").put(
            "metadata",
            JSONObject().put("storage", "bytes").put("scheme", "pbkdf2-p256"),
        )
        assertEquals(KeystoreRecords.SCHEME_PBKDF2_P256, KeystoreRecords.schemeOf(mainKey))
    }

    @Test
    fun treatsAnUnlabelledRootAsTheLegacyBip32Root() {
        // Every record written before the `scheme` flag existed is a
        // BIP32-Ed25519 root; guessing pbkdf2-p256 here would re-derive existing
        // credentials against the wrong parent.
        val legacyRoot = JSONObject().put("type", "hd-root-key")
            .put("metadata", JSONObject().put("storage", "bytes"))
        assertEquals(KeystoreRecords.SCHEME_BIP32_ED25519, KeystoreRecords.schemeOf(legacyRoot))
        assertEquals(KeystoreRecords.SCHEME_BIP32_ED25519, KeystoreRecords.schemeOf(JSONObject()))
    }

    @Test
    fun prefersTheMainKeyForANewCredential() {
        // Both roots exist on a migrated wallet, and the BIP32 one is listed
        // first (it is what the wallet used to point at) — a new key must still
        // take the dp256 main key.
        val candidates = listOf(
            KeystoreRecords.ParentKeyRecord("bip32-root", KeystoreRecords.SCHEME_BIP32_ED25519),
            KeystoreRecords.ParentKeyRecord("dp256-main", KeystoreRecords.SCHEME_PBKDF2_P256),
        )
        assertEquals("dp256-main", KeystoreRecords.selectParentKey(candidates, null)?.keyId)
    }

    @Test
    fun honoursTheSchemeAnExistingCredentialIsPinnedTo() {
        val candidates = listOf(
            KeystoreRecords.ParentKeyRecord("dp256-main", KeystoreRecords.SCHEME_PBKDF2_P256),
            KeystoreRecords.ParentKeyRecord("bip32-root", KeystoreRecords.SCHEME_BIP32_ED25519),
        )
        assertEquals(
            "bip32-root",
            KeystoreRecords.selectParentKey(candidates, KeystoreRecords.SCHEME_BIP32_ED25519)?.keyId,
        )
    }

    @Test
    fun refusesToSubstituteAParentForAPinnedCredential() {
        // Deriving an old credential from the main key would produce a different
        // key and silently invalidate the passkey the relying party trusts, so
        // "no parent" is the only correct answer.
        val candidates = listOf(
            KeystoreRecords.ParentKeyRecord("dp256-main", KeystoreRecords.SCHEME_PBKDF2_P256),
        )
        assertNull(KeystoreRecords.selectParentKey(candidates, KeystoreRecords.SCHEME_BIP32_ED25519))
        assertNull(KeystoreRecords.selectParentKey(emptyList(), null))
    }

    @Test
    fun fallsBackToTheMostAuthoritativeRootWhenThereIsNoMainKey() {
        val candidates = listOf(
            KeystoreRecords.ParentKeyRecord("pointed-at", KeystoreRecords.SCHEME_BIP32_ED25519),
            KeystoreRecords.ParentKeyRecord("discovered", KeystoreRecords.SCHEME_BIP32_ED25519),
        )
        assertEquals("pointed-at", KeystoreRecords.selectParentKey(candidates, null)?.keyId)
    }

    // --- Legacy inline material --------------------------------------------

    @Test
    fun readsLegacyMaterialFromANumberArray() {
        val bytes = ByteArray(96) { (it and 0xFF).toByte() }
        val record = JSONObject().put("privateKey", JSONArray(bytes.map { it.toInt() and 0xFF }))
        assertArrayEquals(bytes, KeystoreRecords.materialFromLegacyRecord(record))
    }

    @Test
    fun readsLegacyMaterialFromASeedField() {
        // A seed record names its bytes `seed`, not `privateKey`.
        val bytes = ByteArray(64) { (255 - it).toByte() }
        val record = JSONObject().put("seed", JSONArray(bytes.map { it.toInt() and 0xFF }))
        assertArrayEquals(bytes, KeystoreRecords.materialFromLegacyRecord(record))
    }

    @Test
    fun readsLegacyMaterialFromAHexString() {
        val record = JSONObject().put("privateKey", "0x00ff10")
        assertArrayEquals(byteArrayOf(0, -1, 16), KeystoreRecords.materialFromLegacyRecord(record))
    }

    @Test
    fun returnsNoLegacyMaterialForARecordThatHasNone() {
        // A split-layout record keeps its bytes in `m/<id>`; a domain key has
        // none at all.
        val record = JSONObject().put("type", "hd-derived-p256")
            .put("metadata", JSONObject().put("storage", "none"))
        assertNull(KeystoreRecords.materialFromLegacyRecord(record))
    }

    @Test
    fun doesNotRecogniseWalletOwnedTypesAsPasskeys() {
        // These are exactly the record types the wallet's keystore writes to
        // the SAME shared MMKV instance; `clearCredentials`/`getAllCredentials`
        // must never treat them as this module's own.
        assertFalse(KeystoreRecords.isPasskeyRecordType("seed"))
        assertFalse(KeystoreRecords.isPasskeyRecordType("hd-root-key"))
        assertFalse(KeystoreRecords.isPasskeyRecordType("hd-derived-ed25519"))
        assertFalse(KeystoreRecords.isPasskeyRecordType("ed25519"))
        assertFalse(KeystoreRecords.isPasskeyRecordType(""))
    }
}
