package co.algorand.passkeyautofill.credentials

data class Credential(
    val credentialId: String,
    val origin: String,
    val userHandle: String,
    val userId: String,
    val publicKey: String,
    val privateKey: String,
    val count: Int,
    val biometricIv: String? = null,
    /** The root record this credential's key was derived from, when known. */
    val parentKeyId: String? = null,
    /**
     * The derivation scheme this credential is pinned to for life
     * ([KeystoreRecords.SCHEME_PBKDF2_P256] or
     * [KeystoreRecords.SCHEME_BIP32_ED25519]).
     *
     * `null` on every credential created before the wallet exposed its
     * deterministic-P256 main key, and those all derive from the BIP32-Ed25519
     * root — re-deriving one against a different parent would produce a
     * different key and silently break the passkey the relying party already
     * trusts.
     */
    val derivationScheme: String? = null,
    /**
     * Which identity string this credential's material is derived from (see
     * [PasskeyDerivation]). Records written before the field existed read back as
     * [PasskeyDerivation.VERSION_LEGACY_LABEL], leaving their derivation
     * unchanged.
     */
    val derivationVersion: Int = PasskeyDerivation.VERSION_LEGACY_LABEL,
)