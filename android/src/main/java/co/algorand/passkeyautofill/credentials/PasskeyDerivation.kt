package co.algorand.passkeyautofill.credentials

/**
 * Which identity a credential's deterministic material is derived from.
 *
 * Everything deterministic about a passkey — the P-256 signing key
 * (`SHA-512(mainKey ‖ origin ‖ identity ‖ counter)[0..32]`, the canonical
 * `@algorandfoundation/dp256` contract) and the PRF `credRandom` — is keyed on
 * an identity string. Which string that is has to be recorded per credential:
 * PRF is recomputed from the seed on EVERY assertion, so silently changing the
 * input would silently change every already-issued PRF secret.
 *
 * - [VERSION_LEGACY_LABEL] is what earlier builds used: the account LABEL
 *   (`user.name`, lowercased). Relying parties rename users routinely — an email
 *   or username change makes the credential non-re-derivable — and the label is
 *   platform-specific, which is why Android and iOS derived different keys for
 *   the same account.
 * - [VERSION_CANONICAL_USER_ID] is the RP-owned `user.id` (base64url, case
 *   preserved), the one identifier the spec guarantees is stable for the
 *   lifetime of the credential. It is identical on both platforms, so the same
 *   seed + relying party + account now reproduces the same key and the same PRF
 *   outputs on Android and iOS.
 *
 * Records written before the field existed read back as
 * [VERSION_LEGACY_LABEL], so their derivation is unchanged. This includes the
 * wallet's own keystore-derived passkeys, whose keys the keystore derives from
 * the account address — they keep deriving from it until the wallet opts them in
 * by writing `metadata.derivationVersion`.
 */
object PasskeyDerivation {
    /** The account label (`user.name`), lowercased. Legacy; never stamped on new credentials. */
    const val VERSION_LEGACY_LABEL = 1

    /** The relying party's `user.id`, base64url and case preserved. */
    const val VERSION_CANONICAL_USER_ID = 2

    /** Stamped on credentials created by this build. */
    const val VERSION_CURRENT = VERSION_CANONICAL_USER_ID

    /** Placeholder written when a creation request carries no `user.id`. */
    private const val PLACEHOLDER_USER_ID = "unknown-id"

    /**
     * Normalise a `user.id` to unpadded base64url so an encoding variant can
     * never change the derived key. The value is OPAQUE RP-owned bytes, so case
     * is significant and must be preserved.
     */
    fun normalizeUserId(userId: String?): String =
        (userId ?: "")
            .trim()
            .trimEnd('=')
            .replace('+', '-')
            .replace('/', '_')

    /** Whether a `user.id` is present and usable as a derivation input. */
    fun isDerivableUserId(userId: String?): Boolean {
        val normalized = normalizeUserId(userId)
        return normalized.isNotEmpty() && normalized != PLACEHOLDER_USER_ID
    }

    /**
     * The version to stamp on a credential being created: canonical when the
     * relying party supplied a `user.id`, otherwise legacy — a placeholder must
     * never become key material.
     */
    fun versionForNewCredential(userId: String?): Int =
        if (isDerivableUserId(userId)) VERSION_CURRENT else VERSION_LEGACY_LABEL

    /**
     * The derivation identity for a credential, ready to be passed verbatim to
     * the key/PRF derivation (already normalised and case-folded as its version
     * requires — callers must not lowercase it again).
     */
    fun identity(version: Int, userId: String?, legacyLabel: String): String =
        if (version >= VERSION_CANONICAL_USER_ID && isDerivableUserId(userId)) {
            normalizeUserId(userId)
        } else {
            legacyLabel.lowercase()
        }

    /** The derivation identity of a stored credential. */
    fun identity(credential: Credential): String =
        identity(credential.derivationVersion, credential.userId, credential.userHandle)
}
