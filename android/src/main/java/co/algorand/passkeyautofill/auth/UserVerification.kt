package co.algorand.passkeyautofill.auth

/**
 * Whether the user was actually verified for ONE passkey operation, and what
 * the relying party asked for.
 *
 * WebAuthn's UV flag may only be set when a user-verification ceremony ran
 * for this operation. Device unlock, tapping the chooser entry or tapping
 * "Create" in the wallet's own sheet are not verification. Both activities
 * therefore track two facts — did the system's Credential Manager prompt
 * succeed, did a manual `BiometricPrompt` succeed — and derive the flag from
 * them at the single point where the response is built, instead of hard-coding
 * `uv = true`.
 */
object UserVerification {
    const val REQUIRED = "required"
    const val PREFERRED = "preferred"
    const val DISCOURAGED = "discouraged"

    /** The ceremony outcome for one operation. */
    data class Outcome(
        /** What the relying party requested, normalised to one of the three values. */
        val requested: String,
        /** `true` only if a verification ceremony succeeded for this operation. */
        val verified: Boolean,
    ) {
        /**
         * Whether a response may be produced at all. `required` without a
         * completed ceremony must fail rather than be answered with `uv = 0`
         * — and certainly never with `uv = 1`.
         */
        val satisfiesRequest: Boolean get() = verified || requested != REQUIRED
    }

    /**
     * Normalises the request's `userVerification`; unknown or absent values
     * read as `preferred`, the WebAuthn default.
     */
    fun normalize(requested: String?): String = when (requested?.trim()?.lowercase()) {
        REQUIRED -> REQUIRED
        DISCOURAGED -> DISCOURAGED
        else -> PREFERRED
    }

    /**
     * @param requested the request's `userVerification`.
     * @param systemVerified the system-provided `BiometricPromptResult` for this
     *   operation reports success (Single Tap flow).
     * @param manualVerified a `BiometricPrompt` this activity showed succeeded.
     */
    fun outcome(requested: String?, systemVerified: Boolean, manualVerified: Boolean): Outcome =
        Outcome(normalize(requested), verified = systemVerified || manualVerified)
}
