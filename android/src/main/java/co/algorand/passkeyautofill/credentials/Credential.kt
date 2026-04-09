package co.algorand.passkeyautofill.credentials

data class Credential(
    val credentialId: String,
    val origin: String,
    val userHandle: String,
    val userId: String,
    val publicKey: String,
    val privateKey: String,
    val count: Int,
    val biometricIv: String? = null
)