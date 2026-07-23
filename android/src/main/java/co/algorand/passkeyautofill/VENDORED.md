# Vendored native library base — Android FIDO/WebAuthn

> Provenance note for the Liquid Auth consolidation (see
> `react-native-liquid-auth/docs/CONSOLIDATION_PLAN.md`, decisions **D1** / **D4**).

This package derives its FIDO2 / WebAuthn logic from the **same upstream
original SDK** that `react-native-liquid-auth` vendors its signaling stack from.
The two React Native packages share one upstream source: this one vendors the
**FIDO/WebAuthn portion**; `react-native-liquid-auth` vendors the **signaling
portion**. **No signaling / WebRTC code lives in this package.**

| | |
| --- | --- |
| **Upstream repo** | `algorandfoundation/liquid-auth-android` |
| **Upstream path** | `liquid/src/main/java/foundation/algorand/auth/fido2/` (`AttestationApi`, `AssertionApi`, response extensions) |
| **Derived from commit** | `05b51f2609c15c8daa74848ce83f4a1fad397a85` (2026-03-07) |
| **Portion vendored** | FIDO/WebAuthn only (attestation, assertion, credential handling) |
| **Local namespace** | `co.algorand.passkeyautofill` (renamed + evolved for the OS passkey-autofill provider) |

## Sync direction

**Upstream → vendored copy (one-way).** Edit the originals in
`liquid-auth-android` first, then sync WebAuthn changes *down* into this copy.
This tree has been renamed and specialized for the Credential Manager /
autofill provider, so re-syncing is a guided merge rather than a byte copy.
