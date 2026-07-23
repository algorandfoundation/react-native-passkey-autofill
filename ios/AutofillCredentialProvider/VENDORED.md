# Vendored native library base — iOS FIDO/WebAuthn

> Provenance note for the Liquid Auth consolidation (see
> `react-native-liquid-auth/docs/CONSOLIDATION_PLAN.md`, decisions **D1** / **D4**).

This directory derives its FIDO2 / WebAuthn logic from the **same upstream
original SDK** that `react-native-liquid-auth`'s iOS signaling port targets. The
two React Native packages share one upstream source: this one vendors the
**FIDO/WebAuthn portion**; `react-native-liquid-auth` vendors the **signaling
portion**. **No signaling / WebRTC code lives in this package.**

| | |
| --- | --- |
| **Upstream repo** | `algorandfoundation/liquid-auth-ios` |
| **Upstream path** | `Sources/LiquidAuthSDK/` (`AssertionApi`, `AttestationApi`, `AuthenticatorData`, `Utility`) |
| **Derived from commit** | `384c926d334f69e744b80b6166af3d034970170d` (2025-08-20) |
| **Portion vendored** | FIDO/WebAuthn only (attestation, assertion, authenticator data, COSE/CBOR helpers) |

## Sync direction

**Upstream → vendored copy (one-way).** Edit the originals in `liquid-auth-ios`
first, then sync WebAuthn changes *down* into this copy. This tree has been
specialized for the iOS `ASCredentialProvider` autofill extension, so re-syncing
is a guided merge rather than a byte copy.
