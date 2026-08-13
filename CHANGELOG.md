# [1.0.0-canary.24](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.23...v1.0.0-canary.24) (2026-08-13)

### Bug Fixes

- update vendored keystore packages ([4ae89a7](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/4ae89a704074ba0703bd264dd5f446b19e4cc1a2))

# [1.0.0-canary.23](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.22...v1.0.0-canary.23) (2026-08-13)

### Features

- keystore migrations ([00f01b6](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/00f01b6ce17842a58e989a71696fe809d969b002))

# [1.0.0-canary.22](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.21...v1.0.0-canary.22) (2026-07-15)

### Bug Fixes

- write keychain group into the extension Info.plist so the extension can resolve it ([a98ea08](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/a98ea0827164b5402a3f530579cd6908e52c0242))

### Features

- accept the master key as raw bytes instead of a hex string ([86f85a8](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/86f85a8667489f938266188f7551598c3e14cc0c))
- store the iOS master key in the Keychain instead of plaintext UserDefaults ([00dd362](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/00dd362d7214e91296982e012aedd817b09ab83d))

# [1.0.0-canary.21](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.20...v1.0.0-canary.21) (2026-06-11)

### Bug Fixes

- check for quotes for the DEVELOPMENT_TEAM ([d4aa43d](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/d4aa43dc74c318f9ac8a4d2d4b761d30bb44d576))
- fix missing prf file and target iOS 26 shapes ([150a161](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/150a1615b7e4588bea91bf3900f82f054c939276))

# [1.0.0-canary.20](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.19...v1.0.0-canary.20) (2026-06-10)

### Bug Fixes

- **Android:** improve setting intent handling, gradle includes pickFirst for MMKV. ([27af9e4](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/27af9e470fb2d53f375422b246e3f8d72329b2c0))

# [1.0.0-canary.19](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.18...v1.0.0-canary.19) (2026-06-09)

### Bug Fixes

- **android:** credential repository filter types in getAllCredentials ([2b6523f](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/2b6523fc25aaadb5152b0b0d3d6b3a56e9de1759))

# [1.0.0-canary.18](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.17...v1.0.0-canary.18) (2026-06-09)

### Features

- PRF extension support for deterministically derived secrets ([4b5b05a](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/4b5b05ab146e39b191855ccb01fd4aca5ed32819))

# [1.0.0-canary.17](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.16...v1.0.0-canary.17) (2026-05-28)

### Bug Fixes

- allow configurable AAGUID ([d5a8176](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/d5a81765ba150e9873e18875f0ac9f7bc4aede93))
- **Android:** add NoOp methods for iOS-specific functionality ([e2c64db](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/e2c64db479cda70c7c61b7ab3021b70db949a15b))
- compile issue ([16b939c](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/16b939cb555e75bd052ce57a41a838810a2770cd))

### Features

- configurable credential requirement ([dc09916](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/dc09916d1ee5c8c9d33e53b57f00171472f4f665))
- record lastUsedAt/count and fix error handling ([47b40ab](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/47b40abf692c0f7cffee6f2266c66f61f8006a65))

# [1.0.0-canary.16](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.15...v1.0.0-canary.16) (2026-05-15)

### Bug Fixes

- align ios autofill root key flow ([1287f57](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/1287f57952b41829032ef368bad826624375e9a3))

### Features

- add iOS passkey autofill provider ([9aad8f8](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/9aad8f8ceb2ad54cf53847b60dd6e70d5b2a1f2b))

# [1.0.0-canary.15](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.14...v1.0.0-canary.15) (2026-04-10)

### Bug Fixes

- use bouncycastle bcprov-jdk15to18 for android ([cd860b2](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/cd860b2012f2189e854137afa55c7a0c0dc1b94c))

# [1.0.0-canary.14](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.13...v1.0.0-canary.14) (2026-04-10)

### Bug Fixes

- switch to maven for local AAR dependency ([f4e52b4](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/f4e52b46d618e6e8a7972e649c5d75d768e32339))

# [1.0.0-canary.13](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.12...v1.0.0-canary.13) (2026-04-10)

### Bug Fixes

- bump keystore to 1.0.0-canary.9 ([f093bab](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/f093bab0b74d5cbf93e8f03ecd8d56c77597d3f5))

# [1.0.0-canary.12](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.11...v1.0.0-canary.12) (2026-04-10)

### Features

- **android:** biometrics single tap and fallback ([a6cbe4c](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/a6cbe4cf51579b15b2a219e1e06e843bb6001ed4))
- **android:** support DER format ([492034f](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/492034f8b031e795b2575be69da8c3a1adb9096c))

# [1.0.0-canary.11](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.10...v1.0.0-canary.11) (2026-03-31)

### Bug Fixes

- update service url ([ffc2c22](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/ffc2c22e18661cf5a159eef5b06303b94981df6b))

# [1.0.0-canary.10](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.9...v1.0.0-canary.10) (2026-03-30)

### Bug Fixes

- bouncy castle provider insertion order ([9e9039d](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/9e9039deab02f75f5a4397cedc098c0ca2e24875))

# [1.0.0-canary.9](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.8...v1.0.0-canary.9) (2026-03-30)

### Bug Fixes

- x logins, refactor example views to be dialogs ([e7a1ccf](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/e7a1ccf91f88b5c369ff3082f06d538fc8b3db89))

# [1.0.0-canary.8](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.7...v1.0.0-canary.8) (2026-03-27)

### Features

- passkey added and authenticated events ([b9871f4](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/b9871f475a9a633ae98d30a702ef2814ec8ae5e0))

# [1.0.0-canary.7](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.6...v1.0.0-canary.7) (2026-03-24)

### Bug Fixes

- update package lock and include in CI/CD ([1d775cd](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/1d775cdde170a6ef400a1ee8a01fce759ddb1f1e))

# [1.0.0-canary.6](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.5...v1.0.0-canary.6) (2026-03-24)

### Bug Fixes

- include banner for package README ([60a6559](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/60a655932faac6de57daf0f30261f2d03a2c1476))

# [1.0.0-canary.5](https://github.com/algorandfoundation/react-native-passkey-autofill/compare/v1.0.0-canary.4...v1.0.0-canary.5) (2026-03-24)

### Features

- **android:** add allowed credentials mapping ([e7134fc](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/e7134fc1e5bf09649155e38010e4ef9728580812))
- **android:** credential compatibility with system-provided clientDataHash and compact JSON ([428e96f](https://github.com/algorandfoundation/react-native-passkey-autofill/commit/428e96f89b73cd35fdbfaa6669f39da68403e17e))
