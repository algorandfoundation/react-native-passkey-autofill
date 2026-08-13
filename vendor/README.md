# Vendored keystore packages

Interim home for the split keystore packages until they are published to npm.

The monolithic `@algorandfoundation/keystore` was split into
`@algorandfoundation/keystore-core` (platform-agnostic engine) plus one adapter
per platform; the `example/` app in this repo consumes `keystore-core` and
`@algorandfoundation/react-native-keystore`. Both currently only exist in the
[`wallet-provider-extensions`](https://github.com/algorandfoundation/wallet-provider-extensions)
repository — npm still carries a `0.0.1-beta.0` placeholder for `keystore-core`.

They are vendored as tarballs rather than referenced as `file:../…` directories
for two reasons:

- `pnpm pack` rewrites the workspace-only `catalog:` / `workspace:` specifiers
  in those manifests into concrete versions, which pnpm can resolve; a `file:`
  reference straight at the source directory keeps the unresolved specifiers
  and fails to install.
- pnpm installs a `file:` **directory** as a symlink, and Metro refuses to
  resolve a module whose real path lies outside the project root (it is not in
  `watchFolders`), so `expo export` / `expo start` fails. A tarball is
  extracted into `node_modules/` as a real directory and bundles normally.

Regenerate them after changing the keystore source:

```bash
cd ../wallet-provider-extensions
pnpm install
pnpm --filter @algorandfoundation/keystore-core build
pnpm --filter @algorandfoundation/react-native-keystore build
(cd keystore/core && pnpm pack --pack-destination ../../../react-native-passkey-autofill/vendor)
(cd keystore/react-native && pnpm pack --pack-destination ../../../react-native-passkey-autofill/vendor)
cd ../react-native-passkey-autofill && pnpm install
```

The root `package.json`'s `pnpm.overrides["@algorandfoundation/keystore-core"]`
entry points the copy that `react-native-keystore` asks for at the same
tarball, since that version is not on npm yet. `react-native-mmkv` and
`react-native-quick-crypto` are already pinned workspace-wide in that same
`pnpm.overrides` block, so `react-native-keystore`'s own (older) ranges for
those two resolve to the versions the rest of the workspace uses without an
extra override.

Once the packages are released, delete this directory, drop the
`keystore-core` override and depend on the published versions instead.
