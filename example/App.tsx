import { useEvent } from 'expo';
import ReactNativePasskeyAutofill from 'react-native-passkey-autofill';
import { Button, SafeAreaView, ScrollView, Text, View, TextInput, StyleSheet } from 'react-native';
import {useEffect, useState} from 'react';
import { Passkey } from 'react-native-passkey';
import {install} from 'react-native-quick-crypto'
import { sha512_256 } from "@noble/hashes/sha2.js";
import { base32 } from "@scure/base";
import { Buffer } from "buffer";
import {WithKeyStore, getMasterKey, type KeyStoreExtension, storage, decode, decryptData} from "@algorandfoundation/react-native-keystore";
import {Provider} from '@algorandfoundation/wallet-provider'
import {Store} from "@tanstack/store";
import type { Key } from "@algorandfoundation/keystore";
install();

// Use this method to check if passkeys are supported on the device

const isSupported: boolean = Passkey.isSupported();

const keyStore = new Store<{keys: Key[], status: string}>({keys: [], status: "idle"});

const provider: KeyStoreExtension = WithKeyStore({
  name: 'passkey-autofill-example',
  version: '1.0.0',
}, {
  keystore: {
    store: keyStore,
    hooks: Object.assign((_id: string, cb: Function, opts: any) => cb(opts), {
      before: () => {},
      after: () => {},
      wrap: () => {},
      remove: () => {},
    }) as any
  }
});

export function encodeAddress(publicKey: Uint8Array<ArrayBufferLike>): string {
  const hash = sha512_256(publicKey); // 32 bytes
  const checksum = hash.slice(-4); // last 4 bytes
  const addressBytes = new Uint8Array([...publicKey, ...checksum]);
  return base32.encode(addressBytes).replace(/=+$/, "").toUpperCase();
}

export function toBase64URL(arr: Uint8Array | ArrayBuffer): string {
  const base64 = Buffer.from(arr).toString('base64');
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function fromBase64Url(base64url: string): Uint8Array {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(base64, 'base64'));
}

async function generateEd25519KeyPair() {
  const keyPair = await crypto.subtle.generateKey(
      {
        name: "Ed25519", // Specify the algorithm name
        namedCurve: "Ed25519", // Redundant but good practice
      },
      true, // Set to true to allow keys to be extracted (exported)
      ["sign", "verify"] // Define the allowed operations for the keys
  );

  return {
    privateKey: keyPair.privateKey,
    publicKey: await crypto.subtle.exportKey("raw", keyPair.publicKey)
  };
}

type Account = {privateKey:  CryptoKey, publicKey: ArrayBuffer}
export default function App() {
  const onChangePayload = useEvent(ReactNativePasskeyAutofill, 'onChange');
  const [account, setAccount] = useState<Account | null>(null);
  const [xhdKeyId, setXhdKeyId] = useState<string | null>(null);
  const [xhdEd25519KeyId, setXhdEd25519KeyId] = useState<string | null>(null);
  const [keys, setKeys] = useState<Key[]>([]);
  const [status, setStatus] = useState(keyStore.state.status);

  const loadKeysFromStorage = async () => {
    try {
      const allKeys = storage.getAllKeys();
      const masterKey = await getMasterKey();
      const loadedKeys: Key[] = [];

      for (const id of allKeys) {
        if (id === 'credentials') {
          const json = storage.getString(id);
          if (json) {
            try {
              const creds = JSON.parse(json);
              creds.forEach((c: any) => {
                loadedKeys.push({
                  id: c.credentialId,
                  type: 'passkey' as any,
                  algorithm: 'P256',
                  metadata: {
                    origin: c.origin,
                    userHandle: c.userHandle,
                    userId: c.userId
                  },
                  publicKey: fromBase64Url(c.publicKey)
                });
              });
            } catch (e) {
              console.warn('Failed to parse credentials:', e);
            }
          }
          continue;
        }

        const encrypted = storage.getString(id);
        if (encrypted) {
          try {
            const decrypted = decryptData(masterKey, encrypted);
            const data = decode(decrypted);
            // Strip private keys/seeds for the reactive state
            const { privateKey, seed, ...keyMetadata } = data as any;
            loadedKeys.push(keyMetadata);
          } catch (e) {
            console.warn(`Failed to decrypt key ${id}:`, e);
          }
        }
      }
      
      keyStore.setState(s => ({ ...s, keys: loadedKeys }));
    } catch (e) {
      console.error('Error loading keys from storage:', e);
    }
  };

  useEffect(() => {
    // Initial keys from store
    setKeys(keyStore.state.keys);
    setStatus(keyStore.state.status);

    // Subscribe to store changes
    return keyStore.subscribe(() => {
      setKeys(keyStore.state.keys);
      setStatus(keyStore.state.status);
    });
  }, []);

  useEffect(() => {
    loadKeysFromStorage();
  }, []);

  useEffect(() => {
    if(!account) {
      generateEd25519KeyPair().then(setAccount)
    }
  }, [account]);

  useEffect(() => {
    // Ensure the master key is initialized in the Keychain and synced with Autofill
    getMasterKey().then(key => {
      ReactNativePasskeyAutofill.setParentSecret(key.toString('hex')).catch(console.error);
    }).catch(console.error);

    // Configure default intent actions for this example app
    ReactNativePasskeyAutofill.configureIntentActions(
      'co.algorand.passkeyautofill.GET_PASSKEY',
      'co.algorand.passkeyautofill.CREATE_PASSKEY'
    ).catch(console.error);
  }, []);

  const handleClearCredentials = async () => {
    try {
      provider.key.store.clear();
      keyStore.setState(s => ({ ...s, keys: [] }));
      alert('Credentials and keys cleared');
    } catch (e) {
      alert('Failed to clear credentials: ' + e);
    }
  };

  const handleCreatePasskey = async () => {
    try {
      if (!account) {
        alert('Account not ready');
        return;
      }
      const response = await fetch('https://fido.shore-tech.net/attestation/request', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          "username": encodeAddress(new Uint8Array(account.publicKey)),
          "displayName": "Liquid Auth User",
          "authenticatorSelection": {
            "userVerification": "required"
          },
          "extensions": {
            "liquid": true
          }
        },),
      });
      const options = await response.json();
      console.log('Passkey creation options:', options);
      if (options.error) {
          throw new Error(options.error);
      }
      
      const result: any = await Passkey.create(options);
      console.log('Passkey creation result:', result);

      // If we have an Ed25519 key, add the liquid extension result to simulate the validation flow
      if (xhdEd25519KeyId) {
        const ed25519Key = keys.find(k => k.id === xhdEd25519KeyId);
        if (ed25519Key && ed25519Key.publicKey) {
          const challenge = fromBase64Url(options.challenge);
          const signature = await provider.key.store.sign(xhdEd25519KeyId, challenge);
          
          result.clientExtensionResults = {
            ...result.clientExtensionResults,
            liquid: {
              requestId: 'example-session-' + Date.now(),
              origin: 'fido.shore-tech.net',
              type: 'algorand',
              address: encodeAddress(ed25519Key.publicKey),
              signature: toBase64URL(signature),
              device: 'Passkey AutoFill Example'
            }
          };
          console.log('Added liquid extension to result:', result.clientExtensionResults.liquid);
        }
      }

      // Submit the result to the debug service
      const submitResponse = await fetch('https://fido.shore-tech.net/attestation/response', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(result),
      });
      const submitResult = await submitResponse.json();
      console.log('Passkey submission result:', submitResult);
      if (submitResult.error) {
          throw new Error(submitResult.error);
      }

      // Rehydrate the store from storage to show the new passkey
      await loadKeysFromStorage();

      alert('Passkey created and submitted successfully!');
    } catch (e) {
      console.error('Passkey creation error:', e);
      alert('Failed to create passkey: ' + e);
    }
  };

  const handleCreateXHDKey = async () => {
    try {
      // 1. Import a seed
      const seed = new Uint8Array(32).fill(0xAA);
      const seedId = await provider.key.store.importSeed!(seed, { name: 'Main Seed' });
      console.log('Seed imported:', seedId);

      // 2. Generate a XHDDomainP256 key
      const keyId = await provider.key.store.generate!({
        type: 'hd-derived-p256',
        algorithm: 'P256',
        extractable: false,
        keyUsages: ['sign'],
        params: {
          parentKeyId: seedId,
          origin: 'fido.shore-tech.net',
          userHandle: 'user-123',
          counter: 0,
        }
      });
      
      console.log('XHD Key created:', keyId);
      setXhdKeyId(keyId);
      await loadKeysFromStorage();
      alert('XHD Key created successfully!\nID: ' + keyId);
    } catch (e) {
      console.error('XHD creation error:', e);
      alert('Failed to create XHD key: ' + e);
    }
  };

  const handleCreateXHDEd25519Key = async () => {
    try {
      // 1. Import a seed
      const seed = new Uint8Array(32).fill(0xAA);
      const seedId = await provider.key.store.importSeed!(seed, { name: 'Main Seed' });
      
      // 2. Generate HD Root Key
      const rootKeyId = await provider.key.store.generate!({
        type: 'hd-root-key',
        algorithm: 'raw',
        extractable: true,
        keyUsages: ['deriveKey', 'deriveBits'],
        params: {
          parentKeyId: seedId
        }
      });

      // 3. Generate a XHDEd25519 key
      const keyId = await provider.key.store.generate!({
        type: 'hd-derived-ed25519',
        algorithm: 'EdDSA',
        extractable: true,
        keyUsages: ['sign', 'verify'],
        params: {
          parentKeyId: rootKeyId,
          context: 0,
          account: 0,
          index: 0,
          derivation: 9
        }
      });
      setXhdEd25519KeyId(keyId);
      await loadKeysFromStorage();
      alert('XHD Ed25519 Key created: ' + keyId);
    } catch (e: any) {
      alert('Error: ' + e.message);
    }
  };

  console.log(isSupported)
  if(!isSupported) return (
      <View style={styles.view}>
        <Text>Passkeys are not supported on this device</Text>
      </View>
  )
  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.container}>
        <Text style={styles.header}>Passkey AutoFill Example</Text>
        
        <Group name="Credentials">
          <View style={{ gap: 10 }}>
            <Button title="Clear Credentials" onPress={handleClearCredentials} color="red" />
          </View>
        </Group>

        <Group name="Functions">
          <View style={{ gap: 10 }}>
            <Button title="Create Passkey" onPress={handleCreatePasskey} />
            <Button title="Create XHD P256 Key" onPress={handleCreateXHDKey} color="green" />
            <Button title="Create XHD Ed25519 Key" onPress={handleCreateXHDEd25519Key} color="blue" />
            <Text>{ReactNativePasskeyAutofill.hello()}</Text>
          </View>
        </Group>

        <Group name={`Keys in Store (${status})`}>
          {keys.length > 0 ? (
            keys.map((key, index) => (
              <View key={key.id || index} style={styles.credItem}>
                <Text style={styles.credText}>ID: {key.id}</Text>
                <Text style={styles.credText}>Type: {key.type}</Text>
                <Text style={styles.credText}>Algo: {key.algorithm}</Text>
                {key.keyUsages && (
                  <Text style={styles.credText}>Usages: {key.keyUsages.join(', ')}</Text>
                )}
                {key.metadata && (key.metadata as any).origin && (
                  <Text style={styles.credText}>Origin: {(key.metadata as any).origin}</Text>
                )}
                {key.metadata && (key.metadata as any).userHandle && (
                  <Text style={styles.credText}>User: {(key.metadata as any).userHandle}</Text>
                )}
              </View>
            ))
          ) : (
            <Text>No keys in store</Text>
          )}
        </Group>
      </ScrollView>
    </SafeAreaView>
  );
}

function Group(props: { name: string; children: React.ReactNode }) {
  return (
    <View style={styles.group}>
      <Text style={styles.groupHeader}>{props.name}</Text>
      {props.children}
    </View>
  );
}

const styles = StyleSheet.create({
  header: {
    fontSize: 30,
    margin: 20,
    fontWeight: 'bold',
  },
  groupHeader: {
    fontSize: 20,
    marginBottom: 10,
    fontWeight: '600',
  },
  group: {
    margin: 10,
    backgroundColor: '#fff',
    borderRadius: 10,
    padding: 15,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.2,
    shadowRadius: 1.41,
    elevation: 2,
  },
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  view: {
    flex: 1,
    height: 200,
  },
  input: {
    borderWidth: 1,
    borderColor: '#ccc',
    borderRadius: 5,
    padding: 10,
    marginBottom: 10,
  },
  credItem: {
    marginTop: 10,
    padding: 10,
    backgroundColor: '#f9f9f9',
    borderRadius: 5,
    borderWidth: 1,
    borderColor: '#eee',
  },
  credText: {
    fontSize: 12,
    fontFamily: 'monospace',
  },
});
