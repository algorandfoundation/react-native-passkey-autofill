import ReactNativePasskeyAutofill from '@algorandfoundation/react-native-passkey-autofill';
import { Button, SafeAreaView, ScrollView, Text, View, StyleSheet } from 'react-native';
import { useEffect, useState } from 'react';
import { Passkey } from 'react-native-passkey';
import { install } from 'react-native-quick-crypto';
import Hook from "before-after-hook";

import { ReactNativeProvider, WalletProvider } from './providers/ReactNativeProvider';
import { useProvider } from './hooks/useProvider';
import { keyStore } from './stores/keystore';
import { passkeysStore } from './stores/passkeys';
import {
  encodeAddress,
  toBase64URL,
  fromBase64Url,
  generateEd25519KeyPair
} from './utils/crypto';
import {bootstrap, fullReload} from "./bootstrap";

install();

const isSupported: boolean = Passkey.isSupported();

const provider = new ReactNativeProvider({
  id: 'passkey-autofill-example',
  name: 'Passkey AutoFill Example',
}, {
  keystore: {
    store: keyStore,
    hooks: new Hook.Collection()
  },
  passkeys: {
    store: passkeysStore,
    hooks: new Hook.Collection(),
    keystore: {
      autoPopulate: true,
    }
  }
});


bootstrap();

function AppContent() {
  const { keys, passkeys, status, passkey, key } = useProvider();
  const [account, setAccount] = useState<any>(null);
  const [xhdEd25519KeyId, setXhdEd25519KeyId] = useState<string | null>(null);
  const [activePasskeyId, setActivePasskeyId] = useState<string | null>(null);

  useEffect(() => {
    const ed25519 = keys.find(k => k.type === 'hd-derived-ed25519' || k.type === 'ed25519');
    setXhdEd25519KeyId(ed25519 ? ed25519.id : null);
    
    if (passkeys.length > 0 && !activePasskeyId) {
      setActivePasskeyId(passkeys[0].id);
    }
  }, [keys, passkeys]);

  useEffect(() => {
    if(!account) {
      generateEd25519KeyPair().then(setAccount)
    }
  }, [account]);

  const handleClearCredentials = async () => {
    try {
      await key.store.clear();
      await passkey.store.clear();
      await ReactNativePasskeyAutofill.clearCredentials();
      setXhdEd25519KeyId(null);
      setActivePasskeyId(null);
      alert('Passkeys and keys cleared');
    } catch (e) {
      alert('Failed to clear passkeys: ' + e);
    }
  };

  const handlePasskeyAction = async () => {
    if (passkeys.length > 0) {
      await handleGetPasskey();
    } else {
      await handleCreatePasskey();
    }
  };

  const handleGetPasskey = async () => {
    try {
      const credentialId = activePasskeyId || (passkeys.length > 0 ? passkeys[0].id : null);
      if (!credentialId) {
        alert('No passkey selected');
        return;
      }

      const urlSafeCredentialId = credentialId.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
      const response = await fetch(`https://fido.shore-tech.net/assertion/request/${urlSafeCredentialId}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          "userVerification": "required"
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to get assertion request: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const options = await response.json();
      console.log(options)
      const result = await Passkey.get(options);

      const submitResponse = await fetch('https://fido.shore-tech.net/assertion/response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
      });

      if (!submitResponse.ok) {
        const errorText = await submitResponse.text();
        throw new Error(`Failed to submit assertion response: ${submitResponse.status} ${submitResponse.statusText} - ${errorText}`);
      }

      const submitResult = await submitResponse.json();
      if (submitResult.error) throw new Error(submitResult.error);

      alert('Passkey used and verified successfully!');
    } catch (e) {
      console.error('Passkey get error:', e);
      alert('Failed to use passkey: ' + e);
    }
  };

  const handleCreatePasskey = async () => {
    try {
      if (!xhdEd25519KeyId) {
        alert('Key not ready');
        return;
      }
      const ed25519Key = keys.find(k => k.id === xhdEd25519KeyId);
      if(!ed25519Key) {
        alert('Key not found');
        return;
      }
      if(!ed25519Key.publicKey) {
        alert('Key does not have a public key');
        return;
      }
      if(typeof ed25519Key?.metadata?.parentKeyId !== 'string') {
        alert("Key does not have a parent key ID");
        return;
      }

      await ReactNativePasskeyAutofill.setHdRootKeyId(ed25519Key.metadata.parentKeyId)

      const response = await fetch('https://fido.shore-tech.net/attestation/request', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          "username": encodeAddress(new Uint8Array(ed25519Key.publicKey)),
          "displayName": "Liquid Auth User",
          "authenticatorSelection": { "userVerification": "required" },
          "extensions": { "liquid": true }
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to get attestation request: ${response.status} ${response.statusText} - ${errorText}`);
      }

      const options = await response.json();
      
      const result: any = await Passkey.create(options);

      // TODO: this should happen in the passkey extension
      await fullReload()

      if (ed25519Key && ed25519Key.publicKey) {
        const challenge = fromBase64Url(options.challenge);
        const signature = await key.store.sign(xhdEd25519KeyId, challenge);
        
        result.clientExtensionResults = {
          ...result.clientExtensionResults,
          liquid: {
            requestId: 'example-session-' + Date.now(),
            origin: 'fido.shore-tech.net',
            type: 'algorand',
            address: encodeAddress(new Uint8Array(ed25519Key.publicKey)),
            signature: toBase64URL(signature),
            device: 'Passkey AutoFill Example'
          }
        };
      }

      const submitResponse = await fetch('https://fido.shore-tech.net/attestation/response', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(result),
      });

      if (!submitResponse.ok) {
        const errorText = await submitResponse.text();
        throw new Error(`Failed to submit attestation response: ${submitResponse.status} ${submitResponse.statusText} - ${errorText}`);
      }

      const submitResult = await submitResponse.json();
      if (submitResult.error) throw new Error(submitResult.error);

      // Re-bootstrap to ensure the new passkey is available for autofill
      //await bootstrap();

      alert('Passkey created and submitted successfully!');
    } catch (e) {
      console.error('Passkey creation error:', e);
      alert('Failed to create passkey: ' + e);
    }
  };

  const handleCreateXHDEd25519Key = async () => {
    try {
      const seed = new Uint8Array(32).fill(0xAA);
      const seedId = await key.store.importSeed!(seed, { name: 'Main Seed' });
      
      const rootKeyId = await key.store.generate!({
        type: 'hd-root-key',
        algorithm: 'raw',
        extractable: true,
        keyUsages: ['deriveKey', 'deriveBits'],
        params: { parentKeyId: seedId }
      });

      const kId = await key.store.generate!({
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
      setXhdEd25519KeyId(kId);
      alert('XHD Ed25519 Key created: ' + kId);
    } catch (e: any) {
      alert('Error: ' + e.message);
    }
  };

  if(!isSupported) return (
      <View style={styles.view}>
        <Text>Passkeys are not supported on this device</Text>
      </View>
  )

  return (
    <SafeAreaView style={styles.container}>
      <ScrollView style={styles.container}>
        <Text style={styles.header}>Passkey AutoFill Example</Text>
        
        <Group name="Passkeys">
          <View style={{ gap: 10 }}>
            <Button title="Clear Passkeys" onPress={handleClearCredentials} color="red" />
          </View>
        </Group>

        <Group name="Functions">
          <View style={{ gap: 10 }}>
            {activePasskeyId && <Text style={styles.credText}>Active Passkey: {activePasskeyId}</Text>}
            {xhdEd25519KeyId && <Text style={styles.credText}>Active Ed25519: {xhdEd25519KeyId}</Text>}
            <Button
              title={passkeys.length > 0 ? "Use Passkey" : "Create Passkey"}
              onPress={handlePasskeyAction}
              disabled={!xhdEd25519KeyId}
            />
            <Button title="Create XHD Ed25519 Key" onPress={handleCreateXHDEd25519Key} color="blue" />
          </View>
        </Group>

        <Group name={`Keys in Store (${status})`}>
          {keys.length > 0 ? (
            keys.map((k, index) => (
              <View key={k.id || index} style={styles.credItem}>
                <Text style={styles.credText}>ID: {k.id}</Text>
                <Text style={styles.credText}>Type: {k.type}</Text>
                <Text style={styles.credText}>Algo: {k.algorithm}</Text>
                {k.keyUsages && (
                  <Text style={styles.credText}>Usages: {k.keyUsages.join(', ')}</Text>
                )}
              </View>
            ))
          ) : (
            <Text>No keys in store</Text>
          )}
        </Group>

        <Group name={`Passkeys (${passkeys.length})`}>
          {passkeys.length > 0 ? (
            passkeys.map((p, index) => (
              <View key={p.id || index} style={styles.credItem}>
                <Text style={styles.credText}>Name: {p.name}</Text>
                <Text style={styles.credText}>ID: {p.id}</Text>
                {p.metadata?.origin && (
                  <Text style={styles.credText}>Origin: {p.metadata.origin}</Text>
                )}
              </View>
            ))
          ) : (
            <Text>No passkeys</Text>
          )}
        </Group>
      </ScrollView>
    </SafeAreaView>
  );
}

export default function App() {
  useEffect(() => {
    return () => {
      ReactNativePasskeyAutofill.clearCredentials().catch(console.error);
    };
  }, []);

  return (
    <WalletProvider provider={provider}>
      <AppContent />
    </WalletProvider>
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
  header: { fontSize: 30, margin: 20, fontWeight: 'bold' },
  groupHeader: { fontSize: 20, marginBottom: 10, fontWeight: '600' },
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
  container: { flex: 1, backgroundColor: '#f5f5f5' },
  view: { flex: 1, height: 200, justifyContent: 'center', alignItems: 'center' },
  credItem: {
    marginTop: 10,
    padding: 10,
    backgroundColor: '#f9f9f9',
    borderRadius: 5,
    borderWidth: 1,
    borderColor: '#eee',
  },
  credText: { fontSize: 12, fontFamily: 'monospace' },
});
