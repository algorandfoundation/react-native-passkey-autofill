import React from 'react';
import renderer from 'react-test-renderer';
import App from '../App';

// Mock the native module
jest.mock('@algorandfoundation/react-native-passkey-autofill', () => ({
  setMasterKey: jest.fn(),
  setHdRootKeyId: jest.fn(),
  getHdRootKeyId: jest.fn(),
  configureIntentActions: jest.fn(),
  clearCredentials: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('@algorandfoundation/react-native-keystore', () => ({
  WithKeyStore: (Base: any) => Base,
}), { virtual: true });

jest.mock('@algorandfoundation/wallet-provider', () => ({
  Provider: class {
    static EXTENSIONS = [];
  },
}), { virtual: true });

jest.mock('../extensions/passkeys', () => ({
  WithPasskeyStore: (Base: any) => Base,
}));

jest.mock('../extensions/passkeys-keystore', () => ({
  WithPasskeysKeystore: (Base: any) => Base,
}));

// Mock other native modules if necessary
jest.mock('react-native-passkey', () => ({
  Passkey: {
    isSupported: jest.fn(() => true),
    create: jest.fn(),
    get: jest.fn(),
  },
}));

jest.mock('react-native-quick-crypto', () => ({
  install: jest.fn(),
}));

// Mocking fetch for the tests
global.fetch = jest.fn(() =>
  Promise.resolve({
    ok: true,
    json: () => Promise.resolve({}),
  })
) as jest.Mock;

describe('<App />', () => {
  it('renders correctly', () => {
    const tree = renderer.create(<App />).toJSON();
    expect(tree).toBeDefined();
  });
});
