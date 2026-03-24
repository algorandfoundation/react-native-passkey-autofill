const mockModule = {
  setMasterKey: jest.fn(),
  setHdRootKeyId: jest.fn(),
  getHdRootKeyId: jest.fn(),
  configureIntentActions: jest.fn(),
  clearCredentials: jest.fn(),
};

jest.mock('expo', () => ({
  requireNativeModule: () => mockModule,
  NativeModule: class {},
}));

import { requireNativeModule } from 'expo';
import ReactNativePasskeyAutofill from '../index';

describe('ReactNativePasskeyAutofill', () => {
  it('should be defined', () => {
    expect(ReactNativePasskeyAutofill).toBeDefined();
  });

  it('should call setMasterKey', async () => {
    const mockModule = requireNativeModule('ReactNativePasskeyAutofill');
    await ReactNativePasskeyAutofill.setMasterKey('secret');
    expect(mockModule.setMasterKey).toHaveBeenCalledWith('secret');
  });
});
