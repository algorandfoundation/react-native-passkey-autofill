const mockModule: Record<string, jest.Mock> = {
  setMasterKey: jest.fn(),
  setMainKeyId: jest.fn(),
  getMainKeyId: jest.fn(),
  setHdRootKeyId: jest.fn(),
  getHdRootKeyId: jest.fn(),
  configureIntentActions: jest.fn(),
  clearCredentials: jest.fn(),
  // Intentionally omit `replaceCredentialIdentities`, `refreshCredentialIdentities`,
  // `getStoredCredentials`, and `getDiagnostics` to mirror the real Android
  // native module surface and exercise the JS no-op fallbacks.
  isProviderActive: jest.fn(),
  openProviderSettings: jest.fn(),
};

jest.mock("expo", () => ({
  requireNativeModule: () => mockModule,
  NativeModule: class {},
}));

jest.mock("react-native", () => ({ Platform: { OS: "android" } }));

import { requireNativeModule } from "expo";
import ReactNativePasskeyAutofill from "../index";

describe("ReactNativePasskeyAutofill", () => {
  it("should be defined", () => {
    expect(ReactNativePasskeyAutofill).toBeDefined();
  });

  it("should call setMasterKey", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    const secret = new Uint8Array([1, 2, 3]);
    await ReactNativePasskeyAutofill.setMasterKey(secret);
    expect(mockModule.setMasterKey).toHaveBeenCalledWith(secret);
  });

  it("should call setMainKeyId", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    await ReactNativePasskeyAutofill.setMainKeyId("test-id");
    expect(mockModule.setMainKeyId).toHaveBeenCalledWith("test-id");
  });

  it("should call getMainKeyId", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    mockModule.getMainKeyId.mockResolvedValue("test-id");
    const result = await ReactNativePasskeyAutofill.getMainKeyId();
    expect(result).toBe("test-id");
    expect(mockModule.getMainKeyId).toHaveBeenCalled();
  });

  it("should call setHdRootKeyId (deprecated)", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    await ReactNativePasskeyAutofill.setHdRootKeyId("test-id");
    expect(mockModule.setHdRootKeyId).toHaveBeenCalledWith("test-id");
  });

  it("should call getHdRootKeyId (deprecated)", async () => {
    const mockModule = requireNativeModule("ReactNativePasskeyAutofill");
    mockModule.getHdRootKeyId.mockResolvedValue("test-id");
    const result = await ReactNativePasskeyAutofill.getHdRootKeyId();
    expect(result).toBe("test-id");
    expect(mockModule.getHdRootKeyId).toHaveBeenCalled();
  });

  it("provides a no-op fallback on Android for iOS-only methods", async () => {
    // The Android native module does not implement these methods; the JS
    // wrapper must return resolved promises instead of throwing
    // `TypeError: ... is not a function`.
    await expect(ReactNativePasskeyAutofill.refreshCredentialIdentities()).resolves.toBeUndefined();
    await expect(ReactNativePasskeyAutofill.getStoredCredentials()).resolves.toEqual([]);
    await expect(ReactNativePasskeyAutofill.getDiagnostics()).resolves.toEqual([]);
    await expect(
      ReactNativePasskeyAutofill.replaceCredentialIdentities([]),
    ).resolves.toBeUndefined();
  });
});
