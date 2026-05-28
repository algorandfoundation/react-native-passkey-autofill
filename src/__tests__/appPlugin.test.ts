// app.plugin.js is plain CommonJS at the repo root.
const plugin = require("../../app.plugin.js");

describe("getBiometricRequirement", () => {
  it("defaults to strongOrCredential when unset", () => {
    expect(plugin.getBiometricRequirement({})).toBe("strongOrCredential");
  });

  it("returns each valid value unchanged", () => {
    expect(plugin.getBiometricRequirement({ biometricRequirement: "strong" })).toBe("strong");
    expect(plugin.getBiometricRequirement({ biometricRequirement: "strongOrCredential" })).toBe(
      "strongOrCredential",
    );
    expect(plugin.getBiometricRequirement({ biometricRequirement: "weakOrCredential" })).toBe(
      "weakOrCredential",
    );
  });

  it("trims whitespace", () => {
    expect(plugin.getBiometricRequirement({ biometricRequirement: "  strong  " })).toBe("strong");
  });

  it("throws on an unknown value", () => {
    expect(() => plugin.getBiometricRequirement({ biometricRequirement: "fingerprintOnly" })).toThrow(
      /biometricRequirement/,
    );
  });
});

describe("getAaguid", () => {
  it("returns null when unset", () => {
    expect(plugin.getAaguid({})).toBeNull();
    expect(plugin.getAaguid({ aaguid: undefined })).toBeNull();
  });

  it("returns a valid UUID unchanged", () => {
    expect(plugin.getAaguid({ aaguid: "1f59713a-c021-4e63-9158-2cc5fdc14e52" })).toBe(
      "1f59713a-c021-4e63-9158-2cc5fdc14e52",
    );
  });

  it("trims surrounding whitespace", () => {
    expect(plugin.getAaguid({ aaguid: "  1f59713a-c021-4e63-9158-2cc5fdc14e52  " })).toBe(
      "1f59713a-c021-4e63-9158-2cc5fdc14e52",
    );
  });

  it("accepts uppercase hex", () => {
    expect(plugin.getAaguid({ aaguid: "1F59713A-C021-4E63-9158-2CC5FDC14E52" })).toBe(
      "1F59713A-C021-4E63-9158-2CC5FDC14E52",
    );
  });

  it("throws on a non-UUID value", () => {
    expect(() => plugin.getAaguid({ aaguid: "not-a-uuid" })).toThrow(/aaguid/);
  });

  it("throws on a UUID with a malformed segment", () => {
    expect(() => plugin.getAaguid({ aaguid: "1f59713a-c021-4e63-9158-2cc5fdc14e5" })).toThrow(
      /aaguid/,
    );
  });
});
