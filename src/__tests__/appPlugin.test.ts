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
