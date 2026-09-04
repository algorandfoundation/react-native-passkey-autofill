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
    expect(() =>
      plugin.getBiometricRequirement({ biometricRequirement: "fingerprintOnly" }),
    ).toThrow(/biometricRequirement/);
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

describe("getDeterministicP256Revision", () => {
  const sha = "4fe03ee04894cb3dcf706b9e70a39588c1cec1c9";

  it("defaults to the pinned commit", () => {
    expect(plugin.getDeterministicP256Revision({})).toBe(
      plugin.DETERMINISTIC_P256_PACKAGE_REVISION,
    );
    expect(plugin.DETERMINISTIC_P256_PACKAGE_REVISION).toMatch(/^[0-9a-f]{40}$/);
  });

  it("accepts a full commit SHA override and normalises its case", () => {
    expect(plugin.getDeterministicP256Revision({ deterministicP256PackageRevision: sha })).toBe(
      sha,
    );
    expect(
      plugin.getDeterministicP256Revision({
        deterministicP256PackageRevision: ` ${sha.toUpperCase()} `,
      }),
    ).toBe(sha);
  });

  it("rejects anything that is not a 40-character SHA", () => {
    for (const value of ["main", "v1.0.0", sha.slice(0, 7), `${sha}0`, ""]) {
      expect(() =>
        plugin.getDeterministicP256Revision({ deterministicP256PackageRevision: value }),
      ).toThrow(/deterministicP256PackageRevision/);
    }
  });

  it("refuses the removed branch prop instead of silently tracking a branch", () => {
    expect(() =>
      plugin.getDeterministicP256Revision({ deterministicP256PackageBranch: "main" }),
    ).toThrow(/mutable reference/);
  });
});

describe("addSwiftPackageProduct", () => {
  const repositoryURL = "https://github.com/algorandfoundation/deterministic-P256-swift/";
  const revision = "4fe03ee04894cb3dcf706b9e70a39588c1cec1c9";

  // The minimal slice of an xcode `project` the helper touches.
  const fakeProject = (existingPackage?: Record<string, unknown>) => {
    let counter = 0;
    const objects: Record<string, Record<string, unknown>> = {
      XCRemoteSwiftPackageReference: existingPackage
        ? { EXISTING: existingPackage, EXISTING_comment: 'XCRemoteSwiftPackageReference "x"' }
        : {},
      PBXNativeTarget: { TARGET: { name: "Ext", buildPhases: [] } },
    };
    const firstProject: Record<string, unknown> = {};
    return {
      hash: { project: { objects } },
      generateUuid: () => `UUID${++counter}`,
      getFirstProject: () => ({ firstProject }),
      pbxNativeTargetSection: () => objects.PBXNativeTarget,
      objects,
    };
  };

  it("writes a revision requirement, never a branch", () => {
    const project = fakeProject();
    plugin.addSwiftPackageProduct(project, {
      targetUuid: "TARGET",
      packageName: "deterministic-P256-swift",
      productName: "deterministicP256-swift",
      repositoryURL,
      revision,
    });
    const references = Object.entries(project.objects.XCRemoteSwiftPackageReference).filter(
      ([key]) => !key.endsWith("_comment"),
    );
    expect(references).toHaveLength(1);
    expect((references[0][1] as { requirement: unknown }).requirement).toEqual({
      kind: "revision",
      revision,
    });
  });

  it("replaces a branch requirement left by an earlier prebuild", () => {
    const project = fakeProject({
      isa: "XCRemoteSwiftPackageReference",
      repositoryURL: `"${repositoryURL}"`,
      requirement: { kind: "branch", branch: "main" },
    });
    plugin.addSwiftPackageProduct(project, {
      targetUuid: "TARGET",
      packageName: "deterministic-P256-swift",
      productName: "deterministicP256-swift",
      repositoryURL,
      revision,
    });
    expect(
      (project.objects.XCRemoteSwiftPackageReference.EXISTING as { requirement: unknown })
        .requirement,
    ).toEqual({
      kind: "revision",
      revision,
    });
    expect(
      Object.keys(project.objects.XCRemoteSwiftPackageReference).filter(
        (k) => !k.endsWith("_comment"),
      ),
    ).toEqual(["EXISTING"]);
  });
});
