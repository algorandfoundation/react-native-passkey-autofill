const {
  withAndroidManifest,
  withEntitlementsPlist,
  withInfoPlist,
  withStringsXml,
  withProjectBuildGradle,
  withMainApplication,
  withDangerousMod,
  withXcodeProject,
  AndroidConfig,
} = require("@expo/config-plugins");
const path = require("path");
const fs = require("fs");

const IOS_EXTENSION_NAME = "PasskeyAutofillCredentialProvider";
const IOS_EXTENSION_FILES = [
  "CredentialProviderViewController.swift",
  "PasskeyKeystoreMMKV.h",
  "PasskeyKeystoreMMKV.mm",
  "PasskeyAutofillCredentialProvider-Bridging-Header.h",
  "PasskeyCredentialStore.swift",
  "WebAuthn.swift",
  "BiometricRequirement.swift",
];
const IOS_EXTENSION_SOURCE_FILES = IOS_EXTENSION_FILES.filter((file) => !file.endsWith(".h"));
const DETERMINISTIC_P256_PACKAGE_URL =
  "https://github.com/algorandfoundation/deterministic-P256-swift/";
const DETERMINISTIC_P256_PRODUCT_NAME = "deterministicP256-swift";

const getAssociatedDomain = (site) => {
  try {
    return new URL(site).host;
  } catch {
    return site.replace(/^https?:\/\//, "").split("/")[0];
  }
};

const getIosBundleIdentifier = (config) =>
  config.ios?.bundleIdentifier ||
  config.ios?.bundleIdentifierOverride ||
  "co.algorand.auth.example";

const getAppGroup = (config, props) =>
  props.appGroup || `group.${getIosBundleIdentifier(config)}.passkey-autofill`;

const AAGUID_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

// Optional authenticator AAGUID. When set, both platforms embed it in attestation
// responses so the credential provider presents a consistent identity to relying parties.
const getAaguid = (props) => {
  if (!props.aaguid) {
    return null;
  }
  const value = String(props.aaguid).trim();
  if (!AAGUID_REGEX.test(value)) {
    throw new Error(
      `react-native-passkey-autofill: "aaguid" must be a UUID string, received "${props.aaguid}".`,
    );
  }
  return value;
};

const BIOMETRIC_REQUIREMENT_VALUES = ["strong", "strongOrCredential", "weakOrCredential"];
const DEFAULT_BIOMETRIC_REQUIREMENT = "strongOrCredential";
// Must match `META_DATA_KEY` in android/.../auth/BiometricRequirement.kt.
const ANDROID_BIOMETRIC_META_DATA_NAME = "co.algorand.passkeyautofill.BIOMETRIC_REQUIREMENT";
// Must match `infoDictionaryKey` in ios/AutofillCredentialProvider/BiometricRequirement.swift.
const IOS_BIOMETRIC_INFO_PLIST_KEY = "ReactNativePasskeyAutofillBiometricRequirement";

// Authenticators a passkey operation will accept. Default is intentionally more permissive than
// strong-only: it leaves iOS unchanged (passcode still allowed) and lets Android accept the device
// credential. See docs/superpowers/specs/2026-05-28-configurable-biometric-requirement-design.md.
const getBiometricRequirement = (props) => {
  if (props.biometricRequirement == null) {
    return DEFAULT_BIOMETRIC_REQUIREMENT;
  }
  const value = String(props.biometricRequirement).trim();
  if (!BIOMETRIC_REQUIREMENT_VALUES.includes(value)) {
    throw new Error(
      `react-native-passkey-autofill: "biometricRequirement" must be one of ${BIOMETRIC_REQUIREMENT_VALUES.join(
        ", ",
      )}, received "${props.biometricRequirement}".`,
    );
  }
  return value;
};

const normalizeXcodeName = (name) => String(name || "").replace(/^"|"$/g, "");

const getExtensionTarget = (project) => {
  const targets = project.pbxNativeTargetSection();
  const targetUuid = Object.keys(targets).find((uuid) => {
    const target = targets[uuid];
    return (
      target?.isa === "PBXNativeTarget" &&
      target.productType === '"com.apple.product-type.app-extension"' &&
      normalizeXcodeName(target.name) === IOS_EXTENSION_NAME
    );
  });

  return targetUuid ? { uuid: targetUuid, pbxNativeTarget: targets[targetUuid] } : null;
};

const getDevelopmentTeam = (project) => {
  const buildConfigs = project.pbxXCBuildConfigurationSection();
  const config = Object.keys(buildConfigs)
    .filter((key) => !key.endsWith("_comment"))
    .map((key) => buildConfigs[key])
    .find((entry) => {
      const team = entry?.buildSettings?.DEVELOPMENT_TEAM;
      return team && team !== '"$(DEVELOPMENT_TEAM)"' && team !== "$(DEVELOPMENT_TEAM)";
    });

  return config?.buildSettings?.DEVELOPMENT_TEAM;
};

const writePlist = (filePath, body) => {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, body);
};

const extensionInfoPlist = ({ label, supportedDomains, aaguid, biometricRequirement }) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key>
  <string>${label}</string>
  <key>CFBundleExecutable</key>
  <string>$(EXECUTABLE_NAME)</string>
  <key>CFBundleIdentifier</key>
  <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
  <key>CFBundleName</key>
  <string>$(PRODUCT_NAME)</string>
  <key>CFBundlePackageType</key>
  <string>XPC!</string>
  <key>CFBundleShortVersionString</key>
  <string>$(MARKETING_VERSION)</string>
  <key>CFBundleVersion</key>
  <string>$(CURRENT_PROJECT_VERSION)</string>
  <key>ReactNativePasskeyAutofillAppGroup</key>
  <string>$(PASSKEY_AUTOFILL_APP_GROUP)</string>
  <key>AppGroupIdentifier</key>
  <string>$(PASSKEY_AUTOFILL_APP_GROUP)</string>
${aaguid ? `  <key>ReactNativePasskeyAutofillAAGUID</key>\n  <string>${aaguid}</string>\n` : ""}  <key>${IOS_BIOMETRIC_INFO_PLIST_KEY}</key>
  <string>${biometricRequirement}</string>
  <key>NSFaceIDUsageDescription</key>
  <string>Rocca uses Face ID to create and use passkeys.</string>
  <key>NSExtension</key>
  <dict>
    <key>ASCredentialProviderExtensionSupportedDomains</key>
    <array>
${supportedDomains.map((domain) => `      <string>${domain}</string>`).join("\n")}
    </array>
    <key>CFBundleDisplayName</key>
    <string>${label}</string>
    <key>NSExtensionAttributes</key>
    <dict>
      <key>ASCredentialProviderExtensionCapabilities</key>
      <dict>
        <key>ProvidesOneTimeCodes</key>
        <false/>
        <key>ProvidesPasskeys</key>
        <true/>
        <key>ProvidesPasswords</key>
        <false/>
        <key>ProvidesTextToInsert</key>
        <false/>
        <key>ShowsConfigurationUI</key>
        <false/>
      </dict>
    </dict>
    <key>NSExtensionPointIdentifier</key>
    <string>com.apple.authentication-services-credential-provider-ui</string>
    <key>NSExtensionPrincipalClass</key>
    <string>$(PRODUCT_MODULE_NAME).CredentialProviderViewController</string>
  </dict>
</dict>
</plist>
`;

const extensionEntitlementsPlist = ({ appGroup }) => `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.developer.authentication-services.autofill-credential-provider</key>
  <true/>
  <key>com.apple.security.application-groups</key>
  <array>
    <string>${appGroup}</string>
  </array>
</dict>
</plist>
`;

const withIosPasskeyAutofill = (config, props = {}) => {
  const site = props.site || "https://debug.liquidauth.com";
  const label = props.label || "My Credential Provider";
  const associatedDomain = getAssociatedDomain(site);
  const supportedDomains = props.supportedDomains || [associatedDomain];
  const appGroup = getAppGroup(config, props);
  const aaguid = getAaguid(props);
  const biometricRequirement = getBiometricRequirement(props);

  config = withInfoPlist(config, (config) => {
    config.modResults.ReactNativePasskeyAutofillAppGroup = appGroup;
    config.modResults.AppGroupIdentifier = appGroup;
    return config;
  });

  config = withEntitlementsPlist(config, (config) => {
    const domains = new Set(config.modResults["com.apple.developer.associated-domains"] || []);
    domains.add(`webcredentials:${associatedDomain}`);
    config.modResults["com.apple.developer.associated-domains"] = [...domains];
    config.modResults["com.apple.developer.authentication-services.autofill-credential-provider"] =
      true;

    const appGroups = new Set(config.modResults["com.apple.security.application-groups"] || []);
    appGroups.add(appGroup);
    config.modResults["com.apple.security.application-groups"] = [...appGroups];
    return config;
  });

  config = withDangerousMod(config, [
    "ios",
    async (config) => {
      const iosRoot = config.modRequest.platformProjectRoot;
      const extensionRoot = path.join(iosRoot, IOS_EXTENSION_NAME);
      const sourceRoot = path.join(__dirname, "ios/AutofillCredentialProvider");

      fs.mkdirSync(extensionRoot, { recursive: true });
      for (const file of IOS_EXTENSION_FILES) {
        fs.copyFileSync(path.join(sourceRoot, file), path.join(extensionRoot, file));
      }

      writePlist(
        path.join(extensionRoot, `${IOS_EXTENSION_NAME}-Info.plist`),
        extensionInfoPlist({ label, supportedDomains, aaguid, biometricRequirement }),
      );
      writePlist(
        path.join(extensionRoot, `${IOS_EXTENSION_NAME}.entitlements`),
        extensionEntitlementsPlist({ appGroup }),
      );
      return config;
    },
  ]);

  config = withXcodeProject(config, (config) => {
    const project = config.modResults;
    const bundleIdentifier = `${getIosBundleIdentifier(config)}.PasskeyAutofillCredentialProvider`;
    const buildNumber = config.ios?.buildNumber || config.versionCode || "1";
    const developmentTeam =
      props.developmentTeam ||
      props.appleTeamId ||
      getDevelopmentTeam(project) ||
      "$(DEVELOPMENT_TEAM)";
    let target =
      getExtensionTarget(project) ||
      project.addTarget(IOS_EXTENSION_NAME, "app_extension", IOS_EXTENSION_NAME, bundleIdentifier);

    if (target?.uuid) {
      ensureSourceFilesInTarget(
        project,
        target.uuid,
        IOS_EXTENSION_SOURCE_FILES.map((file) => `${IOS_EXTENSION_NAME}/${file}`),
      );
      if (!hasBuildPhase(project, target.uuid, "PBXFrameworksBuildPhase")) {
        project.addBuildPhase(
          ["AuthenticationServices.framework", "CryptoKit.framework"],
          "PBXFrameworksBuildPhase",
          "Frameworks",
          target.uuid,
        );
      }
      addSwiftPackageProduct(project, {
        targetUuid: target.uuid,
        packageName: "deterministic-P256-swift",
        productName: DETERMINISTIC_P256_PRODUCT_NAME,
        repositoryURL: props.deterministicP256PackageURL || DETERMINISTIC_P256_PACKAGE_URL,
        branch: props.deterministicP256PackageBranch || "main",
      });
      setExtensionBuildSettings(project, target.uuid, {
        ASSETCATALOG_COMPILER_GLOBAL_ACCENT_COLOR_NAME: '"AccentColor"',
        APPLICATION_EXTENSION_API_ONLY: "YES",
        CODE_SIGN_ENTITLEMENTS: `"${IOS_EXTENSION_NAME}/${IOS_EXTENSION_NAME}.entitlements"`,
        CURRENT_PROJECT_VERSION: `"${buildNumber}"`,
        DEVELOPMENT_TEAM: developmentTeam,
        IPHONEOS_DEPLOYMENT_TARGET: "17.0",
        MARKETING_VERSION: `"${config.version || "1.0.0"}"`,
        PASSKEY_AUTOFILL_APP_GROUP: `"${appGroup}"`,
        PRODUCT_BUNDLE_IDENTIFIER: `"${bundleIdentifier}"`,
        SWIFT_ACTIVE_COMPILATION_CONDITIONS: "PASSKEY_AUTOFILL_EXTENSION",
        HEADER_SEARCH_PATHS: [
          '"$(inherited)"',
          '"$(SRCROOT)/Pods/Headers/Public"',
          '"$(SRCROOT)/Pods/Headers/Public/MMKVCore"',
        ],
        LIBRARY_SEARCH_PATHS: [
          '"$(inherited)"',
          '"$(BUILD_DIR)/$(CONFIGURATION)$(EFFECTIVE_PLATFORM_NAME)/MMKVCore"',
        ],
        OTHER_LDFLAGS: ['"$(inherited)"', '"-lMMKVCore"', '"-lc++"', '"-lz"'],
        SWIFT_OBJC_BRIDGING_HEADER: `"${IOS_EXTENSION_NAME}/PasskeyAutofillCredentialProvider-Bridging-Header.h"`,
        SWIFT_VERSION: "5.9",
      });
    }

    return config;
  });

  return config;
};

const addSwiftPackageProduct = (
  project,
  { targetUuid, packageName, productName, repositoryURL, branch },
) => {
  const objects = project.hash.project.objects;
  objects.XCRemoteSwiftPackageReference = objects.XCRemoteSwiftPackageReference || {};
  objects.XCSwiftPackageProductDependency = objects.XCSwiftPackageProductDependency || {};
  objects.PBXBuildFile = objects.PBXBuildFile || {};

  const packageComment = `XCRemoteSwiftPackageReference "${packageName}"`;
  let packageUuid = Object.keys(objects.XCRemoteSwiftPackageReference).find(
    (key) =>
      !key.endsWith("_comment") &&
      objects.XCRemoteSwiftPackageReference[key].repositoryURL === `"${repositoryURL}"`,
  );
  if (!packageUuid) {
    packageUuid = project.generateUuid();
    objects.XCRemoteSwiftPackageReference[packageUuid] = {
      isa: "XCRemoteSwiftPackageReference",
      repositoryURL: `"${repositoryURL}"`,
      requirement: {
        branch,
        kind: "branch",
      },
    };
    objects.XCRemoteSwiftPackageReference[`${packageUuid}_comment`] = packageComment;
  }

  const firstProject = project.getFirstProject().firstProject;
  firstProject.packageReferences = firstProject.packageReferences || [];
  if (!firstProject.packageReferences.some((reference) => reference.value === packageUuid)) {
    firstProject.packageReferences.push({ value: packageUuid, comment: packageComment });
  }

  let productUuid = Object.keys(objects.XCSwiftPackageProductDependency).find(
    (key) =>
      !key.endsWith("_comment") &&
      objects.XCSwiftPackageProductDependency[key].package === packageUuid &&
      objects.XCSwiftPackageProductDependency[key].productName === `"${productName}"`,
  );
  if (!productUuid) {
    productUuid = project.generateUuid();
    objects.XCSwiftPackageProductDependency[productUuid] = {
      isa: "XCSwiftPackageProductDependency",
      package: packageUuid,
      productName: `"${productName}"`,
    };
    objects.XCSwiftPackageProductDependency[`${productUuid}_comment`] = productName;
  }

  const target = project.pbxNativeTargetSection()[targetUuid];
  target.packageProductDependencies = target.packageProductDependencies || [];
  if (!target.packageProductDependencies.some((dependency) => dependency.value === productUuid)) {
    target.packageProductDependencies.push({ value: productUuid, comment: productName });
  }

  const frameworksPhase = target.buildPhases
    .map((phase) => ({ phase, value: objects.PBXFrameworksBuildPhase?.[phase.value] }))
    .find(({ value }) => value)?.value;
  if (!frameworksPhase) {
    return;
  }
  const alreadyLinked = frameworksPhase.files.some(
    (file) => file.comment === `${productName} in Frameworks`,
  );
  if (!alreadyLinked) {
    const buildFileUuid = project.generateUuid();
    objects.PBXBuildFile[buildFileUuid] = {
      isa: "PBXBuildFile",
      productRef: productUuid,
      productRef_comment: productName,
    };
    objects.PBXBuildFile[`${buildFileUuid}_comment`] = `${productName} in Frameworks`;
    frameworksPhase.files.push({
      value: buildFileUuid,
      comment: `${productName} in Frameworks`,
    });
  }
};

const hasBuildPhase = (project, targetUuid, phaseType) => {
  const target = project.pbxNativeTargetSection()[targetUuid];
  return target.buildPhases.some((phase) => project.hash.project.objects[phaseType]?.[phase.value]);
};

const getBuildPhase = (project, targetUuid, phaseType) => {
  const target = project.pbxNativeTargetSection()[targetUuid];
  const phases = project.hash.project.objects[phaseType] || {};
  const phaseRef = target.buildPhases.find((phase) => phases[phase.value]);
  return phaseRef ? phases[phaseRef.value] : null;
};

const getFileType = (filePath) => {
  if (filePath.endsWith(".swift")) return "sourcecode.swift";
  if (filePath.endsWith(".mm")) return "sourcecode.cpp.objcpp";
  if (filePath.endsWith(".m")) return "sourcecode.c.objc";
  if (filePath.endsWith(".h")) return "sourcecode.c.h";
  return "text";
};

const getOrCreateFileReference = (project, filePath) => {
  const fileReferences = project.pbxFileReferenceSection();
  const existingUuid = Object.keys(fileReferences).find((uuid) => {
    if (uuid.endsWith("_comment")) return false;
    const refPath = fileReferences[uuid]?.path;
    return refPath === filePath || refPath === `"${filePath}"`;
  });
  if (existingUuid) {
    return existingUuid;
  }

  const uuid = project.generateUuid();
  const basename = path.basename(filePath);
  fileReferences[uuid] = {
    isa: "PBXFileReference",
    fileEncoding: 4,
    lastKnownFileType: getFileType(filePath),
    name: basename,
    path: filePath,
    sourceTree: '"<group>"',
  };
  fileReferences[`${uuid}_comment`] = basename;
  return uuid;
};

const getOrCreateBuildFile = (project, fileRefUuid, basename) => {
  const buildFiles = project.pbxBuildFileSection();
  const existingUuid = Object.keys(buildFiles).find((uuid) => {
    if (uuid.endsWith("_comment")) return false;
    return buildFiles[uuid]?.fileRef === fileRefUuid;
  });
  if (existingUuid) {
    return existingUuid;
  }

  const uuid = project.generateUuid();
  buildFiles[uuid] = {
    isa: "PBXBuildFile",
    fileRef: fileRefUuid,
    fileRef_comment: basename,
  };
  buildFiles[`${uuid}_comment`] = `${basename} in Sources`;
  return uuid;
};

const ensureSourceFilesInTarget = (project, targetUuid, files) => {
  const sourcesPhase = getBuildPhase(project, targetUuid, "PBXSourcesBuildPhase");
  if (!sourcesPhase) {
    project.addBuildPhase(files, "PBXSourcesBuildPhase", "Sources", targetUuid);
    return;
  }

  for (const filePath of files) {
    const basename = path.basename(filePath);
    const alreadyInSources = sourcesPhase.files.some(
      (file) => file.comment === `${basename} in Sources`,
    );
    if (alreadyInSources) {
      continue;
    }

    const fileRefUuid = getOrCreateFileReference(project, filePath);
    const buildFileUuid = getOrCreateBuildFile(project, fileRefUuid, basename);
    sourcesPhase.files.push({
      value: buildFileUuid,
      comment: `${basename} in Sources`,
    });
  }
};

const setExtensionBuildSettings = (project, targetUuid, settings) => {
  const target = project.pbxNativeTargetSection()[targetUuid];
  const configurationList = project.pbxXCConfigurationList()[target.buildConfigurationList];
  for (const config of configurationList.buildConfigurations) {
    const buildConfig = project.pbxXCBuildConfigurationSection()[config.value];
    buildConfig.buildSettings = {
      ...buildConfig.buildSettings,
      ...settings,
    };
  }
};

const withAndroidCookieModule = (config) => {
  return withDangerousMod(config, [
    "android",
    async (config) => {
      const projectRoot = config.modRequest.projectRoot;
      const packageId = config.android?.package || "co.algorand.auth.example";
      const packagePath = packageId.replace(/\./g, "/");
      const targetDir = path.join(projectRoot, "android/app/src/main/java", packagePath);

      // Ensure the directory exists
      fs.mkdirSync(targetDir, { recursive: true });

      const cookieModuleContent = `package ${packageId}

import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.Promise
import android.webkit.CookieManager

class CookieModule(reactContext: ReactApplicationContext) : ReactContextBaseJavaModule(reactContext) {
    override fun getName(): String {
        return "CookieModule"
    }

    @ReactMethod
    fun getCookie(url: String, promise: Promise) {
        try {
            val cookieManager = CookieManager.getInstance()
            val cookie = cookieManager.getCookie(url)
            promise.resolve(cookie)
        } catch (e: Exception) {
            promise.reject("E_COOKIE_MANAGER", e.message)
        }
    }

    @ReactMethod
    fun setCookie(url: String, cookie: String, promise: Promise) {
        try {
            val cookieManager = CookieManager.getInstance()
            cookieManager.setCookie(url, cookie)
            promise.resolve(null)
        } catch (e: Exception) {
            promise.reject("E_COOKIE_MANAGER", e.message)
        }
    }
}
`;

      const cookiePackageContent = `package ${packageId}

import com.facebook.react.ReactPackage
import com.facebook.react.bridge.NativeModule
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.uimanager.ViewManager

class CookiePackage : ReactPackage {
    override fun createNativeModules(reactContext: ReactApplicationContext): List<NativeModule> {
        return listOf(CookieModule(reactContext))
    }

    override fun createViewManagers(reactContext: ReactApplicationContext): List<ViewManager<*, *>> {
        return emptyList()
    }
}
`;

      fs.writeFileSync(path.join(targetDir, "CookieModule.kt"), cookieModuleContent);
      fs.writeFileSync(path.join(targetDir, "CookiePackage.kt"), cookiePackageContent);

      return config;
    },
  ]);
};

const withUserAgent = (config) => {
  return withMainApplication(config, (config) => {
    let content = config.modResults.contents;

    // Add imports
    const imports = [
      "import android.webkit.CookieManager",
      "import com.facebook.react.modules.network.OkHttpClientProvider",
      "import com.facebook.react.modules.network.ForwardingCookieHandler",
      "import com.facebook.react.modules.network.ReactCookieJarContainer",
      "import okhttp3.Interceptor",
      "import okhttp3.JavaNetCookieJar",
      "import java.net.CookieHandler",
      "import android.os.Build",
    ];

    imports.forEach((imp) => {
      if (!content.includes(imp)) {
        content = content.replace(/package .*\n/, (match) => `${match}${imp}\n`);
      }
    });

    // Add OkHttpClient customization in onCreate
    const okHttpClientCode = `
    CookieManager.getInstance().setAcceptCookie(true)
    CookieManager.setAcceptFileSchemeCookies(true)

    OkHttpClientProvider.setOkHttpClientFactory {
      val userAgent = "\${BuildConfig.APPLICATION_ID}/\${BuildConfig.VERSION_NAME} " +
          "(Android \${Build.VERSION.RELEASE}; \${Build.MODEL}; \${Build.BRAND})"

      val cookieHandler = ForwardingCookieHandler()
      CookieHandler.setDefault(cookieHandler)

      val cookieJarContainer = ReactCookieJarContainer()
      cookieJarContainer.setCookieJar(JavaNetCookieJar(cookieHandler))

      OkHttpClientProvider.createClientBuilder()
        .cookieJar(cookieJarContainer)
        .addInterceptor(Interceptor { chain ->
          val request = chain.request().newBuilder().header("User-Agent", userAgent).build()
          chain.proceed(request)
        })
        .build()
    }
`;

    if (!content.includes("OkHttpClientProvider.setOkHttpClientFactory")) {
      content = content.replace(/super\.onCreate\(\)/, `super.onCreate()${okHttpClientCode}`);
    }

    // Register CookiePackage if it exists
    if (!content.includes("add(CookiePackage())")) {
      content = content.replace(
        /PackageList\(this\)\.packages\.apply \{/,
        `PackageList(this).packages.apply {\n              add(CookiePackage())`,
      );
    }

    config.modResults.contents = content;
    return config;
  });
};

const withPasskeyAutofill = (config, props = {}) => {
  const site = props.site || "https://debug.liquidauth.com";
  const label = props.label || "My Credential Provider";
  const aaguid = getAaguid(props);

  config = withIosPasskeyAutofill(config, props);
  config = withAndroidCookieModule(config);
  config = withUserAgent(config);

  // TODO: Move assetlinks to CLI
  // 1. Add asset_statements meta-data to MainActivity
  config = withAndroidManifest(config, async (config) => {
    const mainActivity = config.modResults.manifest.application[0].activity.find(
      (a) => a["$"]["android:name"] === ".MainActivity",
    );
    if (mainActivity) {
      if (!mainActivity["meta-data"]) {
        mainActivity["meta-data"] = [];
      }
      if (!mainActivity["meta-data"].find((m) => m["$"]["android:name"] === "asset_statements")) {
        mainActivity["meta-data"].push({
          $: {
            "android:name": "asset_statements",
            "android:resource": "@string/asset_statements",
          },
        });
      }
    }
    return config;
  });

  // Expose the configured biometric requirement to the native provider/activities.
  config = withAndroidManifest(config, (config) => {
    const application = config.modResults.manifest.application[0];
    if (!application["meta-data"]) {
      application["meta-data"] = [];
    }
    const name = ANDROID_BIOMETRIC_META_DATA_NAME;
    const existing = application["meta-data"].find((m) => m["$"]["android:name"] === name);
    const value = getBiometricRequirement(props);
    if (existing) {
      existing["$"]["android:value"] = value;
    } else {
      application["meta-data"].push({ $: { "android:name": name, "android:value": value } });
    }
    return config;
  });

  // 2. Add asset_statements string to strings.xml
  config = withStringsXml(config, (config) => {
    const stringItems = [
      {
        $: { name: "asset_statements", translatable: "false" },
        _: JSON.stringify([
          {
            relation: [
              "delegate_permission/common.handle_all_urls",
              "delegate_permission/common.get_login_creds",
            ],
            target: {
              namespace: "web",
              site: site,
            },
          },
        ]),
      },
      {
        $: { name: "passkey_autofill_label", translatable: "true" },
        _: label,
      },
    ];
    if (aaguid) {
      stringItems.push({
        $: { name: "passkey_autofill_aaguid", translatable: "false" },
        _: aaguid,
      });
    }
    config.modResults = AndroidConfig.Strings.setStringItem(stringItems, config.modResults);
    return config;
  });

  // 3. Add local Maven repository for local AAR
  config = withProjectBuildGradle(config, (config) => {
    if (config.modResults.contents.includes("android/libs/repo")) {
      return config;
    }
    // Dynamically find the path to the library's android/libs/repo directory
    const projectRoot = config.modRequest.projectRoot;
    const libraryRepoPath = path.join(__dirname, "android/libs/repo");
    const relativeRepoPath = path.relative(projectRoot, libraryRepoPath).replace(/\\/g, "/");

    // In Gradle, rootDir is the android directory of the app.
    // So the path to the repo relative to rootDir is ../<relativeRepoPath>
    const repoInjectedCode = `allprojects {
  repositories {
    maven {
      url = uri("\${rootDir}/../${relativeRepoPath}")
    }`;

    config.modResults.contents = config.modResults.contents.replace(
      /allprojects\s*{[\s\n]*repositories\s*{/,
      repoInjectedCode,
    );
    return config;
  });

  return config;
};

module.exports = withPasskeyAutofill;
module.exports.getBiometricRequirement = getBiometricRequirement;
