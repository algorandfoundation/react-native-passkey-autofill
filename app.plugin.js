const {
  withAndroidManifest,
  withStringsXml,
  withProjectBuildGradle,
  withMainApplication,
  withDangerousMod,
  withXcodeProject,
  withEntitlementsPlist,
  AndroidConfig,
} = require("@expo/config-plugins");
const path = require("path");
const fs = require("fs");

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

const withIosSwiftPackages = (config) => {
  return withXcodeProject(config, (config) => {
    const xcodeProject = config.modResults;
    const { objects } = xcodeProject.hash.project;

    const packages = [
      {
        name: "deterministicP256-swift",
        url: "https://github.com/algorandfoundation/deterministic-P256-swift/",
        branch: "main",
        products: ["deterministicP256-swift"],
      },
      {
        name: "LiquidAuthSDK",
        url: "https://github.com/algorandfoundation/liquid-auth-ios/",
        branch: "main",
        products: ["LiquidAuthSDK"],
      },
    ];

    packages.forEach((pkg) => {
      // Check if package already exists
      if (objects.XCRemoteSwiftPackageReference) {
        const exists = Object.values(objects.XCRemoteSwiftPackageReference).some(
          (ref) => ref.repositoryURL === `"${pkg.url}"` || ref.repositoryURL === pkg.url
        );
        if (exists) return;
      }

      // 1. Create XCRemoteSwiftPackageReference
      const packageRefUuid = xcodeProject.generateUuid();
      objects.XCRemoteSwiftPackageReference = objects.XCRemoteSwiftPackageReference || {};
      objects.XCRemoteSwiftPackageReference[packageRefUuid] = {
        isa: 'XCRemoteSwiftPackageReference',
        repositoryURL: `"${pkg.url}"`,
        requirement: {
          branch: pkg.branch,
          kind: 'branch'
        }
      };
      objects.XCRemoteSwiftPackageReference[`${packageRefUuid}_comment`] = `XCRemoteSwiftPackageReference "${pkg.name}"`;

      // 2. Add to PBXProject packageReferences
      for (const key in objects.PBXProject) {
        if (!key.endsWith('_comment')) {
          objects.PBXProject[key].packageReferences = objects.PBXProject[key].packageReferences || [];
          objects.PBXProject[key].packageReferences.push(packageRefUuid);
        }
      }

      // 3. Create XCSwiftPackageProductDependency for each product
      pkg.products.forEach(productName => {
        const productDepUuid = xcodeProject.generateUuid();
        objects.XCSwiftPackageProductDependency = objects.XCSwiftPackageProductDependency || {};
        objects.XCSwiftPackageProductDependency[productDepUuid] = {
          isa: 'XCSwiftPackageProductDependency',
          package: packageRefUuid,
          productName: productName
        };
        objects.XCSwiftPackageProductDependency[`${productDepUuid}_comment`] = productName;

        // 4. Link to all PBXNativeTarget
        for (const targetKey in objects.PBXNativeTarget) {
          if (!targetKey.endsWith('_comment')) {
            const target = objects.PBXNativeTarget[targetKey];
            target.packageProductDependencies = target.packageProductDependencies || [];
            target.packageProductDependencies.push(productDepUuid);
          }
        }
      });
    });

    // Copy CredentialRepository+HD.swift to the main target
    const projectRoot = config.modRequest.projectRoot;
    const libraryRoot = __dirname;
    const hdFileSourcePath = path.join(libraryRoot, "ios/Credentials/CredentialRepository+HD.swift");
    const hdFileDestPath = path.join(projectRoot, "ios", config.modRequest.projectName, "CredentialRepository+HD.swift");
    
    // Ensure the destination directory exists
    fs.mkdirSync(path.dirname(hdFileDestPath), { recursive: true });
    fs.copyFileSync(hdFileSourcePath, hdFileDestPath);
    
    // We need to add this file to the project and link it to the main target
    const mainTargetUuid = Object.keys(objects.PBXNativeTarget).find(key => !key.endsWith('_comment'));
    const mainGroupKey = xcodeProject.findPBXGroupKey({ name: config.modRequest.projectName });
    
    const hdFileRelativePath = `${config.modRequest.projectName}/CredentialRepository+HD.swift`;
    const oldPath = "../ios/Credentials/CredentialRepository+HD.swift";
    
    if (mainTargetUuid && mainGroupKey) {
        if (xcodeProject.hasFile(oldPath)) {
            xcodeProject.removeSourceFile(oldPath, { target: mainTargetUuid }, mainGroupKey);
        }
        if (!xcodeProject.hasFile(hdFileRelativePath)) {
            xcodeProject.addSourceFile(hdFileRelativePath, { target: mainTargetUuid }, mainGroupKey);
        }
    }

    return config;
  });
};

const withIosAutofill = (config, props = {}) => {
  const appGroupIdentifier = props.appGroupIdentifier || `group.${config.ios?.bundleIdentifier || "co.algorand.auth"}.autofill`;
  const site = props.site || "https://debug.liquidauth.com";

  if (!config.ios) config.ios = {};
  if (!config.ios.infoPlist) config.ios.infoPlist = {};
  if (!config.ios.entitlements) config.ios.entitlements = {};

  // 1. Add App Group to Info.plist
  config.ios.infoPlist.AppGroupIdentifier = appGroupIdentifier;

  // 2. Add App Group entitlement
  const existingGroups = config.ios.entitlements["com.apple.security.application-groups"] || [];
  if (!existingGroups.includes(appGroupIdentifier)) {
    config.ios.entitlements["com.apple.security.application-groups"] = [...existingGroups, appGroupIdentifier];
  }

  // 3. Add Autofill Credential Provider entitlement
  config.ios.entitlements["com.apple.developer.authentication-services.autofill-credential-provider"] = true;

  // 4. Add Associated Domains
  let domain = site;
  try {
    domain = new URL(site).hostname;
  } catch (e) {
    domain = site.replace(/^https?:\/\//, "").split("/")[0];
  }
  
  const existingAssociatedDomains = config.ios.entitlements["com.apple.developer.associated-domains"] || [];
  const webCredentialsDomain = `webcredentials:${domain}`;
  if (!existingAssociatedDomains.includes(webCredentialsDomain)) {
    config.ios.entitlements["com.apple.developer.associated-domains"] = [...existingAssociatedDomains, webCredentialsDomain];
  }

  return config;
};

const withIosPodfileFrameworks = (config) => {
  return withDangerousMod(config, [
    "ios",
    async (config) => {
      const podfile = path.join(config.modRequest.projectRoot, "ios/Podfile");
      let content = fs.readFileSync(podfile, "utf8");
      
      if (!content.includes("use_frameworks! :linkage => :static")) {
        content = content.replace(
          /target '.*' do/,
          (match) => `${match}\n  use_frameworks! :linkage => :static`
        );
        fs.writeFileSync(podfile, content);
      }
      return config;
    },
  ]);
};

const withPasskeyAutofill = (config, props = {}) => {
  const site = props.site || "https://debug.liquidauth.com";
  const label = props.label || "My Credential Provider";

  config = withAndroidCookieModule(config);
  config = withUserAgent(config);
  config = withIosSwiftPackages(config);
  config = withIosPodfileFrameworks(config);
  config = withIosAutofill(config, props);

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

  // 2. Add asset_statements string to strings.xml
  config = withStringsXml(config, (config) => {
    config.modResults = AndroidConfig.Strings.setStringItem(
      [
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
      ],
      config.modResults,
    );
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
    const relativeRepoPath = path.relative(projectRoot, libraryRepoPath);

    // In Gradle, rootDir is the android directory of the app.
    // So the path to the repo relative to rootDir is ../<relativeRepoPath>
    const repoInjectedCode = `allprojects {
  repositories {
    maven {
      url = uri("\${rootDir}/../${relativeRepoPath}")
    }
  }
}
`;
    config.modResults.contents = config.modResults.contents.replace(
      /allprojects \{[\s\S]*?repositories \{/,
      (match) => `${match}\n    maven {\n      url = uri("\${rootDir}/../${relativeRepoPath}")\n    }`
    );
    return config;
  });

  return config;
};

module.exports = withPasskeyAutofill;