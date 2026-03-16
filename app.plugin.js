const {
  withAndroidManifest,
  withStringsXml,
  withProjectBuildGradle,
  withMainApplication,
  withDangerousMod,
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
      const targetDir = path.join(
        projectRoot,
        "android/app/src/main/java",
        packagePath
      );

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

      fs.writeFileSync(
        path.join(targetDir, "CookieModule.kt"),
        cookieModuleContent
      );
      fs.writeFileSync(
        path.join(targetDir, "CookiePackage.kt"),
        cookiePackageContent
      );

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
        content = content.replace(
          /package .*\n/,
          (match) => `${match}${imp}\n`
        );
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
      content = content.replace(
        /super\.onCreate\(\)/,
        `super.onCreate()${okHttpClientCode}`
      );
    }

    // Register CookiePackage if it exists
    if (!content.includes("add(CookiePackage())")) {
      content = content.replace(
        /PackageList\(this\)\.packages\.apply \{/,
        `PackageList(this).packages.apply {\n              add(CookiePackage())`
      );
    }

    config.modResults.contents = content;
    return config;
  });
};

const withPasskeyAutofill = (config, props = {}) => {
  const site = props.site || "https://fido.shore-tech.net";
  const label = props.label || "My Credential Provider";

  config = withAndroidCookieModule(config);
  config = withUserAgent(config);

  // TODO: Move assetlinks to CLI
  // 1. Add asset_statements meta-data to MainActivity
  config = withAndroidManifest(config, async (config) => {
    const mainActivity = config.modResults.manifest.application[0].activity.find(
      (a) => a["$"]["android:name"] === ".MainActivity"
    );
    if (mainActivity) {
      if (!mainActivity["meta-data"]) {
        mainActivity["meta-data"] = [];
      }
      if (
        !mainActivity["meta-data"].find(
          (m) => m["$"]["android:name"] === "asset_statements"
        )
      ) {
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
      config.modResults
    );
    return config;
  });

  // 3. Add flatDir repository for local AAR
  config = withProjectBuildGradle(config, (config) => {
    if (config.modResults.contents.includes("dP256Android-release")) {
      return config;
    }
    const libsDir = path.join(__dirname, "android/libs");
    config.modResults.contents = config.modResults.contents.replace(
      /allprojects\s*{[\s\n]*repositories\s*{/,
      `allprojects {
  repositories {
    flatDir {
      dirs "${libsDir}"
    }`
    );
    return config;
  });

  return config;
};

module.exports = withPasskeyAutofill;
