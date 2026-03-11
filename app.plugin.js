const {
  withAndroidManifest,
  withStringsXml,
  withProjectBuildGradle,
  AndroidConfig,
} = require("@expo/config-plugins");
const path = require("path");

const withPasskeyAutofill = (config, props = {}) => {
  const site = props.site || "https://fido.shore-tech.net";

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
