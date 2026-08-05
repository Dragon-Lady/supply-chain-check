const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;
const LOCKFILES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "pnpm-lock.yaml",
  "yarn.lock"
]);
const PYTHON_DEPENDENCY_FILES = new Set(["requirements.txt", "pyproject.toml", "uv.lock", "Pipfile.lock"]);
const PYTHON_SOURCE_EXTENSIONS = new Set([".py"]);
const COMPOSER_DEPENDENCY_FILES = new Set(["composer.json", "composer.lock"]);
const RUBY_DEPENDENCY_FILES = new Set(["Gemfile", "Gemfile.lock"]);
const RUBY_SOURCE_EXTENSIONS = new Set([".rb"]);
const PACKAGE_MANIFEST = "package.json";
const BROWSER_EXTENSION_MANIFEST = "manifest.json";
const GITIGNORE_FILE = ".gitignore";
const NPM_CONFIG_FILE = ".npmrc";
const TOOL_CONFIG_FILES = new Set(["settings.json", "settings.local.json", "tasks.json", "extensions.json"]);
const DEPLOYMENT_CONFIG_FILES = new Set(["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]);
const JAVASCRIPT_SOURCE_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);
const PYTHON_STARTUP_HOOK_EXTENSIONS = new Set([".pth"]);
const NATIVE_EXTENSION_EXTENSIONS = new Set([".so"]);
const WASM_EXTENSIONS = new Set([".wasm"]);
const VSIX_EXTENSIONS = new Set([".vsix"]);
const MIASMA_MARKER_FILES = new Set(["ARCHITECTURE.MD", "INTEGRATION_TESTING.md", "README.md", "bunfig.toml", "binding.gyp"]);
const HADES_NATIVE_EXTENSION_FILES = new Set(["ensmallen_haswell.abi3.so", "ensmallen_core2.abi3.so"]);
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);
const LITELLM_AFFECTED_MIN = "1.74.2";
const LITELLM_FIXED = "1.83.7";
const STARLETTE_FIXED = "1.0.1";
const LANGFLOW_UPLOAD_FIXED = "1.9.1";
const LANGFLOW_WEBHOOK_AFFECTED_MAX = "1.8.4";
const LANGFLOW_WEBHOOK_FIXED = "1.9.1";
const LANGFLOW_PYTHON_REPL_FIXED = "1.9.4";
const LIVEWIRE_AFFECTED_MIN = "3.0.0";
const LIVEWIRE_FIXED = "3.6.4";
const OPENCLAW_FIXED = "2026.4.23";
const OPENCLAW_CONFIG_FILES = new Set([".crabbox.yaml", ".crabbox.yml"]);
const NPM_V12_PREPARE_MIN = "11.16.0";
const LITELLM_MCP_TEST_ROUTES = [
  "/mcp-rest/test/connection",
  "/mcp-rest/test/tools/list"
];
const PROVIDER_KEY_ENV_TERMS = [
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "AZURE_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "AWS_ACCESS_KEY_ID",
  "GOOGLE_API_KEY",
  "GEMINI_API_KEY",
  "MISTRAL_API_KEY",
  "COHERE_API_KEY"
];

const AUTOJACK_TEXT_INDICATORS = [
  "AutoJack",
  "StdioServerParams",
  "server_params",
  "/api/mcp/ws",
  "/api/mcp",
  "autogenstudio",
  "AutoGen Studio",
  "localhost:8081",
  "127.0.0.1:8081",
  "b047730"
];

const GLASSWASM_OPENVSX_PACKAGES = [
  "exargd/vsblack@0.0.1",
  "vscode/exargd/vsblack@0.0.1",
  "exargd.vsblack-0.0.1.vsix",
  "noellee-doc/flint-debug@0.1.1",
  "vscode/noellee-doc/flint-debug@0.1.1",
  "noellee-doc.flint-debug-0.1.1.vsix"
];

const GLASSWASM_TEXT_INDICATORS = [
  "snqpkebiwrxmoivl.wasm",
  "orybbbdsuqmaapel.wasm",
  "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f",
  "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58",
  "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25",
  "dodod.lat",
  "6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz",
  "getSignaturesForAddress",
  "getTransaction",
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
  "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM"
];

const JETBRAINS_AI_KEY_PLUGIN_IDS = [
  "org.sm.yms.toolkit",
  "com.json.simple.kit",
  "org.bug.find.tools",
  "org.translate.ai.simple",
  "com.yy.test.ai.simple",
  "com.dev.ai.toolkit",
  "com.json.view.simple",
  "com.my.git.ai.kit",
  "org.check.ai.ds",
  "com.review.tool.code",
  "org.code.assist.dev.tool",
  "com.coder.ai.dpt",
  "com.my.code.tools",
  "ord.cp.code.ai.kit",
  "com.dp.git.ai.tool"
];

const JETBRAINS_AI_KEY_ENDPOINT_INDICATORS = [
  "39.107.60.51",
  "39.107.60[.]51",
  "39.107.60.51/api/software/key",
  "39.107.60[.]51/api/software/key",
  "/api/software/key",
  "F48D2AA7CF341F782C1D",
  "BaseUtil.request",
  "BaseUtil.request()",
  "save()",
  "51 chars",
  "plaintext HTTP"
];

const EXTENSION_COMMERCE_SDK_TEXT_INDICATORS = [
  "Give Freely",
  "GiveFreely",
  "givefreely",
  "givefreely.com",
  "commerce-tracking SDK",
  "affiliate SDK",
  "affiliate tracking",
  "persistent device ID",
  "deviceId",
  "geolocate",
  "geolocation by IP",
  "all-sites permission",
  "all sites permission"
];

const ADBLOCK_YOUTUBE_EXTENSION_IDS = [
  "cmedhionkhpnakcndndgjdbohmhepckk",
  "onomjaelhagjjojbkcafidnepbfkpnee",
  "ogcaehilgakehloljjmajoempaflmdci",
  "gekoepiplklhniacchbbgbhilidiojmb"
];

const ADBLOCK_YOUTUBE_NETWORK_INDICATORS = [
  "api.adblock-for-youtube.com",
  "get.adblock-for-youtube.com",
  "api.extensionplay.com",
  "extensionplay.com",
  "unistream.io",
  "cdn.unistream.io",
  "api.unistream.io",
  "api.ad-block-for-chrome.com",
  "get.ad-block-for-chrome.com"
];

const ADBLOCK_YOUTUBE_TEXT_INDICATORS = [
  "Adblock for YouTube",
  "Adblock for Chrome",
  "Adblock for You",
  "AdBlock Suite",
  "BadBlocker",
  "Unistream SDK",
  "scripletsRules",
  "trusted-create-element",
  "MAIN-world",
  "remote-controlled injection path",
  "chrome.scripting.executeScript",
  "world: 'MAIN'",
  "world:\"MAIN\"",
  "/youtube\\.com/",
  "youtube.com anywhere in the URL"
];

const DEFAULT_ADVISORY = {
  indicators: {
    maliciousOptionalDependencyName: "terminal-logger-utils",
    maliciousOptionalDependencySpec: "",
    payloadFiles: [],
    payloadFileHashes: {},
    maliciousOptionalDependencies: [
      { name: "pretty-logger-utils" },
      { name: "ts-logger-pack" },
      { name: "pinno-loggers" }
    ]
  },
  packages: {},
  pypiPackages: {},
  composerPackages: {},
  gemPackages: {}
};

function loadAdvisoryData() {
  const dataDir = path.join(__dirname, "..", "data");
  try {
    const raw = loadSplitAdvisoryData(dataDir);
    return normalizeAdvisory(raw);
  } catch (error) {
    const legacyPath = path.join(dataDir, "affected-packages.json");
    try {
      const raw = JSON.parse(fs.readFileSync(legacyPath, "utf8"));
      return normalizeAdvisory(raw);
    } catch (legacyError) {
      if (error.code === "ENOENT" || legacyError.code === "ENOENT") return DEFAULT_ADVISORY;
    }
    return DEFAULT_ADVISORY;
  }
}

function loadSplitAdvisoryData(dataDir) {
  const advisory = readJsonFile(path.join(dataDir, "advisory.json"));
  return {
    ...advisory,
    indicators: readJsonFile(path.join(dataDir, "indicators.json")),
    packages: readJsonFile(path.join(dataDir, "packages", "npm.json")),
    pypiPackages: readJsonFile(path.join(dataDir, "packages", "pypi.json")),
    composerPackages: readJsonFile(path.join(dataDir, "packages", "composer.json")),
    gemPackages: readJsonFile(path.join(dataDir, "packages", "rubygems.json"))
  };
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function scanTarget(targetPath, options = {}) {
  const root = path.resolve(targetPath || ".");
  const advisory = options.advisory || loadAdvisoryData();
  const payloadFiles = new Set(advisory.indicators.payloadFiles || DEFAULT_ADVISORY.indicators.payloadFiles);
  const findings = [];
  const trustSignals = [];
  const seen = { files: 0, manifests: 0, lockfiles: 0 };

  walk(root, (filePath, dirent) => {
    seen.files += 1;
    const base = dirent.name;

    scanMiasmaPath(filePath, findings);
    scanHadesPath(filePath, findings);
    scanGlassWasmPath(filePath, findings);
    scanJetBrainsAiKeyStealerPath(filePath, findings);
    scanAdblockForYoutubePath(filePath, findings);

    if (payloadFiles.has(base)) {
      findings.push(finding("critical", "payload-file", filePath, `Known incident payload filename present: ${base}`));
      scanPayloadHash(filePath, base, advisory, findings);
    }

    if (base === PACKAGE_MANIFEST) {
      seen.manifests += 1;
      scanPackageJson(filePath, advisory, findings, trustSignals);
      return;
    }

    if (base === BROWSER_EXTENSION_MANIFEST) {
      scanBrowserExtensionManifest(filePath, advisory, findings);
      return;
    }

    if (base === GITIGNORE_FILE) {
      scanGitignoreFile(filePath, findings);
      return;
    }

    if (base === NPM_CONFIG_FILE) {
      scanNpmConfigFile(filePath, findings, trustSignals);
      return;
    }

    if (isAstroConfigFile(filePath, base)) {
      scanAstroConfigFile(filePath, findings);
      return;
    }

    if (isOpenClawConfigFile(filePath, base)) {
      scanOpenClawConfigFile(filePath, findings);
      return;
    }

    if (LOCKFILES.has(base)) {
      seen.lockfiles += 1;
      scanTextFile(filePath, advisory, findings, trustSignals);
      return;
    }

    if (isPythonDependencyFile(base)) {
      scanPythonDependencyFile(filePath, advisory, findings);
      return;
    }

    if (isPythonStartupHookFile(filePath)) {
      scanPythonStartupHookFile(filePath, advisory, findings);
      return;
    }

    if (isPythonSourceFile(filePath)) {
      scanPythonSourceFile(filePath, advisory, findings);
      return;
    }

    if (isNativePythonExtensionFile(filePath)) {
      scanNativePythonExtensionFile(filePath, findings);
      return;
    }

    if (isWasmFile(filePath)) {
      scanWasmFile(filePath, findings);
      return;
    }

    if (isVsixFile(filePath)) {
      scanVsixFile(filePath, findings);
      return;
    }

    if (COMPOSER_DEPENDENCY_FILES.has(base)) {
      scanComposerDependencyFile(filePath, advisory, findings);
      return;
    }

    if (isRubyDependencyFile(filePath, base)) {
      scanRubyDependencyFile(filePath, advisory, findings);
      return;
    }

    if (isRubySourceFile(filePath)) {
      scanRubySourceFile(filePath, base, advisory, findings);
      return;
    }

    if (isToolConfigFile(filePath, base)) {
      scanToolConfigFile(filePath, advisory, findings);
      return;
    }

    if (isGitHubActionsWorkflowFile(filePath, base)) {
      scanGitHubActionsWorkflowFile(filePath, advisory, findings);
      return;
    }

    if (isMiasmaMarkerFile(base)) {
      scanMiasmaMarkerFile(filePath, findings);
      return;
    }

    if (isDeploymentConfigFile(base)) {
      scanDeploymentConfigFile(filePath, advisory, findings);
      return;
    }

    if (isJavaScriptSourceFile(filePath)) {
      scanJavaScriptSourceFile(filePath, advisory, findings);
    }
  });

  const dedupedFindings = dedupeFindings(findings);
  const dedupedTrustSignals = dedupeTrustSignals(trustSignals);
  const risk = riskLevel(dedupedFindings);
  return {
    tool: "supply-chain-check",
    scannedAt: new Date().toISOString(),
    target: root,
    risk,
    summary: {
      filesScanned: seen.files,
      packageManifestsScanned: seen.manifests,
      lockfilesScanned: seen.lockfiles,
      trustSignals: dedupedTrustSignals.length,
      findings: dedupedFindings.length
    },
    trustSignals: dedupedTrustSignals,
    findings: dedupedFindings,
    guidance: guidanceForRisk(risk)
  };
}

function walk(root, onFile) {
  let rootStat;
  try {
    rootStat = fs.statSync(root);
  } catch (error) {
    return;
  }

  if (rootStat.isFile()) {
    onFile(root, { name: path.basename(root) });
    return;
  }

  const stack = [root];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (error) {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        stack.push(fullPath);
      } else if (entry.isFile()) {
        onFile(fullPath, entry);
      }
    }
  }
}

function scanPayloadHash(filePath, fileName, advisory, findings) {
  const knownHashes = advisory.indicators.payloadFileHashes?.[fileName];
  if (!Array.isArray(knownHashes) || knownHashes.length === 0) return;

  let data;
  try {
    data = fs.readFileSync(filePath);
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not hash payload candidate: ${error.message}`));
    return;
  }

  const sha256 = crypto.createHash("sha256").update(data).digest("hex");
  if (knownHashes.includes(sha256)) {
    findings.push(finding("critical", "payload-hash", filePath, `${fileName} matches known malicious SHA-256 ${sha256}.`));
  }
}

function scanPackageJson(filePath, advisory, findings, trustSignals) {
  let rawText;
  let manifest;
  try {
    rawText = fs.readFileSync(filePath, "utf8");
    manifest = JSON.parse(rawText);
  } catch (error) {
    findings.push(finding("low", "parse-error", filePath, `Could not parse package.json: ${error.message}`));
    return;
  }

  scanManifestText(filePath, rawText, advisory, findings);
  scanMiasmaText(filePath, rawText, findings, "Manifest");
  scanHadesText(filePath, rawText, findings, "Manifest");
  scanGlassWasmText(filePath, rawText, findings, "Manifest");
  scanExtensionCommerceSdkText(filePath, rawText, findings, "Manifest");
  scanOpenClawText(filePath, rawText, findings, "Manifest");
  scanNpmV12Manifest(filePath, rawText, manifest, findings, trustSignals);
  scanNpmStagedPublishSignals(filePath, rawText, trustSignals);

  if (manifest.name && manifest.version && versionIsListed(advisory.packages[manifest.name], manifest.version)) {
    findings.push(finding("critical", "known-bad-version", filePath, `${manifest.name}@${manifest.version} is listed as compromised.`));
  }

  const dependencySections = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies", "bundledDependencies"];
  for (const section of dependencySections) {
    const deps = manifest[section];
    if (!deps || typeof deps !== "object" || Array.isArray(deps)) continue;

    for (const [name, spec] of Object.entries(deps)) {
      inspectDependencySpec(filePath, section, name, String(spec), advisory, findings);
    }
  }

  const scripts = manifest.scripts || {};
  for (const scriptName of LIFECYCLE_SCRIPTS) {
    if (typeof scripts[scriptName] === "string") {
      const scriptBody = scripts[scriptName];
      if (scriptName === "postinstall" && /\butils\.cjs\b/i.test(scriptBody)) {
        findings.push(finding("critical", "dprk-npm-rat-postinstall", filePath, `postinstall runs utils.cjs, matching the OX DPRK npm RAT dropper pattern: ${scriptBody}`));
      }
      const severity = scriptName === "postinstall" && /\butils\.cjs\b/i.test(scriptBody) ? "high" : "medium";
      findings.push(finding(severity, "lifecycle-script", filePath, `Lifecycle script "${scriptName}" is present: ${scriptBody}`));
    }
  }
}

function scanManifestText(filePath, text, advisory, findings) {
  const indicators = advisory.indicators;

  for (const payload of indicators.payloadFiles) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "payload-reference", filePath, `Manifest references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Manifest");
}

function normalizeAdvisory(raw) {
  const advisory = {
    indicators: {
      ...DEFAULT_ADVISORY.indicators,
      ...(raw && typeof raw.indicators === "object" ? raw.indicators : {})
    },
    packages: {},
    pypiPackages: {},
    composerPackages: {},
    gemPackages: {}
  };

  if (raw && raw.packages && typeof raw.packages === "object" && !Array.isArray(raw.packages)) {
    for (const [name, versions] of Object.entries(raw.packages)) {
      addAdvisoryPackage(advisory.packages, name, versions);
    }
  } else if (Array.isArray(raw)) {
    for (const item of raw) {
      if (!item || typeof item !== "object") continue;
      addAdvisoryPackage(advisory.packages, item.name || item.package || item.packageName, item.version || item.versions);
    }
  } else if (raw && typeof raw === "object") {
    for (const [name, versions] of Object.entries(raw)) {
      if (name === "indicators") continue;
      addAdvisoryPackage(advisory.packages, name, versions);
    }
  }

  if (raw && raw.pypiPackages && typeof raw.pypiPackages === "object" && !Array.isArray(raw.pypiPackages)) {
    for (const [name, versions] of Object.entries(raw.pypiPackages)) {
      addAdvisoryPackage(advisory.pypiPackages, normalizePythonPackageName(name), versions);
    }
  }

  if (raw && raw.composerPackages && typeof raw.composerPackages === "object" && !Array.isArray(raw.composerPackages)) {
    for (const [name, versions] of Object.entries(raw.composerPackages)) {
      addAdvisoryPackage(advisory.composerPackages, name.toLowerCase(), versions);
    }
  }

  if (raw && raw.gemPackages && typeof raw.gemPackages === "object" && !Array.isArray(raw.gemPackages)) {
    for (const [name, versions] of Object.entries(raw.gemPackages)) {
      addAdvisoryPackage(advisory.gemPackages, name.toLowerCase(), versions);
    }
  }

  return advisory;
}

function addAdvisoryPackage(packages, name, versions) {
  if (typeof name !== "string" || name.length === 0) return;
  const normalizedVersions = Array.isArray(versions) ? versions : [versions];
  const cleanVersions = normalizedVersions.filter((version) => typeof version === "string" && version.length > 0);
  if (cleanVersions.length > 0) packages[name] = cleanVersions;
}

function inspectDependencySpec(filePath, section, name, spec, advisory, findings) {
  const indicators = advisory.indicators;

  if (name === indicators.maliciousOptionalDependencyName) {
    findings.push(finding("critical", "malicious-dependency-name", filePath, `${section} contains ${name}.`));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency && name === dependency.name) {
      findings.push(finding("critical", "malicious-dependency-name", filePath, `${section} contains ${name}.`));
    }
  }

  if (indicators.maliciousOptionalDependencySpec && spec.includes(indicators.maliciousOptionalDependencySpec)) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, `${section}.${name} points to the known malicious GitHub commit.`));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency?.spec && spec.includes(dependency.spec)) {
      findings.push(finding("critical", "malicious-dependency-spec", filePath, `${section}.${name} points to a known malicious GitHub commit.`));
    }
  }

  if (/^github:/i.test(spec) || /github\.com[:/]/i.test(spec)) {
    const severity = section === "optionalDependencies" ? "high" : "medium";
    findings.push(finding(severity, "github-dependency", filePath, `${section}.${name} resolves from GitHub: ${spec}`));
  }

  if (matchesActiveNamespace(name, advisory)) {
    findings.push(finding("medium", "active-campaign-namespace", filePath, `${section}.${name} is in a namespace reported in the active campaign; verify the exact version.`));
  }

  if (matchesActivePackage(name, advisory)) {
    findings.push(finding("medium", "active-campaign-package", filePath, `${section}.${name} is a package reported in the active campaign; verify the exact version.`));
  }

  if (versionIsListed(advisory.packages[name], spec)) {
    findings.push(finding("critical", "known-bad-requested-version", filePath, `${section}.${name} requests compromised version ${spec}.`));
  }

  scanLiteLlmDependencySpec(filePath, section, name, spec, findings);
  scanLangflowDependencySpec(filePath, section, name, spec, findings);
  scanOpenClawDependencySpec(filePath, section, name, spec, findings);
  scanNpmV12DependencySpec(filePath, section, name, spec, findings);
}

function scanTextFile(filePath, advisory, findings, trustSignals) {
  let stat;
  try {
    stat = fs.statSync(filePath);
  } catch (error) {
    return;
  }
  if (stat.size > DEFAULT_MAX_FILE_BYTES) {
    findings.push(finding("low", "large-lockfile-skipped", filePath, `Skipped lockfile over ${DEFAULT_MAX_FILE_BYTES} bytes.`));
    return;
  }

  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read lockfile: ${error.message}`));
    return;
  }

  const indicators = advisory.indicators;
  for (const payload of indicators.payloadFiles) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "payload-reference", filePath, `Lockfile references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Lockfile");
  scanMiasmaText(filePath, text, findings, "Lockfile");
  scanHadesText(filePath, text, findings, "Lockfile");
  scanGlassWasmText(filePath, text, findings, "Lockfile");
  scanExtensionCommerceSdkText(filePath, text, findings, "Lockfile");
  scanLiteLlmText(filePath, text, findings, "Lockfile");
  scanOpenClawText(filePath, text, findings, "Lockfile");
  scanNpmV12LockfileText(filePath, text, findings);
  scanNpmStagedPublishSignals(filePath, text, trustSignals);

  if (text.includes(indicators.maliciousOptionalDependencyName)) {
    findings.push(finding("critical", "malicious-dependency-name", filePath, `Lockfile references ${indicators.maliciousOptionalDependencyName}.`));
  }

  if (indicators.maliciousOptionalDependencySpec && text.includes(indicators.maliciousOptionalDependencySpec)) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, "Lockfile references the known malicious GitHub commit."));
  }

  for (const dependency of indicators.maliciousOptionalDependencies || []) {
    if (dependency?.name && text.includes(dependency.name)) {
      findings.push(finding("critical", "malicious-dependency-name", filePath, `Lockfile references ${dependency.name}.`));
    }
    if (dependency?.spec && text.includes(dependency.spec)) {
      findings.push(finding("critical", "malicious-dependency-spec", filePath, "Lockfile references a known malicious GitHub commit."));
    }
  }

  for (const [pkg, versions] of Object.entries(advisory.packages)) {
    if (packageIsListedAllVersions(versions) && text.includes(pkg)) {
      findings.push(finding("critical", "known-bad-lockfile-package", filePath, `Lockfile references ${pkg}, which is listed as compromised for all observed versions.`));
      continue;
    }
    for (const version of versions) {
      if (version === "*") continue;
      if (lockfileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-lockfile-version", filePath, `Lockfile references ${pkg}@${version}.`));
      }
    }
  }

  for (const namespace of advisory.indicators.activeNamespaces || []) {
    if (typeof namespace === "string" && namespace.length > 0 && text.includes(namespace)) {
      findings.push(finding("medium", "active-campaign-namespace", filePath, `Lockfile references namespace reported in the active campaign: ${namespace}`));
    }
  }

  for (const pkg of advisory.indicators.activePackages || []) {
    if (typeof pkg === "string" && pkg.length > 0 && text.includes(pkg)) {
      findings.push(finding("medium", "active-campaign-package", filePath, `Lockfile references package reported in the active campaign: ${pkg}`));
    }
  }
}

function scanPythonDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Python dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Python dependency file");
  scanMiasmaText(filePath, text, findings, "Python dependency file");
  scanHadesText(filePath, text, findings, "Python dependency file");
  scanGlassWasmText(filePath, text, findings, "Python dependency file");
  scanLiteLlmText(filePath, text, findings, "Python dependency file");
  scanAutoJackText(filePath, text, findings, "Python dependency file");
  scanLangflowDependencyText(filePath, text, findings, "Python dependency file");

  for (const [pkg, versions] of Object.entries(advisory.pypiPackages || {})) {
    if (packageIsListedAllVersions(versions) && pythonFileMentionsPackage(text, pkg)) {
      findings.push(finding("critical", "known-bad-pypi-package", filePath, `Python dependency file references ${pkg}, which is listed as compromised for all observed versions.`));
      continue;
    }
    for (const version of versions) {
      if (pythonFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-pypi-version", filePath, `Python dependency file references ${pkg}==${version}.`));
      }
    }
  }
}

function scanLangflowDependencyText(filePath, text, findings, sourceLabel) {
  for (const version of packageVersionsInText(text, "langflow")) {
    if (compareDottedVersion(version, LANGFLOW_PYTHON_REPL_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-10561-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-10561 PythonREPL unauthenticated RCE. Upgrade to langflow>=${LANGFLOW_PYTHON_REPL_FIXED}.`));
    }
    if (compareDottedVersion(version, LANGFLOW_WEBHOOK_AFFECTED_MAX) <= 0) {
      findings.push(finding("critical", "langflow-cve-2026-7664-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-7664 unauthenticated webhook/MCP flow execution. Upgrade to langflow>=${LANGFLOW_WEBHOOK_FIXED}.`));
    }
    if (compareDottedVersion(version, LANGFLOW_UPLOAD_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-55450-vulnerable-version", filePath, `${sourceLabel} references Langflow ${version}, affected by CVE-2026-55450. Upgrade to langflow>=${LANGFLOW_UPLOAD_FIXED}.`));
    }
  }
}

function scanPythonStartupHookFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Python startup hook file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Python startup hook");
  scanMiasmaText(filePath, text, findings, "Python startup hook");
  scanHadesText(filePath, text, findings, "Python startup hook");
  scanGlassWasmText(filePath, text, findings, "Python startup hook");
}

function scanPythonSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Python source file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Python source file");
  scanMiasmaText(filePath, text, findings, "Python source file");
  scanHadesText(filePath, text, findings, "Python source file");
  scanGlassWasmText(filePath, text, findings, "Python source file");
  scanAutoJackText(filePath, text, findings, "Python source file");
}

function scanNativePythonExtensionFile(filePath, findings) {
  const base = path.basename(filePath);
  if (HADES_NATIVE_EXTENSION_FILES.has(base)) {
    findings.push(finding("critical", "hades-known-native-extension", filePath, `Native extension filename reported in Hades PyPI artifacts: ${base}`));
    return;
  }

  const siblingPayload = path.join(path.dirname(filePath), "_index.js");
  if (base.endsWith(".abi3.so") && fs.existsSync(siblingPayload)) {
    findings.push(finding("high", "hades-native-extension-payload-pair", filePath, "Python native extension is paired with _index.js, matching the Hades import-time launcher layout."));
  }
}

function scanWasmFile(filePath, findings) {
  const base = path.basename(filePath);
  const normalized = filePath.replace(/\\/g, "/");
  if (base === "snqpkebiwrxmoivl.wasm" || base === "orybbbdsuqmaapel.wasm") {
    findings.push(finding("critical", "glasswasm-openvsx-wasm-payload-file", filePath, `GlassWASM Open VSX WASM payload filename is present: ${base}`));
  }

  const hash = hashFileSha256(filePath);
  if (hash === "558b4f1d9a263c13756ab0126c09dd080c85ba405b29488e1c4e6aa68b554f1f") {
    findings.push(finding("critical", "glasswasm-openvsx-wasm-payload-hash", filePath, `WASM file matches Socket GlassWASM payload SHA-256 ${hash}.`));
  } else if (/\/(?:\.vscode|\.vscode-oss|\.cursor|\.windsurf)\/extensions\//i.test(normalized)) {
    findings.push(finding("medium", "editor-extension-wasm-review", filePath, "WASM file appears inside an editor extension path; review provenance and loader behavior."));
  }
}

function scanVsixFile(filePath, findings) {
  const base = path.basename(filePath);
  if (/^(?:exargd\.vsblack-0\.0\.1|noellee-doc\.flint-debug-0\.1\.1)\.vsix$/i.test(base)) {
    findings.push(finding("critical", "glasswasm-openvsx-vsix-file", filePath, `Known GlassWASM Open VSX trojanized VSIX filename is present: ${base}`));
  }

  const hash = hashFileSha256(filePath);
  if (hash === "3aa31999398e7f80231c03d7137ffdb554a84b83dbcffc59ce16c9a65f9e5d58"
    || hash === "1e283327ad048bea39f4a8501770858a20f3555e87fe3e202274f2e87f8a3c25") {
    findings.push(finding("critical", "glasswasm-openvsx-vsix-hash", filePath, `VSIX file matches Socket GlassWASM affected package SHA-256 ${hash}.`));
  }
}

function scanComposerDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Composer dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Composer dependency file");
  scanGlassWasmText(filePath, text, findings, "Composer dependency file");
  scanLivewireComposerText(filePath, text, findings, "Composer dependency file");

  for (const [pkg, versions] of Object.entries(advisory.composerPackages || {})) {
    for (const version of versions) {
      if (composerFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-composer-version", filePath, `Composer dependency file references ${pkg}@${version}.`));
      }
    }
  }
}

function scanLivewireComposerText(filePath, text, findings, sourceLabel) {
  const versions = composerPackageVersionsInText(text, "livewire/livewire");
  for (const version of versions) {
    if (isVersionInRange(version, LIVEWIRE_AFFECTED_MIN, LIVEWIRE_FIXED)) {
      findings.push(finding("critical", "livewire-cve-2025-54068-vulnerable-version", filePath, `${sourceLabel} references livewire/livewire ${version}, affected by CVE-2025-54068. Upgrade to livewire/livewire>=${LIVEWIRE_FIXED}.`));
    }
  }

  if (versions.length === 0 && composerConstraintNeedsLivewireReview(text)) {
    findings.push(finding("medium", "livewire-cve-2025-54068-version-range-review", filePath, `${sourceLabel} references a broad livewire/livewire v3 constraint. Verify the resolved lockfile is livewire/livewire>=${LIVEWIRE_FIXED}.`));
  }
}

function scanRubyDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Ruby dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Ruby dependency file");
  scanGlassWasmText(filePath, text, findings, "Ruby dependency file");
  scanRubyTextIndicators(filePath, text, advisory, findings, "Ruby dependency file");

  for (const [pkg, versions] of Object.entries(advisory.gemPackages || {})) {
    for (const version of versions) {
      if (rubyFileMentionsGemVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-gem-version", filePath, `Ruby dependency file references ${pkg}@${version}.`));
      }
    }
  }
}

function scanRubySourceFile(filePath, base, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Ruby source file: ${error.message}`));
    return;
  }

  const rubyPayloadFiles = advisory.indicators?.rubyPayloadFiles || [];
  if (rubyPayloadFiles.includes(base)) {
    findings.push(finding("medium", "ruby-payload-filename", filePath, `Ruby file uses a filename reported in GemStuffer samples: ${base}`));
    scanRubyPayloadHash(filePath, base, advisory, findings);
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Ruby source file");
  scanGlassWasmText(filePath, text, findings, "Ruby source file");
  scanRubyTextIndicators(filePath, text, advisory, findings, "Ruby source file");
}

function scanRubyPayloadHash(filePath, fileName, advisory, findings) {
  const knownHashes = advisory.indicators?.rubyPayloadFileHashes?.[fileName];
  if (!Array.isArray(knownHashes) || knownHashes.length === 0) return;

  let data;
  try {
    data = fs.readFileSync(filePath);
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not hash Ruby payload candidate: ${error.message}`));
    return;
  }

  const sha256 = crypto.createHash("sha256").update(data).digest("hex");
  if (knownHashes.includes(sha256)) {
    findings.push(finding("critical", "ruby-payload-hash", filePath, `${fileName} matches known malicious SHA-256 ${sha256}.`));
  }
}

function scanRubyTextIndicators(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const values = indicators.rubyIndicators || [];
  if (!Array.isArray(values)) return;

  for (const value of values) {
    if (typeof value !== "string" || value.length === 0) continue;
    if (text.includes(value)) {
      findings.push(finding("high", "ruby-gemstuffer-indicator", filePath, `${sourceLabel} references GemStuffer indicator: ${value}`));
    }
  }
}

function scanToolConfigFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read tool config file: ${error.message}`));
    return;
  }

  const indicators = advisory.indicators;
  for (const payload of indicators.payloadFiles || []) {
    if (text.includes(payload)) {
      findings.push(finding("critical", "tool-config-payload-reference", filePath, `Tool config references ${payload}.`));
    }
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Tool config");
  scanMiasmaText(filePath, text, findings, "Tool config");
  scanHadesText(filePath, text, findings, "Tool config");
  scanGlassWasmText(filePath, text, findings, "Tool config");
  scanExtensionCommerceSdkText(filePath, text, findings, "Tool config");
  scanLiteLlmText(filePath, text, findings, "Tool config");
  scanOpenClawText(filePath, text, findings, "Tool config");
  scanAutoJackText(filePath, text, findings, "Tool config");
}

function scanGitHubActionsWorkflowFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read GitHub Actions workflow file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "GitHub Actions workflow");
  scanMiasmaText(filePath, text, findings, "GitHub Actions workflow");
  scanHadesText(filePath, text, findings, "GitHub Actions workflow");
}

function scanDeploymentConfigFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read deployment config file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Deployment config");
  scanMiasmaText(filePath, text, findings, "Deployment config");
  scanHadesText(filePath, text, findings, "Deployment config");
  scanGlassWasmText(filePath, text, findings, "Deployment config");
  scanExtensionCommerceSdkText(filePath, text, findings, "Deployment config");
  scanLiteLlmText(filePath, text, findings, "Deployment config");
  scanOpenClawText(filePath, text, findings, "Deployment config");
  scanAutoJackText(filePath, text, findings, "Deployment config");
}

function scanJavaScriptSourceFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read JavaScript source file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "JavaScript source file");
  scanMiasmaText(filePath, text, findings, "JavaScript source file");
  scanHadesText(filePath, text, findings, "JavaScript source file");
  scanGlassWasmText(filePath, text, findings, "JavaScript source file");
  scanExtensionCommerceSdkText(filePath, text, findings, "JavaScript source file");
  scanAdblockForYoutubeText(filePath, text, findings, "JavaScript source file");
  scanLiteLlmText(filePath, text, findings, "JavaScript source file");
  scanOpenClawText(filePath, text, findings, "JavaScript source file");
  scanAutoJackText(filePath, text, findings, "JavaScript source file");
}

function scanBrowserExtensionManifest(filePath, advisory, findings) {
  let rawText;
  let manifest;
  try {
    rawText = fs.readFileSync(filePath, "utf8");
    manifest = JSON.parse(rawText);
  } catch (error) {
    findings.push(finding("low", "parse-error", filePath, `Could not parse manifest.json: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, rawText, advisory, findings, "Browser extension manifest");
  scanGlassWasmText(filePath, rawText, findings, "Browser extension manifest");
  scanExtensionCommerceSdkText(filePath, rawText, findings, "Browser extension manifest");
  scanAdblockForYoutubeText(filePath, rawText, findings, "Browser extension manifest");

  if (!manifest || !manifest.manifest_version) return;

  const name = String(manifest.name || "");
  const permissions = [
    ...arrayValues(manifest.permissions),
    ...arrayValues(manifest.host_permissions),
    ...contentScriptMatches(manifest.content_scripts)
  ];
  const broadPermissions = permissions.filter(isAllSitesPermission);

  if (broadPermissions.length > 0) {
    findings.push(finding("medium", "browser-extension-all-sites-permission-review", filePath, `Browser extension manifest grants broad all-sites host permissions: ${broadPermissions.join(", ")}`));
  }

  if (/volume\s*booster/i.test(name) && broadPermissions.length > 0) {
    findings.push(finding("medium", "chrome-volume-booster-permission-drift-watch", filePath, "Volume Booster-style extension has broad all-sites host permissions; review update history for prompt-free activation of telemetry or affiliate SDK code."));
  }

  if (/ad\s*block|adblock|youtube/i.test(name) && broadPermissions.length > 0 && rawText.includes("cmedhionkhpnakcndndgjdbohmhepckk")) {
    findings.push(finding("high", "adblock-youtube-broad-permission-review", filePath, "Adblock for YouTube manifest carries broad all-sites permissions; review update provenance and remote scriptlet configuration."));
  }
}

function scanGitignoreFile(filePath, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read .gitignore: ${error.message}`));
    return;
  }

  scanGitignoreText(filePath, text, findings);
}

function scanAstroConfigFile(filePath, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Astro config: ${error.message}`));
    return;
  }

  scanAstroConfigText(filePath, text, findings);
  scanGlassWasmText(filePath, text, findings, "Astro config");
}

function scanOpenClawConfigFile(filePath, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read OpenClaw config: ${error.message}`));
    return;
  }

  scanOpenClawText(filePath, text, findings, "OpenClaw config");
  scanGlassWasmText(filePath, text, findings, "OpenClaw config");
}

function scanNpmConfigFile(filePath, findings, trustSignals) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read .npmrc: ${error.message}`));
    return;
  }

  scanNpmV12ConfigText(filePath, text, findings, trustSignals);
  scanGlassWasmText(filePath, text, findings, ".npmrc");
}

function scanMiasmaPath(filePath, findings) {
  const normalized = filePath.replace(/\\/g, "/");
  if (normalized.endsWith("/.github/setup.js")) {
    findings.push(finding("critical", "miasma-setup-dropper-file", filePath, "Miasma-style .github/setup.js dropper path is present."));
  }
  if (normalized.endsWith("/.cursor/rules/setup.mdc")) {
    findings.push(finding("high", "miasma-cursor-rule-file", filePath, "Miasma-style Cursor rule file path is present."));
  }
}

function scanHadesPath(filePath, findings) {
  const normalized = filePath.replace(/\\/g, "/");
  const base = path.basename(filePath);
  if (/-setup\.pth$/i.test(base)) {
    findings.push(finding("high", "hades-pth-startup-hook-file", filePath, "Hades-style Python startup hook filename is present."));
  }
  if (base === "_index.js" && /site-packages|\.venv|\/venv\/|\.dist-info|\.whl|py3-none-any/i.test(normalized)) {
    findings.push(finding("high", "hades-python-payload-filename", filePath, "Hades-style _index.js payload filename is present in a Python package context."));
  }
  if (normalized.endsWith("/.github/workflows/codeql.yml")) {
    findings.push(finding("medium", "hades-codeql-workflow-path", filePath, "Unexpected CodeQL workflow changes are listed as a Hades follow-on indicator; review provenance."));
  }
}

function scanGlassWasmPath(filePath, findings) {
  const normalized = filePath.replace(/\\/g, "/");
  const base = path.basename(filePath);
  if (base === "snqpkebiwrxmoivl.wasm" || base === "orybbbdsuqmaapel.wasm") {
    findings.push(finding("critical", "glasswasm-openvsx-wasm-payload-file", filePath, `GlassWASM Open VSX WASM payload filename is present: ${base}`));
  }
  if (/^(?:exargd\.vsblack-0\.0\.1|noellee-doc\.flint-debug-0\.1\.1)\.vsix$/i.test(base)) {
    findings.push(finding("critical", "glasswasm-openvsx-vsix-file", filePath, `Known GlassWASM Open VSX trojanized VSIX filename is present: ${base}`));
  }
  if (/\/(?:\.vscode|\.vscode-oss|\.cursor|\.windsurf)\/extensions\//i.test(normalized)
    && /(?:exargd\.vsblack|noellee-doc\.flint-debug)/i.test(normalized)) {
    findings.push(finding("critical", "glasswasm-openvsx-extension-path", filePath, "Known GlassWASM affected extension ID appears in an editor extension path."));
  }
}

function scanJetBrainsAiKeyStealerPath(filePath, findings) {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  let matchedPluginPath = false;
  for (const pluginId of JETBRAINS_AI_KEY_PLUGIN_IDS) {
    if (normalized.includes(pluginId)) {
      matchedPluginPath = true;
      findings.push(finding("critical", "jetbrains-ai-key-stealer-plugin-path", filePath, `Aikido-reported malicious JetBrains Marketplace plugin ID appears in path: ${pluginId}`));
    }
  }
  if (!matchedPluginPath) return;

  let text;
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > DEFAULT_MAX_FILE_BYTES) return;
    text = fs.readFileSync(filePath, "utf8");
  } catch {
    return;
  }

  scanJetBrainsAiKeyStealerText(filePath, text, findings, "JetBrains plugin file");
}

function scanJetBrainsAiKeyStealerText(filePath, text, findings, sourceLabel) {
  for (const indicator of JETBRAINS_AI_KEY_ENDPOINT_INDICATORS) {
    if (text.includes(indicator)) {
      findings.push(finding("high", "jetbrains-ai-key-stealer-indicator", filePath, `${sourceLabel} references reported JetBrains Marketplace AI-key stealer endpoint: ${indicator}`));
    }
  }
}

function scanAdblockForYoutubePath(filePath, findings) {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  for (const extensionId of ADBLOCK_YOUTUBE_EXTENSION_IDS) {
    if (normalized.includes(extensionId)) {
      findings.push(finding("high", "adblock-youtube-extension-id-path", filePath, `Island-reported Adblock-family Chrome extension ID appears in path: ${extensionId}`));
    }
  }
}

function scanGitignoreText(filePath, text, findings) {
  if (/\b(branch_structure\.json|temp_auto_push\.bat|temp_interactive_push\.bat)\b/i.test(text)) {
    findings.push(finding(
      "high",
      "gitignore-hidden-pr-tooling",
      filePath,
      ".gitignore hides PR automation/helper artifact names reported with Astro config C2 injection."
    ));
  }
}

function scanGlassWasmText(filePath, text, findings, sourceLabel) {
  for (const packageName of GLASSWASM_OPENVSX_PACKAGES) {
    if (text.includes(packageName)) {
      findings.push(finding("critical", "glasswasm-openvsx-package-reference", filePath, `${sourceLabel} references Socket GlassWASM affected Open VSX extension ${packageName}.`));
    }
  }
  for (const indicator of GLASSWASM_TEXT_INDICATORS) {
    if (text.includes(indicator)) {
      findings.push(finding("high", "glasswasm-openvsx-indicator", filePath, `${sourceLabel} contains GlassWASM IOC or C2 dead-drop marker ${indicator}.`));
    }
  }
  if (hasGlassWasmLoaderShape(text)) {
    findings.push(finding("critical", "glasswasm-openvsx-loader-shape", filePath, `${sourceLabel} combines WASM loading with GlassWASM-style Solana C2 or child-process execution behavior.`));
  } else if (hasTinyGoWasmHostShape(text)) {
    findings.push(finding("medium", "tinygo-wasm-js-host-review", filePath, `${sourceLabel} contains TinyGo/WebAssembly JavaScript host fingerprints; review whether the WASM can reach Node APIs.`));
  }
}

function scanExtensionCommerceSdkText(filePath, text, findings, sourceLabel) {
  const matched = EXTENSION_COMMERCE_SDK_TEXT_INDICATORS.filter((indicator) => text.includes(indicator));
  if (matched.length > 0) {
    findings.push(finding("medium", "browser-extension-commerce-sdk-watch", filePath, `${sourceLabel} references browser-extension commerce/affiliate telemetry SDK terms: ${matched.slice(0, 4).join(", ")}`));
  }

  if (/Give\s*Freely|GiveFreely|givefreely/i.test(text)
    && /<all_urls>|\*:\/\/\*\/\*|host_permissions|permissions|chrome\.runtime|chrome\.tabs|fetch\s*\(/i.test(text)) {
    findings.push(finding("medium", "browser-extension-givefreely-broad-permission-watch", filePath, `${sourceLabel} combines Give Freely-style SDK terms with broad extension permission or runtime/network behavior.`));
  }
}

function scanAdblockForYoutubeText(filePath, text, findings, sourceLabel) {
  for (const extensionId of ADBLOCK_YOUTUBE_EXTENSION_IDS) {
    if (text.includes(extensionId)) {
      findings.push(finding("high", "adblock-youtube-extension-id-reference", filePath, `${sourceLabel} references Island-reported Adblock-family Chrome extension ID ${extensionId}.`));
    }
  }

  for (const indicator of ADBLOCK_YOUTUBE_NETWORK_INDICATORS) {
    if (text.includes(indicator)) {
      findings.push(finding("high", "adblock-youtube-network-indicator", filePath, `${sourceLabel} references Adblock for YouTube / related extension infrastructure ${indicator}.`));
    }
  }

  const matched = ADBLOCK_YOUTUBE_TEXT_INDICATORS.filter((indicator) => text.includes(indicator));
  if (matched.length > 0) {
    findings.push(finding("medium", "adblock-youtube-text-indicator", filePath, `${sourceLabel} references Adblock for YouTube script-injection or related-extension terms: ${matched.slice(0, 4).join(", ")}`));
  }

  if (/scripletsRules|trusted-create-element/i.test(text)
    && /chrome\.scripting\.executeScript|world\s*:\s*['"]MAIN['"]|MAIN-world|createElement|scriptlet|server-side configuration|remote-controlled/i.test(text)) {
    findings.push(finding("high", "adblock-youtube-remote-scriptlet-injection-shape", filePath, `${sourceLabel} combines remote scriptlet selection with MAIN-world/script element injection terms reported by Island.`));
  }

  if (/\/youtube\\\.com\/|youtube\.com anywhere in the URL|current URL contains ["']?youtube\.com|includes\s*\(\s*['"]youtube\.com['"]\s*\)/i.test(text)
    && /<all_urls>|\*:\/\/\*\/\*|host_permissions|chrome\.scripting|executeScript|trusted-create-element|scripletsRules/i.test(text)) {
    findings.push(finding("medium", "adblock-youtube-url-gate-review", filePath, `${sourceLabel} matches the weak full-URL youtube.com gate and broad extension execution context described by Island.`));
  }
}

function arrayValues(value) {
  return Array.isArray(value) ? value.map(String) : [];
}

function contentScriptMatches(contentScripts) {
  if (!Array.isArray(contentScripts)) return [];
  return contentScripts.flatMap((script) => arrayValues(script?.matches));
}

function isAllSitesPermission(value) {
  return value === "<all_urls>" || value === "*://*/*" || value === "http://*/*" || value === "https://*/*";
}

function scanAstroConfigText(filePath, text, findings) {
  const hasCreateRequire = /\bcreateRequire\s*\(/i.test(text);
  const hasEvalSink = /\b(eval|Function)\s*\(/i.test(text);
  const hasNetworkLoader = /\brequire\s*\(\s*['"](?:node:)?https?['"]\s*\)|\bfrom\s+['"](?:node:)?https?['"]|\bhttps?\s*\.\s*(?:request|get)\s*\(|\bfetch\s*\(/i.test(text);
  const hasGlobalMutation = /global\s*(?:\.|\[)/i.test(text);
  const hasBlockchainRelay = /trongrid|aptoslabs|bsc-dataseed|publicnode|eth_getTransactionByHash|Sec-V|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP/i.test(text);
  const hasHiddenExecutableLine = text
    .split(/\r?\n/)
    .some((line) => line.length > 300 && /[ \t]{80,}\S/.test(line) && astroConfigLineHasLoaderSignal(line));

  if (hasCreateRequire && (hasEvalSink || hasNetworkLoader || hasGlobalMutation || hasBlockchainRelay)) {
    findings.push(finding(
      "critical",
      "astro-config-require-loader",
      filePath,
      "Astro config reconstructs require and also contains executable loader behavior. Astro evaluates this file during dev/build/preview."
    ));
  }

  if (hasNetworkLoader && hasEvalSink) {
    findings.push(finding(
      "critical",
      "astro-config-network-eval-loader",
      filePath,
      "Astro config combines network retrieval with eval/function execution behavior."
    ));
  }

  if (hasBlockchainRelay) {
    findings.push(finding(
      "high",
      "astro-config-blockchain-c2-marker",
      filePath,
      "Astro config references blockchain/C2 relay markers reported in config-as-code supply-chain attacks."
    ));
  }

  if (hasHiddenExecutableLine) {
    findings.push(finding(
      "high",
      "astro-config-hidden-payload-line",
      filePath,
      "Astro config contains a long horizontally hidden executable-looking payload line."
    ));
  }
}

function astroConfigLineHasLoaderSignal(line) {
  return /createRequire|eval\s*\(|Function\s*\(|global\s*(?:\.|\[)|Buffer\.from|https?\.|\.request\s*\(|\.get\s*\(|fetch\s*\(|trongrid|aptoslabs|bsc-dataseed|publicnode/i.test(line);
}

function scanMiasmaMarkerFile(filePath, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read repository metadata file: ${error.message}`));
    return;
  }
  scanMiasmaText(filePath, text, findings, "Repository metadata");
}

function scanMiasmaText(filePath, text, findings, sourceLabel) {
  if (/Miasma-Open-Source-Release|Mini Shai-Hulud|Team PCP|TeamPCP/i.test(text)) {
    findings.push(finding("critical", "miasma-toolkit-marker", filePath, `${sourceLabel} references Miasma/Mini Shai-Hulud toolkit markers.`));
  }
  if (/SessionStart/i.test(text) && /\.github\/setup\.js|setup\.js|bun\s+run|node\s+\.github/i.test(text)) {
    findings.push(finding("critical", "miasma-agent-sessionstart-hook", filePath, `${sourceLabel} defines an AI-agent SessionStart hook that appears to launch repo-local code.`));
  }
  if (/folderOpen/i.test(text) && /\.github\/setup\.js|setup\.js|bun\s+run|node\s+\.github/i.test(text)) {
    findings.push(finding("critical", "miasma-vscode-folderopen-task", filePath, `${sourceLabel} defines a VS Code folderOpen task that appears to launch repo-local code.`));
  }
  if (/alwaysApply\s*:?\s*true/i.test(text) && /\.github\/setup\.js|setup\.js|run the payload|bun\s+run|node\s+\.github/i.test(text)) {
    findings.push(finding("high", "miasma-cursor-always-apply-rule", filePath, `${sourceLabel} contains an alwaysApply Cursor-style rule tied to payload execution.`));
  }
  if (/skip-checks:true/i.test(text)) {
    findings.push(finding("high", "miasma-skip-checks-commit-marker", filePath, `${sourceLabel} references skip-checks:true, used by Miasma repository mutation to suppress CI.`));
  }
  if (/MCP_SUFFIXES|['"]-mcp['"]|['"]-mpc['"]|TYPO_MODE|TARGET_PACKAGES/i.test(text)) {
    findings.push(finding("medium", "miasma-mcp-typosquat-marker", filePath, `${sourceLabel} references MCP-suffixed typosquat or Miasma typo-mutator controls.`));
  }
  if (/WORKFLOW_ID|REPO_ID_SUFFIX|OIDC_PACKAGES/i.test(text) && /GITHUB_WORKFLOW_REF|GITHUB_REPOSITORY|NPM_TOKEN|NODE_AUTH_TOKEN|id-token\s*:\s*write/i.test(text)) {
    findings.push(finding("high", "miasma-github-oidc-targeting-marker", filePath, `${sourceLabel} references targeted GitHub Actions OIDC propagation controls.`));
  }
  if (/snapshot-[a-z0-9_-]+|Dependabot Updates/i.test(text) && /_index\.js|bun run|OIDC_PACKAGES|NPM_TOKEN|WORKFLOW_ID|REPO_ID_SUFFIX/i.test(text)) {
    findings.push(finding("high", "miasma-repo-poisoning-workflow-marker", filePath, `${sourceLabel} references Miasma-style repository poisoning through snapshot branches or fake Dependabot workflows.`));
  }
  if (/\/etc\/sudoers\.d/i.test(text) && /NOPASSWD:ALL|Privileged|\/etc\/resolv\.conf/i.test(text)) {
    findings.push(finding("high", "miasma-runner-evasion-marker", filePath, `${sourceLabel} references Miasma-style runner sudo/DNS evasion behavior.`));
  }
  if (/AWS-RunShellScript/i.test(text) && /ssm:SendCommand|DescribeInstanceInformation/i.test(text)) {
    findings.push(finding("high", "miasma-aws-ssm-propagation-marker", filePath, `${sourceLabel} references AWS SSM propagation behavior.`));
  }
}

function scanHadesText(filePath, text, findings, sourceLabel) {
  const hasExecutablePthImport = /^\s*import[ \t]/m.test(text);
  const hasBunBootstrap = matchesAnyPattern(text, [
    ["oven-sh\\/bun\\/releases\\/", "download"],
    ["bun-v\\d+\\.\\d+\\.\\d+"],
    ["bun\\.sh\\/", "install"],
    ["Bun\\/1\\.3\\."]
  ]);
  const hasPythonExecution = /subprocess\.(run|Popen|call)|os\.system|exec\(/i.test(text);
  const hasPythonNetworkFetch = /urllib\.request|urlretrieve|requests\.get|curl\b|wget\b|fetch\(/i.test(text);

  if (hasExecutablePthImport && /_index\.js/i.test(text) && hasBunBootstrap && hasPythonExecution) {
    findings.push(finding("critical", "hades-pth-bun-loader", filePath, `${sourceLabel} contains executable .pth-style Bun loader logic for _index.js.`));
  }
  if (/sys\.path/i.test(text) && /_index\.js/i.test(text) && /bun|subprocess/i.test(text)) {
    findings.push(finding("critical", "hades-syspath-payload-loader", filePath, `${sourceLabel} searches sys.path for _index.js and attempts Bun/subprocess execution.`));
  }
  if (hasExecutablePthImport && /_index\.js/i.test(text) && hasPythonNetworkFetch && hasPythonExecution) {
    findings.push(finding("high", "hades-executable-pth-network-launcher", filePath, `${sourceLabel} combines executable .pth import, network retrieval, subprocess execution, and JavaScript payload handoff.`));
  }
  if (matchesAnyPattern(text, [
    ["Hades\\s*-\\s*The End for the ", "Damned"],
    ["IfYouYankThisToken", "ItWillNukeTheComputerOfTheOwnerFully"],
    ["results\\/results-", "\\*\\.json"],
    ["results\\/results-"],
    ["format", "-results"],
    ["Run ", "Copilot"]
  ])) {
    findings.push(finding("high", "hades-github-exfil-marker", filePath, `${sourceLabel} references Hades GitHub or CI exfiltration markers.`));
  }
  if (matchesAnyPattern(text, [
    ["\\.bun", "_ran"],
    ["\\/tmp\\/b\\.zip"],
    ["\\/tmp\\/b\\/bun"],
    ["tempfile\\.gettempdir"],
    ["bun\\s+run\\s+_index\\.js"]
  ])) {
    findings.push(finding("high", "hades-runtime-artifact-marker", filePath, `${sourceLabel} references Hades Bun runtime bootstrap artifacts.`));
  }
  if (matchesAnyPattern(text, [
    ["thebeautiful", "marchoftime"],
    ["thebeautiful", "snadsoftime"],
    ["\\/tmp\\/\\.sshu", "-setup\\.js"],
    ["\\/var\\/run\\/docker\\.sock"],
    ["harden-runner"]
  ])) {
    findings.push(finding("high", "hades-follow-on-indicator", filePath, `${sourceLabel} references Hades follow-on hunting strings or host targets.`));
  }
}

function scanLiteLlmDependencySpec(filePath, section, name, spec, findings) {
  const normalizedName = normalizePythonPackageName(name);
  if (normalizedName !== "litellm" && normalizedName !== "starlette") return;

  const versions = versionsInSpec(spec);
  for (const version of versions) {
    if (normalizedName === "litellm" && isVersionInRange(version, LITELLM_AFFECTED_MIN, LITELLM_FIXED)) {
      findings.push(finding("critical", "litellm-cve-2026-42271-vulnerable-version", filePath, `${section}.${name} references LiteLLM ${version}, affected by CVE-2026-42271. Upgrade to litellm>=${LITELLM_FIXED}.`));
    }
    if (normalizedName === "starlette" && compareDottedVersion(version, STARLETTE_FIXED) < 0) {
      findings.push(finding("medium", "starlette-host-header-review", filePath, `${section}.${name} references Starlette ${version}. If deployed with LiteLLM, upgrade to starlette>=${STARLETTE_FIXED}.`));
    }
  }
}

function scanLangflowDependencySpec(filePath, section, name, spec, findings) {
  if (normalizePythonPackageName(name) !== "langflow") return;

  const versions = versionsInSpec(spec);
  for (const version of versions) {
    if (compareDottedVersion(version, LANGFLOW_PYTHON_REPL_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-10561-vulnerable-version", filePath, `${section}.${name} references Langflow ${version}, affected by CVE-2026-10561 PythonREPL unauthenticated RCE. Upgrade to langflow>=${LANGFLOW_PYTHON_REPL_FIXED}.`));
    }
    if (compareDottedVersion(version, LANGFLOW_WEBHOOK_AFFECTED_MAX) <= 0) {
      findings.push(finding("critical", "langflow-cve-2026-7664-vulnerable-version", filePath, `${section}.${name} references Langflow ${version}, affected by CVE-2026-7664 unauthenticated webhook/MCP flow execution. Upgrade to langflow>=${LANGFLOW_WEBHOOK_FIXED}.`));
    }
    if (compareDottedVersion(version, LANGFLOW_UPLOAD_FIXED) < 0) {
      findings.push(finding("critical", "langflow-cve-2026-55450-vulnerable-version", filePath, `${section}.${name} references Langflow ${version}, affected by CVE-2026-55450. Upgrade to langflow>=${LANGFLOW_UPLOAD_FIXED}.`));
    }
  }
}

function scanOpenClawDependencySpec(filePath, section, name, spec, findings) {
  if (normalizePythonPackageName(name) !== "openclaw") return;

  const versions = versionsInSpec(spec);
  for (const version of versions) {
    if (compareDottedVersion(version, OPENCLAW_FIXED) < 0) {
      findings.push(finding("high", "openclaw-vulnerable-version", filePath, `${section}.${name} references OpenClaw ${version}. Upgrade to openclaw>=${OPENCLAW_FIXED} for the message-object prompt-boundary fix.`));
    }
  }
}

function scanNpmV12Manifest(filePath, rawText, manifest, findings, trustSignals) {
  const npmVersions = [];
  if (typeof manifest.packageManager === "string" && /^npm@/i.test(manifest.packageManager)) {
    npmVersions.push(...versionsInSpec(manifest.packageManager));
  }
  if (manifest.engines && typeof manifest.engines.npm === "string") {
    npmVersions.push(...versionsInSpec(manifest.engines.npm));
  }

  for (const version of npmVersions) {
    if (compareDottedVersion(version, NPM_V12_PREPARE_MIN) < 0) {
      findings.push(finding("medium", "npm-v12-prep-old-npm-pin", filePath, `Project pins npm ${version}; npm ${NPM_V12_PREPARE_MIN}+ shows install-script and non-registry-source migration warnings before npm v12.`));
    }
  }

  if (/"allowScripts"\s*:/i.test(rawText) || /"allow-scripts"\s*:/i.test(rawText)) {
    trustSignals.push(trustSignal(
      "npm-v12-install-script-allowlist",
      filePath,
      "package.json contains npm install-script approval metadata for npm v12 readiness."
    ));
  }
}

function scanNpmV12DependencySpec(filePath, section, name, spec, findings) {
  if (/^(?:git\+|git:\/\/|github:|gitlab:|bitbucket:)|github\.com[:/]/i.test(spec)) {
    findings.push(finding("medium", "npm-v12-git-dependency-review", filePath, `${section}.${name} resolves from a Git source. npm v12 requires explicit --allow-git approval for Git dependencies.`));
  }

  if (/^https?:\/\/.+\.(?:tgz|tar\.gz)(?:[?#].*)?$/i.test(spec)) {
    findings.push(finding("medium", "npm-v12-remote-tarball-review", filePath, `${section}.${name} resolves from a remote tarball URL. npm v12 requires explicit --allow-remote approval for remote URL dependencies.`));
  }
}

function scanNpmV12LockfileText(filePath, text, findings) {
  if (/"hasInstallScript"\s*:\s*true/i.test(text) && !/"allowScripts"\s*:/i.test(text)) {
    findings.push(finding("medium", "npm-v12-install-script-approval-review", filePath, "Lockfile records dependency install scripts. Run npm 11.16+ and review npm approve-scripts output before npm v12."));
  }

  if (/"resolved"\s*:\s*"https?:\/\/[^"]+\.(?:tgz|tar\.gz)(?:[?#][^"]*)?"/i.test(text)) {
    findings.push(finding("medium", "npm-v12-remote-tarball-review", filePath, "Lockfile references a remote tarball URL. npm v12 requires explicit --allow-remote approval for remote URL dependencies."));
  }

  if (/github\.com[:/][^\s"']+|(?:git\+https?|git):\/\/[^\s"']+/i.test(text)) {
    findings.push(finding("medium", "npm-v12-git-dependency-review", filePath, "Lockfile references a Git dependency source. npm v12 requires explicit --allow-git approval for Git dependencies."));
  }
}

function scanNpmV12ConfigText(filePath, text, findings, trustSignals) {
  if (/^\s*strict-allow-scripts\s*=\s*true\s*$/im.test(text)) {
    trustSignals.push(trustSignal(
      "npm-v12-strict-allow-scripts",
      filePath,
      ".npmrc opts into strict install-script approval behavior."
    ));
  }

  if (/^\s*ignore-scripts\s*=\s*true\s*$/im.test(text)) {
    findings.push(finding("low", "npm-v12-ignore-scripts-migration-note", filePath, ".npmrc uses ignore-scripts=true. npm approve-scripts can still list pending approvals, but ignore-scripts takes precedence until removed."));
  }

  if (/^\s*allow-git\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
    findings.push(finding("medium", "npm-v12-broad-allow-git", filePath, ".npmrc broadly allows Git dependency resolution. npm v12 defaults --allow-git to none; keep approvals narrow and intentional."));
  }

  if (/^\s*allow-remote\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
    findings.push(finding("medium", "npm-v12-broad-allow-remote", filePath, ".npmrc broadly allows remote URL dependency resolution. npm v12 defaults --allow-remote to none; keep approvals narrow and intentional."));
  }

  if (/^\s*allow-scripts\s*=\s*(?:true|all|\*)\s*$/im.test(text)) {
    findings.push(finding("medium", "npm-v12-broad-allow-scripts", filePath, ".npmrc broadly allows install scripts. npm v12 moves install-script execution to explicit package approvals."));
  }
}

function scanLiteLlmText(filePath, text, findings, sourceLabel) {
  const hasLiteLlm = /\blitellm\b|LiteLLM|LITELLM|mcp-rest/.test(text);
  const liteLlmVersions = packageVersionsInText(text, "litellm");
  const starletteVersions = packageVersionsInText(text, "starlette");

  for (const version of liteLlmVersions) {
    if (isVersionInRange(version, LITELLM_AFFECTED_MIN, LITELLM_FIXED)) {
      findings.push(finding("critical", "litellm-cve-2026-42271-vulnerable-version", filePath, `${sourceLabel} references LiteLLM ${version}, affected by CVE-2026-42271. Upgrade to litellm>=${LITELLM_FIXED}.`));
    }
  }

  if (hasLiteLlm) {
    for (const version of starletteVersions) {
      if (compareDottedVersion(version, STARLETTE_FIXED) < 0) {
        findings.push(finding("high", "litellm-starlette-host-header-chain", filePath, `${sourceLabel} references LiteLLM with Starlette ${version}; review the unauthenticated RCE chain and upgrade to starlette>=${STARLETTE_FIXED}.`));
      }
    }
  }

  for (const route of LITELLM_MCP_TEST_ROUTES) {
    if (text.includes(route)) {
      findings.push(finding("high", "litellm-mcp-test-route-reference", filePath, `${sourceLabel} references LiteLLM MCP test route ${route}. Block/restrict this route if reachable.`));
    }
  }

  if (hasLiteLlm && /\b(0\.0\.0\.0|\[::\]|::)\b|--host\s+0\.0\.0\.0\b/i.test(text)) {
    findings.push(finding("high", "litellm-public-bind", filePath, `${sourceLabel} appears to bind a LiteLLM-related service to all interfaces.`));
  }

  if (hasLiteLlm) {
    const keyTerms = PROVIDER_KEY_ENV_TERMS.filter((term) => text.includes(term));
    if (keyTerms.length > 0) {
      findings.push(finding("medium", "litellm-provider-key-blast-radius", filePath, `${sourceLabel} references LiteLLM with provider credential environment names: ${keyTerms.join(", ")}. Do not expose proxy/admin/MCP routes publicly.`));
    }
  }
}

function scanAutoJackText(filePath, text, findings, sourceLabel) {
  const hasAutoGen = /autogenstudio|AutoGen Studio|autogen/i.test(text);
  const hasMcpWebSocket =
    /\/api\/mcp\/ws|StdioServerParams|server_params|localhost:8081|127\.0\.0\.1:8081|b047730/i.test(text);

  if (!hasAutoGen && !hasMcpWebSocket) return;

  for (const indicator of AUTOJACK_TEXT_INDICATORS) {
    if (text.includes(indicator)) {
      findings.push(finding("high", "autojack-autogen-mcp-indicator", filePath, `${sourceLabel} references AutoJack/AutoGen local MCP control-plane indicator: ${indicator}`));
    }
  }

  if (hasAutoGen && hasMcpWebSocket) {
    findings.push(finding("high", "autojack-localhost-mcp-control-plane-review", filePath, `${sourceLabel} combines AutoGen/AutoGen Studio with local MCP WebSocket or command-parameter terms. Review whether browsing agents share a host with privileged localhost services.`));
  }
}

function scanOpenClawText(filePath, text, findings, sourceLabel) {
  const maybeOpenClaw =
    /\bopenclaw\b/i.test(text) ||
    isOpenClawConfigFile(filePath, path.basename(filePath)) ||
    isOpenClawContextPath(filePath) ||
    /\bdmPolicy\b|\ballowFrom\b|agents\.defaults\.sandbox/i.test(text);
  if (!maybeOpenClaw) return;

  const openClawVersions = packageVersionsInText(text, "openclaw");
  for (const version of openClawVersions) {
    if (compareDottedVersion(version, OPENCLAW_FIXED) < 0) {
      findings.push(finding("high", "openclaw-vulnerable-version", filePath, `${sourceLabel} references OpenClaw ${version}. Upgrade to openclaw>=${OPENCLAW_FIXED} for the message-object prompt-boundary fix.`));
    }
  }

  const hasOpenDmPolicy = /\bdmPolicy["']?\s*[:=]\s*["']open["']/i.test(text);
  const hasWildcardAllowFrom = /\ballowFrom["']?\s*[:=][\s\S]{0,160}["']\*["']/i.test(text);
  const hasDisabledSandbox = /(?:agents\.defaults\.sandbox\.mode|sandbox[\s\S]{0,80}\bmode)["']?\s*[:=]\s*["'](?:none|off|host|main|disabled)["']/i.test(text);

  if (hasOpenDmPolicy && hasWildcardAllowFrom) {
    findings.push(finding("high", "openclaw-open-dm-wildcard", filePath, `${sourceLabel} appears to allow public inbound DMs with a wildcard allowlist. Require pairing or a stable sender allowlist before enabling agent actions.`));
  }

  if (hasOpenDmPolicy && hasDisabledSandbox) {
    findings.push(finding("high", "openclaw-open-dm-unsandboxed", filePath, `${sourceLabel} appears to combine open inbound DMs with host/main/disabled sandbox mode. Route untrusted channels to a sandboxed non-main agent.`));
  }
}

function scanIndicatorStrings(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const stringGroups = [
    ["network-indicator", indicators.networkIndicators],
    ["workflow-indicator", indicators.workflowIndicators],
    ["campaign-indicator", indicators.campaignIndicators],
    ["dprk-npm-rat-indicator", indicators.dprkNpmRatIndicators],
    ["hades-indicator", indicators.hadesIndicators],
    ["ottercookie-indicator", indicators.otterCookieIndicators],
    ["solana-fakefix-indicator", indicators.solanaFakeFixIndicators],
    ["jetbrains-ai-key-stealer-indicator", indicators.jetBrainsAiKeyStealerIndicators]
  ];

  if (typeof indicators.tokenDescriptionIndicator === "string") {
    stringGroups.push(["token-description-indicator", [indicators.tokenDescriptionIndicator]]);
  }

  for (const [type, values] of stringGroups) {
    if (!Array.isArray(values)) continue;
    for (const value of values) {
      if (typeof value !== "string" || value.length === 0) continue;
      if (text.includes(value)) {
        findings.push(finding("high", type, filePath, `${sourceLabel} references incident indicator: ${value}`));
      }
    }
  }
}

function lockfileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  // Tarball basename is unscoped (e.g. @cacheable/memory → memory-2.2.1.tgz).
  const tarballBase = escapeRegExp(pkg.includes("/") ? pkg.split("/").pop() : pkg);
  const patterns = [
    new RegExp(`${escapedPkg}[^\\n\\r]{0,120}${escapedVersion}`),
    new RegExp(`${escapedPkg.replace("/", "\\/")}[^\\n\\r]{0,120}${escapedVersion}`),
    // package-lock v2/v3 path keys may place "version" on a following line
    new RegExp(`["']node_modules/${escapedPkg}["']\\s*:\\s*\\{[\\s\\S]{0,500}?["']version["']\\s*:\\s*["']${escapedVersion}["']`),
    new RegExp(`node_modules/${escapedPkg}[\\s\\S]{0,240}"version"\\s*:\\s*"${escapedVersion}"`),
    // resolved tarball URLs
    new RegExp(
      `(?:registry\\.npmjs\\.org/|/)(?:@[^/"']+/)?${tarballBase}/-/${tarballBase}-${escapedVersion}\\.tgz`
    ),
    new RegExp(`["']${escapedPkg}@npm:${escapedVersion}["']`)
  ];
  return patterns.some((pattern) => pattern.test(text));
}

function pythonFileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  const normalizedText = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*${escapedVersion})`, "im"),
    new RegExp(`${escapedPkg}[^\\n\\r]{0,200}${escapedVersion}`, "i")
  ];
  return patterns.some((pattern) => pattern.test(normalizedText));
}

function pythonFileMentionsPackage(text, pkg) {
  const escapedPkg = escapeRegExp(pkg);
  const normalizedText = text.toLowerCase();
  const patterns = [
    new RegExp(`(^|[\\s"'\\[]|name\\s*=\\s*["'])${escapedPkg}(["'\\]\\s]|\\s*(==|===|~=|>=|<=|=)\\s*[^\\n\\r]+)`, "im"),
    new RegExp(`\\b${escapedPkg}\\b`, "i")
  ];
  return patterns.some((pattern) => pattern.test(normalizedText));
}

function packageVersionsInText(text, packageName) {
  const escaped = escapeRegExp(packageName);
  const versions = new Set();
  const patterns = [
    new RegExp(`\\b${escaped}\\b\\s*(?:==|===|=|~=|>=|<=|>|<)\\s*["']?([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`\\b${escaped}\\b["']?\\s*[:=]\\s*["']?[^0-9\\n\\r]{0,12}([0-9]+\\.[0-9]+\\.[0-9]+)`, "gi"),
    new RegExp(`name\\s*=\\s*["']${escaped}["'][\\s\\S]{0,300}?version\\s*=\\s*["']([0-9]+\\.[0-9]+\\.[0-9]+)["']`, "gi")
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function versionsInSpec(spec) {
  return Array.from(String(spec).matchAll(/([0-9]+\.[0-9]+\.[0-9]+)/g), (match) => match[1]);
}

function isVersionInRange(version, inclusiveMin, exclusiveMax) {
  return compareDottedVersion(version, inclusiveMin) >= 0 && compareDottedVersion(version, exclusiveMax) < 0;
}

function compareDottedVersion(a, b) {
  const left = String(a).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = String(b).split(".").map((part) => Number.parseInt(part, 10) || 0);
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const l = left[i] || 0;
    const r = right[i] || 0;
    if (l !== r) return l > r ? 1 : -1;
  }
  return 0;
}

function composerFileMentionsPackageVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  return new RegExp(`${escapedPkg}[\\s\\S]{0,500}${escapedVersion}`, "i").test(text.toLowerCase());
}

function composerPackageVersionsInText(text, pkg) {
  const escapedPkg = escapeRegExp(pkg);
  const versions = new Set();
  const patterns = [
    new RegExp(`["']name["']\\s*:\\s*["']${escapedPkg}["'][\\s\\S]{0,500}?["']version["']\\s*:\\s*["']v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)["']`, "gi"),
    new RegExp(`["']${escapedPkg}["']\\s*:\\s*["'][^"']*?v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)`, "gi"),
    new RegExp(`${escapedPkg}[\\s\\S]{0,200}?v?([0-9]+\\.[0-9]+\\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)`, "gi")
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      versions.add(match[1]);
    }
  }
  return Array.from(versions);
}

function composerConstraintNeedsLivewireReview(text) {
  return /["']livewire\/livewire["']\s*:\s*["'][^"']*(?:\^|~|>=|>|3\.|v?3\b)/i.test(text);
}

function rubyFileMentionsGemVersion(text, pkg, version) {
  const escapedPkg = escapeRegExp(pkg);
  const escapedVersion = escapeRegExp(version);
  const normalized = text.toLowerCase();
  const patterns = [
    new RegExp(`\\b${escapedPkg}\\b[\\s\\S]{0,300}\\b${escapedVersion}\\b`, "i"),
    new RegExp(`s\\.name\\s*=\\s*['"]${escapedPkg}['"][\\s\\S]{0,300}s\\.version\\s*=\\s*['"]${escapedVersion}['"]`, "i")
  ];
  return patterns.some((pattern) => pattern.test(normalized));
}

function isPythonDependencyFile(base) {
  return PYTHON_DEPENDENCY_FILES.has(base) || /^requirements.*\.txt$/i.test(base);
}

function isPythonStartupHookFile(filePath) {
  return PYTHON_STARTUP_HOOK_EXTENSIONS.has(path.extname(filePath));
}

function isPythonSourceFile(filePath) {
  return PYTHON_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isNativePythonExtensionFile(filePath) {
  return NATIVE_EXTENSION_EXTENSIONS.has(path.extname(filePath));
}

function isWasmFile(filePath) {
  return WASM_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function isVsixFile(filePath) {
  return VSIX_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function isRubyDependencyFile(filePath, base) {
  return RUBY_DEPENDENCY_FILES.has(base) || path.extname(filePath) === ".gemspec";
}

function isRubySourceFile(filePath) {
  return RUBY_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isToolConfigFile(filePath, base) {
  if (!TOOL_CONFIG_FILES.has(base) && base !== "setup.mdc") return false;
  const normalized = filePath.replace(/\\/g, "/");
  return normalized.includes("/.claude/")
    || normalized.includes("/.gemini/")
    || normalized.includes("/.cursor/")
    || normalized.includes("/.vscode/");
}

function isGitHubActionsWorkflowFile(filePath, base) {
  if (!/\.(?:ya?ml)$/i.test(base)) return false;
  return filePath.replace(/\\/g, "/").includes("/.github/workflows/");
}

function isDeploymentConfigFile(base) {
  return DEPLOYMENT_CONFIG_FILES.has(base);
}

function isMiasmaMarkerFile(base) {
  return MIASMA_MARKER_FILES.has(base);
}

function scanNpmStagedPublishSignals(filePath, text, trustSignals) {
  if (!Array.isArray(trustSignals)) return;

  if (/"approver"\s*:\s*"[^"]+"/i.test(text) || /^\s*approver:\s*\S+/im.test(text)) {
    trustSignals.push(trustSignal(
      "npm-staged-publish-approver",
      filePath,
      "Registry metadata includes an approver field; pnpm 11.5 treats staged publish approval as strong trust evidence."
    ));
  }

  if (/\bnpm\s+stage\s+(publish|approve|reject|view|list|download)\b/i.test(text) || /\bpnpm\s+stage\s+(publish|approve|reject|view|list|download)\b/i.test(text)) {
    trustSignals.push(trustSignal(
      "npm-staged-publish-workflow",
      filePath,
      "Project text references npm staged publishing workflow commands."
    ));
  }
}

function isJavaScriptSourceFile(filePath) {
  return JAVASCRIPT_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function hashFileSha256(filePath) {
  try {
    return crypto.createHash("sha256").update(fs.readFileSync(filePath)).digest("hex");
  } catch (_error) {
    return "";
  }
}

function hasTinyGoWasmHostShape(text) {
  return /wasm_exec\.js|gojs\.syscall\/js|asyncify_(?:start|stop)_(?:unwind|rewind)|new\s+WebAssembly\.(?:Instance|Module)|WebAssembly\.instantiate/i.test(text);
}

function hasGlassWasmLoaderShape(text) {
  const hasWasm = /\.wasm|wasm_exec\.js|WebAssembly\.instantiate|gojs\.syscall\/js|asyncify_(?:start|stop)_(?:unwind|rewind)/i.test(text);
  const hasSolanaDeadDrop = /api\.mainnet\.solana\.com|getSignaturesForAddress|getTransaction|MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr|Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFM|6ExrZayPZzMMSnszc42cH81DpuKT8FhCX9H6Sesn6rpz/i.test(text);
  const hasDownloadExecute = /child_process|execSync|curl\s+-fsSL[\s\S]{0,120}\|\s*bash|powershell[\s\S]{0,80}\b(?:irm|Invoke-RestMethod)\b[\s\S]{0,80}\b(?:iex|Invoke-Expression)\b|windowsHide/i.test(text);
  return hasWasm && (hasSolanaDeadDrop || hasDownloadExecute);
}

function isAstroConfigFile(_filePath, base) {
  return /^astro\.config\.(js|cjs|mjs|ts|mts|cts)$/i.test(base);
}

function isOpenClawConfigFile(filePath, base) {
  return OPENCLAW_CONFIG_FILES.has(base.toLowerCase()) || /^openclaw\.(json|jsonc|yaml|yml|toml)$/i.test(base);
}

function isOpenClawContextPath(filePath) {
  return filePath.replace(/\\/g, "/").toLowerCase().includes("/openclaw/");
}

function normalizePythonPackageName(name) {
  return String(name).toLowerCase().replace(/_/g, "-");
}

function matchesActiveNamespace(packageName, advisory) {
  const namespaces = advisory.indicators?.activeNamespaces;
  if (!Array.isArray(namespaces)) return false;
  return namespaces.some((namespace) => typeof namespace === "string" && namespace.length > 0 && packageName.startsWith(namespace));
}

function matchesActivePackage(packageName, advisory) {
  const packages = advisory.indicators?.activePackages;
  if (!Array.isArray(packages)) return false;
  return packages.some((name) => name === packageName);
}

function versionIsListed(versions, version) {
  if (!Array.isArray(versions)) return false;
  return versions.includes("*") || versions.includes(version);
}

function packageIsListedAllVersions(versions) {
  return Array.isArray(versions) && versions.includes("*");
}

function finding(severity, type, filePath, message) {
  return {
    severity,
    type,
    path: filePath,
    message
  };
}

function trustSignal(type, filePath, message) {
  return {
    type,
    path: filePath,
    message
  };
}

function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];
  for (const item of findings) {
    const key = `${item.severity}\0${item.type}\0${item.path}\0${item.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

function dedupeTrustSignals(signals) {
  const seen = new Set();
  const result = [];
  for (const item of signals) {
    const key = `${item.type}\0${item.path}\0${item.message}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

function riskLevel(findings) {
  if (findings.some((item) => item.severity === "critical")) return "likely-exposed";
  if (findings.some((item) => item.severity === "high")) return "possible-exposure";
  if (findings.some((item) => item.severity === "medium")) return "review-needed";
  return "no-known-indicators";
}

function guidanceForRisk(risk) {
  if (risk === "likely-exposed") {
    return [
      "STOP: Do not run install, build, test, or dev-server commands in this project until reviewed.",
      "This project references known compromised package or payload indicators.",
      "Stop installs, builds, and dev servers in the affected environment.",
      "If payload execution is possible, isolate the host from the network before cleanup.",
      "Rotate GitHub, npm, cloud, Vault, Kubernetes, SSH, and CI secrets from a clean machine.",
      "Treat confirmed execution or credential access as a host compromise and rebuild from a clean baseline."
    ];
  }

  if (risk === "possible-exposure" || risk === "review-needed") {
    return [
      "PAUSE: Review these findings before running package installs or builds.",
      "Review findings before running more package installs.",
      "Prefer npm ci --ignore-scripts or equivalent script-blocking controls until dependency state is verified.",
      "Pin away from known-bad package versions and regenerate lockfiles from a clean environment."
    ];
  }

  return [
    "No known supply-chain indicators were found by this checker.",
    "This does not prove the host is clean; it only means these specific indicators were not observed."
  ];
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function matchesAnyPattern(text, patternParts) {
  return patternParts.some((parts) => new RegExp(parts.join(""), "i").test(text));
}

module.exports = {
  loadAdvisoryData,
  scanTarget,
  riskLevel
};
