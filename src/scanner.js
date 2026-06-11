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
const TOOL_CONFIG_FILES = new Set(["settings.json", "settings.local.json", "tasks.json"]);
const DEPLOYMENT_CONFIG_FILES = new Set(["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]);
const JAVASCRIPT_SOURCE_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);
const PYTHON_STARTUP_HOOK_EXTENSIONS = new Set([".pth"]);
const NATIVE_EXTENSION_EXTENSIONS = new Set([".so"]);
const MIASMA_MARKER_FILES = new Set(["ARCHITECTURE.MD", "INTEGRATION_TESTING.md", "README.md", "bunfig.toml", "binding.gyp"]);
const HADES_NATIVE_EXTENSION_FILES = new Set(["ensmallen_haswell.abi3.so", "ensmallen_core2.abi3.so"]);
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);
const LITELLM_AFFECTED_MIN = "1.74.2";
const LITELLM_FIXED = "1.83.7";
const STARLETTE_FIXED = "1.0.1";
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

    if (payloadFiles.has(base)) {
      findings.push(finding("critical", "payload-file", filePath, `Known incident payload filename present: ${base}`));
      scanPayloadHash(filePath, base, advisory, findings);
    }

    if (base === PACKAGE_MANIFEST) {
      seen.manifests += 1;
      scanPackageJson(filePath, advisory, findings, trustSignals);
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
  scanLiteLlmText(filePath, text, findings, "Lockfile");
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
  scanLiteLlmText(filePath, text, findings, "Python dependency file");

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

function scanComposerDependencyFile(filePath, advisory, findings) {
  let text;
  try {
    text = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    findings.push(finding("low", "read-error", filePath, `Could not read Composer dependency file: ${error.message}`));
    return;
  }

  scanIndicatorStrings(filePath, text, advisory, findings, "Composer dependency file");

  for (const [pkg, versions] of Object.entries(advisory.composerPackages || {})) {
    for (const version of versions) {
      if (composerFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-composer-version", filePath, `Composer dependency file references ${pkg}@${version}.`));
      }
    }
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
  scanLiteLlmText(filePath, text, findings, "Tool config");
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
  scanLiteLlmText(filePath, text, findings, "Deployment config");
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
  scanLiteLlmText(filePath, text, findings, "JavaScript source file");
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
  if (/WORKFLOW_ID|REPO_ID_SUFFIX/i.test(text) && /GITHUB_WORKFLOW_REF|GITHUB_REPOSITORY/i.test(text)) {
    findings.push(finding("high", "miasma-github-oidc-targeting-marker", filePath, `${sourceLabel} references targeted GitHub Actions OIDC propagation controls.`));
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

function scanIndicatorStrings(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const stringGroups = [
    ["network-indicator", indicators.networkIndicators],
    ["workflow-indicator", indicators.workflowIndicators],
    ["campaign-indicator", indicators.campaignIndicators],
    ["dprk-npm-rat-indicator", indicators.dprkNpmRatIndicators],
    ["hades-indicator", indicators.hadesIndicators],
    ["ottercookie-indicator", indicators.otterCookieIndicators],
    ["solana-fakefix-indicator", indicators.solanaFakeFixIndicators]
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
  const patterns = [
    new RegExp(`${escapedPkg}[^\\n\\r]{0,120}${escapedVersion}`),
    new RegExp(`${escapedPkg.replace("/", "\\/")}[^\\n\\r]{0,120}${escapedVersion}`),
    new RegExp(`node_modules/${escapedPkg}[^\\n\\r]{0,240}"version"\\s*:\\s*"${escapedVersion}"`)
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
