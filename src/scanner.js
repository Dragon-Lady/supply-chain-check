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
const COMPOSER_DEPENDENCY_FILES = new Set(["composer.json", "composer.lock"]);
const RUBY_DEPENDENCY_FILES = new Set(["Gemfile", "Gemfile.lock"]);
const RUBY_SOURCE_EXTENSIONS = new Set([".rb"]);
const PACKAGE_MANIFEST = "package.json";
const TOOL_CONFIG_FILES = new Set(["settings.json", "settings.local.json", "tasks.json"]);
const JAVASCRIPT_SOURCE_EXTENSIONS = new Set([".js", ".cjs", ".mjs"]);
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);

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
  const seen = { files: 0, manifests: 0, lockfiles: 0 };

  walk(root, (filePath, dirent) => {
    seen.files += 1;
    const base = dirent.name;

    if (payloadFiles.has(base)) {
      findings.push(finding("critical", "payload-file", filePath, `Known incident payload filename present: ${base}`));
      scanPayloadHash(filePath, base, advisory, findings);
    }

    if (base === PACKAGE_MANIFEST) {
      seen.manifests += 1;
      scanPackageJson(filePath, advisory, findings);
      return;
    }

    if (LOCKFILES.has(base)) {
      seen.lockfiles += 1;
      scanTextFile(filePath, advisory, findings);
      return;
    }

    if (isPythonDependencyFile(base)) {
      scanPythonDependencyFile(filePath, advisory, findings);
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

    if (isJavaScriptSourceFile(filePath)) {
      scanJavaScriptSourceFile(filePath, advisory, findings);
    }
  });

  const dedupedFindings = dedupeFindings(findings);
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
      findings: dedupedFindings.length
    },
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

function scanPackageJson(filePath, advisory, findings) {
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
}

function scanTextFile(filePath, advisory, findings) {
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

  for (const [pkg, versions] of Object.entries(advisory.pypiPackages || {})) {
    for (const version of versions) {
      if (pythonFileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-pypi-version", filePath, `Python dependency file references ${pkg}==${version}.`));
      }
    }
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
}

function scanIndicatorStrings(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const stringGroups = [
    ["network-indicator", indicators.networkIndicators],
    ["workflow-indicator", indicators.workflowIndicators],
    ["campaign-indicator", indicators.campaignIndicators],
    ["dprk-npm-rat-indicator", indicators.dprkNpmRatIndicators]
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

function isRubyDependencyFile(filePath, base) {
  return RUBY_DEPENDENCY_FILES.has(base) || path.extname(filePath) === ".gemspec";
}

function isRubySourceFile(filePath) {
  return RUBY_SOURCE_EXTENSIONS.has(path.extname(filePath));
}

function isToolConfigFile(filePath, base) {
  if (!TOOL_CONFIG_FILES.has(base)) return false;
  const normalized = filePath.replace(/\\/g, "/");
  return normalized.includes("/.claude/") || normalized.includes("/.vscode/");
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

module.exports = {
  loadAdvisoryData,
  scanTarget,
  riskLevel
};
