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
const PACKAGE_MANIFEST = "package.json";
const LIFECYCLE_SCRIPTS = ["preinstall", "install", "postinstall", "prepare"];
const SKIP_DIRS = new Set([".git", ".hg", ".svn", ".next", "dist", "build", "coverage"]);

const DEFAULT_ADVISORY = {
  indicators: {
    maliciousOptionalDependencyName: "@tanstack/setup",
    maliciousOptionalDependencySpec: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
    payloadFiles: ["router_init.js", "tanstack_runner.js", "router_runtime.js"],
    payloadFileHashes: {
      "router_init.js": [
        "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c",
        "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
      ],
      "router_runtime.js": [
        "ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c"
      ],
      "tanstack_runner.js": [
        "2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96"
      ]
    }
  },
  packages: {}
};

function loadAdvisoryData() {
  const dataPath = path.join(__dirname, "..", "data", "affected-packages.json");
  try {
    const raw = JSON.parse(fs.readFileSync(dataPath, "utf8"));
    return normalizeAdvisory(raw);
  } catch (error) {
    if (error.code === "ENOENT") return DEFAULT_ADVISORY;
    return DEFAULT_ADVISORY;
  }
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
    }
  });

  const dedupedFindings = dedupeFindings(findings);
  const risk = riskLevel(dedupedFindings);
  return {
    tool: "tanstack-incident-scanner",
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

  if (manifest.name && manifest.version && advisory.packages[manifest.name]?.includes(manifest.version)) {
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
      const severity = scriptName === "prepare" && /bun\s+run|router_|tanstack_/i.test(scripts[scriptName]) ? "high" : "medium";
      findings.push(finding(severity, "lifecycle-script", filePath, `Lifecycle script "${scriptName}" is present: ${scripts[scriptName]}`));
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
    packages: {}
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

  if (spec.includes(indicators.maliciousOptionalDependencySpec)) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, `${section}.${name} points to the known malicious GitHub commit.`));
  }

  if (/^github:/i.test(spec) || /github\.com[:/]/i.test(spec)) {
    const severity = section === "optionalDependencies" ? "high" : "medium";
    findings.push(finding(severity, "github-dependency", filePath, `${section}.${name} resolves from GitHub: ${spec}`));
  }

  if (advisory.packages[name]?.includes(spec)) {
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

  if (text.includes(indicators.maliciousOptionalDependencySpec)) {
    findings.push(finding("critical", "malicious-dependency-spec", filePath, "Lockfile references the known malicious GitHub commit."));
  }

  for (const [pkg, versions] of Object.entries(advisory.packages)) {
    for (const version of versions) {
      if (lockfileMentionsPackageVersion(text, pkg, version)) {
        findings.push(finding("critical", "known-bad-lockfile-version", filePath, `Lockfile references ${pkg}@${version}.`));
      }
    }
  }
}

function scanIndicatorStrings(filePath, text, advisory, findings, sourceLabel) {
  const indicators = advisory.indicators || {};
  const stringGroups = [
    ["network-indicator", indicators.networkIndicators],
    ["workflow-indicator", indicators.workflowIndicators],
    ["campaign-indicator", indicators.campaignIndicators]
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
      "Stop installs, builds, and dev servers in the affected environment.",
      "If payload execution is possible, isolate the host from the network before cleanup.",
      "Do not revoke tokens from the suspected infected host first.",
      "Rotate GitHub, npm, cloud, Vault, Kubernetes, SSH, and CI secrets from a clean machine.",
      "Treat confirmed execution or credential access as a host compromise and rebuild from a clean baseline."
    ];
  }

  if (risk === "possible-exposure" || risk === "review-needed") {
    return [
      "Review findings before running more package installs.",
      "Prefer npm ci --ignore-scripts or equivalent script-blocking controls until dependency state is verified.",
      "Pin away from known-bad package versions and regenerate lockfiles from a clean environment."
    ];
  }

  return [
    "No known TanStack incident indicators were found by this scanner.",
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
