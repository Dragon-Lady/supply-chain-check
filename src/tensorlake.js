"use strict";
// Static inspection only. Never load the inspected file as a module.
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const SOURCE = "https://www.stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm";
const MAX_BYTES = 2 * 1024 * 1024;
const MONITOR = ["gh-token", "monitor"].join("-");
const MONITOR_FILES = new Set([`${MONITOR}.service`, `${MONITOR}.sh`, `com.user.${MONITOR}.plist`]);
const HASHES = {
  __proto__: null,
  "setup.mjs": "25a0735d0db7dc40e5d45ce42d9c106067e6a66e184d967cfecfab17c3bcb5ef",
  "Math_Symbol.js": "b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec"
};
const METADATA = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]);
const ORDER = "If this code ran, preserve evidence and use incident response to assess and stop the token monitor before revoking credentials from any device. Rotate exposed credentials afterward from a clean device. This scanner does not execute, stop, remove, or revoke anything.";

function exactVersionInMetadata(text, base) {
  if (base.endsWith(".json")) {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) throw Error("invalid metadata");
    if (data.name === "tensorlake" && data.version === "0.5.144") return true;
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, value] of Object.entries(data[section] || {})) {
        if (name === "tensorlake" && value === "0.5.144") return true;
        if (value === "npm:tensorlake@0.5.144") return true;
      }
    }
    for (const [key, value] of Object.entries(data.packages || {})) {
      if ((/(?:^|\/)node_modules\/tensorlake$/.test(key) || value?.name === "tensorlake") && value?.version === "0.5.144") return true;
    }
    // npm lockfile v1 nests dependency records; only follow that structure.
    const pending = [data.dependencies];
    let visited = 0;
    while (pending.length && visited++ < 100000) {
      const deps = pending.pop();
      if (!deps || typeof deps !== "object") continue;
      for (const [name, value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        if ((name === "tensorlake" && value.version === "0.5.144") || value.version === "npm:tensorlake@0.5.144") return true;
        if (value.dependencies) pending.push(value.dependencies);
      }
    }
    if (pending.length) throw Error("metadata traversal limit");
    return false;
  }
  if (base === "pnpm-lock.yaml") {
    // pnpm v5 /name/version and v6-v9 name@version package/snapshot keys.
    return /^\s*['"]?\/?tensorlake(?:@|\/)0\.5\.144(?:\([^\r\n]*\))?['"]?:\s*(?:\{\})?\s*$/m.test(text);
  }
  if (base === "yarn.lock") {
    const blocks = text.split(/(?=^\S)/m);
    return blocks.some(block => {
      const first = block.split(/\r?\n/, 1)[0];
      const tensorlakeKey = /(?:^|,\s*)["']?(?:tensorlake@|[^@,\s"']+@npm:tensorlake@)/.test(first);
      const resolved = /^\s+version\s*:?[ \t]+["']?0\.5\.144["']?\s*$/m.test(block);
      const berryAlias = /^\s+resolution:\s*["']?(?:tensorlake@npm:0\.5\.144|[^@\s"']+@npm:tensorlake@0\.5\.144)["']?\s*$/m.test(block);
      return (tensorlakeKey && resolved) || berryAlias;
    });
  }
  return false;
}

function readLimited(filePath) {
  if (fs.lstatSync(filePath).isSymbolicLink()) throw Error("symlink candidate");
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > MAX_BYTES) throw Error("unsupported or oversized file");
    const data = Buffer.alloc(before.size);
    let offset = 0;
    while (offset < data.length) {
      const count = fs.readSync(fd, data, offset, data.length - offset, offset);
      if (!count) throw Error("file changed during read");
      offset += count;
    }
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw Error("file changed during read");
    return data;
  } finally { fs.closeSync(fd); }
}

function inspectFile(filePath, options = {}) {
  const base = path.basename(filePath);
  const make = (severity, type, message) => ({severity, type, path:filePath, message, evidence:{source:SOURCE, lastVerified:"2026-10-08", activation:"not-assessed"}});
  if (MONITOR_FILES.has(base.toLowerCase())) {
    return [make("critical", "token-monitor-artifact", "A local path matches reported token-monitor persistence. This is a sequence-sensitive candidate, not proof of an installed or armed switch. " + ORDER)];
  }
  if (!HASHES[base] && !(options.packages !== false && METADATA.has(base))) return [];
  try {
    const data = readLimited(filePath);
    if (HASHES[base]) {
      if (crypto.createHash("sha256").update(data).digest("hex") === HASHES[base]) {
        return [make("critical", "tensorlake-payload-hash", `${base} byte-matches a reported tensorlake@0.5.144 payload. Execution and monitor activation are not established. ${ORDER}`)];
      }
      return [make("medium", "tensorlake-filename-review", `${base} is a reported Tensorlake payload name, but its hash does not match this incident. A filename alone does not establish compromise.`)];
    }
    return exactVersionInMetadata(data.toString("utf8"), base)
      ? [make("critical", "tensorlake-exact-version", "Exact npm tensorlake@0.5.144 metadata matches the October 2026 compromise. A package reference does not prove execution or an armed switch. " + ORDER)] : [];
  } catch (_error) {
    return [make("medium", "tensorlake-coverage-incomplete", "Tensorlake inspection could not read or parse this candidate within its 2 MiB limit; coverage is incomplete. File content and error details are withheld.")];
  }
}

function safeRemovalGuidance(findings) {
  const sequenceSensitive = findings.some(f => (f.type || f.id) === "token-monitor-artifact");
  const incident = findings.some(f => ["tensorlake-exact-version", "tensorlake-payload-hash"].includes(f.type || f.id));
  return {required:sequenceSensitive || incident, sequenceSensitive, activation:"not-assessed", firstAction:sequenceSensitive
    ? "STOP: Do not revoke or rotate credentials from any device until incident response assesses and safely disarms the suspected token monitor. A filename match does not prove it is armed."
    : incident ? ORDER : "No Tensorlake or token-monitor indicators were observed in the supported scan scope; this is not a host all-clear.", instructionDestination:SOURCE};
}
module.exports = {inspectFile, safeRemovalGuidance, exactVersionInMetadata};
