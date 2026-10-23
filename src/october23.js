"use strict";
// Offline, bounded inspection. Never import or execute inspected files.
const fs = require("fs");
const path = require("path");
const {incidentalJson} = require("./metadata-scope");
const SOURCES = {
  worm: "https://safedep.io/testmetest-npm-worm-miasma-variant/",
  litellm: "https://docs.litellm.ai/blog/security-incident-oct-21-2026",
  dropper: "https://safedep.io/hugo-paper-mevn-cli-forged-commit-preinstall-dropper/"
};
// Only versions explicitly classified malicious in the dated research table.
const BAD_NPM = {
  "event-bus-lite-testmetest": ["0.0.1"],
  "data-pipeline-testmetest": ["2.0.1"],
  "event-emitter-testmetest": ["1.0.7", "4.1.0", "5.0.0"],
  "test-brotli-testmetest": ["1.0.0"],
  "pixel-map-testmetest": ["0.0.1", "0.0.2"],
  "net-codec-testmetest": ["1.0.1"],
  "log-rotate-testmetest": ["1.0.1"]
};
const NPM_FILES = new Set(["package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]);
const PYTHON_FILES = new Set(["requirements.txt", "pyproject.toml", "uv.lock", "poetry.lock", "Pipfile.lock", "METADATA", "PKG-INFO"]);
const CONTAINER_FILES = new Set(["Dockerfile", "compose.yml", "compose.yaml", "docker-compose.yml", "docker-compose.yaml"]);
const STARTUP_FILES = new Set(["cook.pth", "cook.py", "sitecustomize.py"]);
const SERVICE_FILES = new Set(["net-health-checker.service", "pkg-runtime.service", "net-health-checker.sh", "com.user.net-health-checker.plist", "com.user.pkg-runtime.plist"]);
const ORDER = "If execution is possible, preserve evidence and have incident response assess and safely stop the token-revocation wiper before revoking or rotating credentials from any device. A match does not prove execution or an armed wiper. This scanner makes no changes.";
const LITELLM_ORDER = "Do not start Python or pip in a suspected affected environment: startup hooks can run before imports. Preserve evidence and contain/rebuild the environment; rotate exposed credentials from a clean device after containment. A metadata match does not establish execution.";
const DIGEST = "1bbcb1443bc962e45f5aad53fe3d2c30600e0379715fb6c664cdd3ac126c339e";
const within = (root, file) => { const relative = path.relative(path.resolve(root), path.resolve(file)); return relative === "" || (!relative.startsWith(".." + path.sep) && relative !== ".." && !path.isAbsolute(relative)); };
const escape = value => value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
function candidate(file) {
  const base = path.basename(file);
  return NPM_FILES.has(base) || PYTHON_FILES.has(base) || CONTAINER_FILES.has(base) || STARTUP_FILES.has(base) || SERVICE_FILES.has(base) || base === "binding.gyp" || base === "preinstall.js";
}
function finding(file, severity, type, message, source) {
  return {severity, type, path:file, message, evidence:{source, lastVerified:"2026-10-23", activation:"not-assessed"}};
}
function incomplete(file) {
  return finding(file, "medium", "october23-coverage-incomplete", "October 23 candidate inspection was incomplete (unreadable, malformed, linked, changed, or over budget). Content and error details are withheld.", SOURCES.worm);
}
function read(file, root) {
  if (fs.lstatSync(file).isSymbolicLink()) throw Error("linked candidate");
  if (root && (!within(root, file) || (path.resolve(root) !== path.resolve(file) && !within(fs.realpathSync(root), fs.realpathSync(path.dirname(file)))))) throw Error("outside scope");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW || 0) | (fs.constants.O_NONBLOCK || 0));
  try {
    const before = fs.fstatSync(fd);
    const limit = NPM_FILES.has(path.basename(file)) ? 32 * 1024 * 1024 : 2 * 1024 * 1024;
    if (!before.isFile() || before.size > limit) throw Error("budget");
    const buffer = Buffer.alloc(before.size); let offset = 0;
    while (offset < buffer.length) { const n = fs.readSync(fd, buffer, offset, buffer.length-offset, offset); if (!n) throw Error("changed"); offset += n; }
    const after = fs.fstatSync(fd);
    if (before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) throw Error("changed");
    return buffer.toString("utf8");
  } finally { fs.closeSync(fd); }
}
function npmMatches(text, base) {
  const matches = new Set();
  const add = (name, version) => { if (Object.hasOwn(BAD_NPM, name) && BAD_NPM[name].includes(version)) matches.add(`${name}@${version}`); };
  const alias = value => { if (typeof value !== "string") return; const m = value.match(/^npm:([^@]+)@([^\s]+)$/); if (m) add(m[1], m[2]); };
  if (base.endsWith(".json")) {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) throw Error("metadata");
    add(data.name, data.version);
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      for (const [name, value] of Object.entries(data[section] || {})) { add(name,value); alias(value); }
    }
    for (const [key, value] of Object.entries(data.packages || {})) {
      const name = value?.name || key.match(/(?:^|\/)node_modules\/([^/]+)$/)?.[1];
      add(name, value?.version); alias(value?.version);
    }
    const pending = [data.dependencies]; let count = 0;
    while (pending.length && count++ < 100000) {
      const deps = pending.pop(); if (!deps || typeof deps !== "object") continue;
      for (const [name,value] of Object.entries(deps)) {
        if (!value || typeof value !== "object") continue;
        add(name,value.version); alias(value.version); if (value.dependencies) pending.push(value.dependencies);
      }
    }
    if (pending.length) throw Error("budget");
  } else {
    for (const [name, versions] of Object.entries(BAD_NPM)) for (const version of versions) {
      const n=escape(name), v=escape(version);
      if (base === "pnpm-lock.yaml" && new RegExp(`^\\s*['"]?\\/?${n}(?:@|/)${v}(?:\\([^\\r\\n]*\\))?['"]?:\\s*(?:\\{\\})?\\s*$`, "m").test(text)) add(name,version);
      if (base === "yarn.lock") for (const block of text.split(/(?=^\S)/m)) {
        const key = block.split(/\r?\n/,1)[0];
        if (new RegExp(`(?:^|,\\s*)["']?(?:${n}@|[^@,\\s"']+@npm:${n}@)`).test(key) && new RegExp(`^\\s+version\\s*:?[ \\t]+["']?${v}["']?\\s*$`,"m").test(block)) add(name,version);
      }
    }
  }
  return [...matches];
}
function pythonMatch(text, base) {
  if (base === "METADATA" || base === "PKG-INFO") return /^Name:\s*litellm\s*$/mi.test(text) && /^Version:\s*1\.107\.0\s*$/mi.test(text);
  if (base === "requirements.txt") return /^\s*litellm(?:\[[^\]\r\n]+\])?\s*==\s*1\.107\.0(?=\s*(?:;|#|--hash|$))/mi.test(text);
  if (base === "Pipfile.lock") { const data=JSON.parse(text); return [data.default,data.develop].some(section=>section?.litellm?.version === "==1.107.0"); }
  // Limit TOML matching to dependency strings or a single package table.
  const clean = text.split(/\r?\n/).filter(line=>!/^\s*#/.test(line)).join("\n");
  if (base === "pyproject.toml") {
    const project = clean.match(/(?:^|\n)\[project\]\s*\n([\s\S]*?)(?=\n\[|$)/)?.[1] || "";
    const dependencies = project.match(/(?:^|\n)dependencies\s*=\s*\[([\s\S]*?)\]/)?.[1] || "";
    if (/["']litellm\s*==\s*1\.107\.0(?:\s*;[^"']*)?["']/i.test(dependencies)) return true;
    const poetry = clean.match(/(?:^|\n)\[tool\.poetry\.dependencies\]\s*\n([\s\S]*?)(?=\n\[|$)/)?.[1] || "";
    return /^\s*litellm\s*=\s*["'](?:==)?1\.107\.0["']\s*$/mi.test(poetry);
  }
  return clean.split(/(?=^\[\[package\]\])/m).map(block=>block.split(/\n\[/,1)[0]).some(block=>/^\[\[package\]\]/.test(block) && /^name\s*=\s*["']litellm["']\s*$/mi.test(block) && /^version\s*=\s*["']1\.107\.0["']\s*$/m.test(block));
}
function inspectFile(file, options={}) {
  if (!candidate(file)) return [];
  const base=path.basename(file), out=[];
  const emit=(severity,type,message,source=SOURCES.worm)=>out.push(finding(file,severity,type,message,source));
  try {
    const text=read(file,options.root);
    if (NPM_FILES.has(base)) {
      try {
        for (const match of npmMatches(text,base)) emit("critical","testmetest-exact-version",`Exact dependency metadata matches the reported malicious release ${match}. ${ORDER}`);
      } catch (error) {
        if (error instanceof SyntaxError && incidentalJson(file,options.root) && !/testmetest|\\[ux]/i.test(text))
          emit("low","october23-incidental-json","Malformed JSON in an incidental test/example/generated path was not parsed. It is not treated as an active dependency manifest; valid metadata in these paths is still inspected.");
        else throw error;
      }
    }
    if (PYTHON_FILES.has(base) && pythonMatch(text,base)) emit("critical","litellm-october-compromised-version",`LiteLLM 1.107.0 metadata matches the October 21 compromised release. ${LITELLM_ORDER}`,SOURCES.litellm);
    if (base === "binding.gyp" && /<!\([^\r\n)]*\bnode\s+(?:\.\/)?index\.js\b[^\r\n)]*\)/.test(text)) emit("high","testmetest-gyp-loader-review",`Build metadata invokes an index.js loader using command expansion, consistent with the reported worm trigger. Legitimate builds can also execute commands; review context. ${ORDER}`);
    if (SERVICE_FILES.has(base)) {
      const correlated = /net-health-checker|\.local\/share\/runtimes|sync\.py|msync-3f7a|aiarmor\.website/.test(text);
      emit(correlated?"high":"medium","testmetest-persistence-review",`A reported persistence filename is present${correlated?" with related service or payload terms":"; filename alone is not proof of compromise"}. ${ORDER}`);
    }
    if (STARTUP_FILES.has(base)) {
      const correlated = /\bcook\b/.test(text) && /litellm\.dev|remote_code_loader|XWiA8gZNa7NcX2XRoAEb|letters9813/.test(text);
      if (correlated || base === "cook.pth") emit(correlated?"high":"medium","litellm-startup-review",`Python startup artifact requires review${correlated?"; reported payload terms co-occur":"; filename alone is not proof of compromise"}. ${LITELLM_ORDER}`,SOURCES.litellm);
    }
    if (CONTAINER_FILES.has(base)) {
      for (const match of text.matchAll(/^\s*(?:image:\s*|FROM\s+(?:--platform=\S+\s+)?)["']?((?:ghcr\.io\/berriai\/litellm(?:-database|-non_root)?|(?:docker\.io\/)?litellm\/litellm)(?::[^\s"'#]+|@sha256:[a-f0-9]{64}))(?=[\s"'#]|$)/gmi)) {
        const image=match[1];
        if (image.endsWith("@sha256:"+DIGEST)) emit("critical","litellm-container-digest",`Container configuration references the confirmed compromised image digest. This does not prove a pull or execution. ${LITELLM_ORDER}`,SOURCES.litellm);
        else if (/:(?:v1\.107\.0|latest|main-latest|main-stable)$/.test(image)) emit("medium","litellm-container-window-review","Review the image digest and pull history for October 21, 2026 (11:46–14:20 UTC). These tags were affected during that window; a tag now is not proof of compromise. Do not start the image to investigate.",SOURCES.litellm);
      }
    }
    if (base === "preinstall.js" && /https?:\/\/buildwithknexus\.xyz\/(?:check_m|check_w)\b/.test(text)) emit("high","forged-preinstall-endpoint","A reported forged-commit downloader endpoint occurs in an install-script candidate. Do not execute it; inspect source history and contain the environment if it ran. Text alone does not prove execution.",SOURCES.dropper);
  } catch (_) { out.push(incomplete(file)); }
  return out;
}
function safeRemovalGuidance(findings, fallback) {
  if (!findings.some(f=>/^testmetest-/.test(f.type||f.id||""))) return fallback;
  return {required:true, sequenceSensitive:true, activation:"not-assessed", firstAction:ORDER, instructionDestination:SOURCES.worm};
}
function discover(root, options={}) {
  const files=[], findings=[], stack=[root]; let visited=0;
  const maxEntries = options.maxEntries || 100000;
  let discoveryIncomplete = false;
  const excluded=(options.excludePaths||[]).map(p=>path.resolve(p));
  while (stack.length) {
    if (++visited > maxEntries) { discoveryIncomplete = true; break; }
    const current=stack.pop();
    if (excluded.some(p=>within(p,current))) continue;
    try {
      const stat=fs.lstatSync(current);
      if (stat.isSymbolicLink()) { discoveryIncomplete = true; continue; }
      if (stat.isDirectory()) {
        if ([".git",".hg",".svn",".next","dist","build","coverage"].includes(path.basename(current))) continue;
        const dir = fs.opendirSync(current);
        try {
          let entry;
          while ((entry = dir.readSync())) {
            if (visited + stack.length >= maxEntries) { discoveryIncomplete = true; break; }
            stack.push(path.join(current,entry.name));
          }
        } finally { dir.closeSync(); }
      } else if (candidate(current)) files.push(current);
    } catch (_) { discoveryIncomplete = true; }
  }
  if (discoveryIncomplete) findings.push(incomplete(root));
  return {files,findings};
}
module.exports={inspectFile,discover,safeRemovalGuidance,npmMatches,pythonMatch,SOURCES,ORDER};
