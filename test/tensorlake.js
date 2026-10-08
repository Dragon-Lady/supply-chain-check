"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const check = require("../src/tensorlake");
const pkg = require("../package.json");
const linux = pkg.name === "linux-supply-chain-guard";
const scanner = require(linux ? "../src/checker" : "../src/scanner");
const marker = ["gh-token", "monitor"].join("-");
const canary = "synthetic-private-value-never-print-48317";
let tests = 0;
function test(label, fn) { try { fn(); tests++; } catch (error) { error.message = label + ": " + error.message; throw error; } }
function fixture(fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "tensorlake-test-"));
  const home = path.join(root, "home", "fixture");
  fs.mkdirSync(home, {recursive:true});
  try { fn(root, home); } finally { fs.rmSync(root, {recursive:true, force:true}); }
}
function write(file, content) { fs.mkdirSync(path.dirname(file), {recursive:true}); fs.writeFileSync(file, content, {mode:0o600}); }
function scan(root, home) { return linux ? scanner.scanHost({targetRoot:root, homePath:home, kernelRelease:"9.0.0", architecture:"x64"}) : scanner.scanTarget(home); }
function types(report) { return report.findings.map(f => f.type || f.id); }
function cli(root, home, json) { return runCLI(process["exec" + "Path"], [path.join(__dirname, "..", "bin", pkg.name + ".js"), ...(linux ? [root, "--home", home] : [home]), ...(json ? ["--json"] : [])], {encoding:"utf8", timeout:30000}); }
const metadata = check.exactVersionInMetadata;
const positives = [
  ["package.json", {name:"tensorlake", version:"0.5.144"}],
  ["package.json", {dependencies:{tensorlake:"0.5.144"}}],
  ["package.json", {devDependencies:{alias:"npm:tensorlake@0.5.144"}}],
  ["package-lock.json", {lockfileVersion:3, packages:{"node_modules/tensorlake":{version:"0.5.144"}}}],
  ["package-lock.json", {lockfileVersion:2, packages:{"node_modules/a/node_modules/tensorlake":{version:"0.5.144"}}}],
  ["package-lock.json", {packages:{"node_modules/alias":{name:"tensorlake", version:"0.5.144"}}}],
  ["npm-shrinkwrap.json", {dependencies:{a:{version:"1.0.0", dependencies:{tensorlake:{version:"0.5.144"}}}}}],
  ["package-lock.json", {dependencies:{alias:{version:"npm:tensorlake@0.5.144"}}}],
  ["yarn.lock", 'tensorlake@^0.5.0:\n  version "0.5.144"\n'],
  ["yarn.lock", '"tensorlake@npm:^0.5.0":\n  version: 0.5.144\n  resolution: "tensorlake@npm:0.5.144"\n'],
  ["yarn.lock", '"alias@npm:tensorlake@0.5.144":\n  version "0.5.144"\n'],
  ["yarn.lock", '"alias@npm:tensorlake@^0.5.0":\n  version: 0.5.144\n  resolution: "alias@npm:tensorlake@0.5.144"\n'],
  ["pnpm-lock.yaml", 'packages:\n  /tensorlake/0.5.144:\n    resolution: {}\n'],
  ["pnpm-lock.yaml", "packages:\n  'tensorlake@0.5.144':\n    resolution: {}\n"],
  ["pnpm-lock.yaml", 'snapshots:\n  tensorlake@0.5.144(peer@1.0.0): {}\n'],
];
positives.forEach(([base, data], i) => test("exact metadata " + i, () => assert(metadata(typeof data === "string" ? data : JSON.stringify(data), base))));
const negatives = [
  ["package.json", {name:"tensorlake", version:"0.5.143"}],
  ["package.json", {dependencies:{tensorlake:"0.5.145"}}],
  ["package.json", {dependencies:{tensorlake:"0.5.1440"}}],
  ["package.json", {dependencies:{tensorlake:"^0.5.144"}}],
  ["package.json", {dependencies:{"@other/tensorlake":"0.5.144"}}],
  ["package.json", {description:"tensorlake@0.5.144"}],
  ["package-lock.json", {packages:{"node_modules/not-tensorlake":{version:"0.5.144"}}}],
  ["yarn.lock", 'tensorlake@^0.5.0:\n  version "0.5.143"\nother@1:\n  version "0.5.144"\n'],
  ["yarn.lock", '"@other/tensorlake@^0.5.0":\n  version "0.5.144"\n'],
  ["pnpm-lock.yaml", 'packages:\n  tensorlake@0.5.1440: {}\n'],
  ["pnpm-lock.yaml", 'packages:\n  "@other/tensorlake@0.5.144": {}\n'],
];
negatives.forEach(([base, data], i) => test("negative metadata " + i, () => assert(!metadata(typeof data === "string" ? data : JSON.stringify(data), base))));

test("package alone is exposure evidence, never armed-state proof", () => fixture((root, home) => {
  const file = path.join(home, "project", "package.json");
  write(file, JSON.stringify({dependencies:{tensorlake:"0.5.144"}, description:canary}));
  const report = scan(root, home);
  assert(types(report).includes("tensorlake-exact-version"));
  assert(report.safeRemovalGuidance.required);
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false);
  assert.strictEqual(report.safeRemovalGuidance.activation, "not-assessed");
  assert(!JSON.stringify(report).includes(canary));
  const output = cli(root, home, true);
  assert.strictEqual(output.status, 2, output.stderr);
  assert.strictEqual(JSON.parse(output.stdout).safeRemovalGuidance.sequenceSensitive, false);
}));

test("monitor filename requires response order in text and JSON", () => fixture((root, home) => {
  // Inert fixture: no executable service, shell instructions or token.
  const file = path.join(home, ".config", "systemd", "user", marker + ".service");
  write(file, "[Unit]\nDescription=Inert candidate " + canary + "\n");
  const report = scan(root, home);
  assert(types(report).includes("token-monitor-artifact"));
  assert(report.safeRemovalGuidance.sequenceSensitive);
  assert.strictEqual(report.safeRemovalGuidance.activation, "not-assessed");
  assert(!JSON.stringify(report).includes(canary));
  for (const json of [false, true]) {
    const output = cli(root, home, json);
    assert.strictEqual(output.status, 4, output.stderr);
    assert(!output.stdout.includes(canary));
    assert(/any device/.test(output.stdout));
    if (json) assert(JSON.parse(output.stdout).safeRemovalGuidance.sequenceSensitive);
    else assert(/STOP|Pause and contact incident response/.test(output.stdout));
  }
}));

test("monitor text inside documentation is not an installed monitor", () => fixture((root, home) => {
  write(path.join(home, "README.md"), "Historical reference: " + marker + ".service\n");
  const report = scan(root, home);
  assert(!types(report).includes("token-monitor-artifact"));
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false);
}));

test("benign candidate filename is review only", () => fixture((_root, home) => {
  const file = path.join(home, "setup.mjs"); write(file, "// inert harmless setup\n");
  const findings = check.inspectFile(file);
  assert.strictEqual(findings[0].type, "tensorlake-filename-review");
  assert.strictEqual(findings[0].severity, "medium");
  assert.strictEqual(check.safeRemovalGuidance(findings).required, false);
}));

test("hash evidence does not imply monitor activation", () => fixture((_root, home) => {
  const file = path.join(home, "Math_Symbol.js"); write(file, "// inert digest fixture\n");
  const original = crypto.createHash;
  crypto.createHash = () => ({update() { return this; }, digest() { return "b50a00900399ba99fb6ce1fc151519cb99d44320ef2a631f2237e1aea0ad6fec"; }});
  let findings;
  try { findings = check.inspectFile(file); } finally { crypto.createHash = original; }
  assert.strictEqual(findings[0].type, "tensorlake-payload-hash");
  assert.strictEqual(check.safeRemovalGuidance(findings).sequenceSensitive, false);
  assert.strictEqual(findings[0].evidence.activation, "not-assessed");
}));

test("invalid or oversized metadata reports incomplete without disclosing content", () => fixture((_root, home) => {
  const file = path.join(home, "package.json");
  for (const content of [canary, "null", "[]", " ".repeat(2 * 1024 * 1024 + 1)]) {
    write(file, content);
    const findings = check.inspectFile(file);
    assert.strictEqual(findings[0].type, "tensorlake-coverage-incomplete");
    assert(!JSON.stringify(findings).includes(canary));
    assert.strictEqual(check.safeRemovalGuidance(findings).required, false);
  }
}));

if (process.platform !== "win32") test("symlink candidate is not followed", () => fixture((root, home) => {
  const outside = path.join(root, "private.txt"); write(outside, canary);
  const file = path.join(home, "package.json"); fs.symlinkSync(outside, file);
  const findings = check.inspectFile(file);
  assert.strictEqual(findings[0].type, "tensorlake-coverage-incomplete");
  assert(!JSON.stringify(findings).includes(canary));
}));

test("changed file is incomplete", () => fixture((_root, home) => {
  const file = path.join(home, "package.json"); write(file, '{}');
  const original = fs.readSync; let changed = false;
  fs.readSync = function(...args) { const count = original(...args); if (!changed) { changed = true; fs.appendFileSync(file, " "); } return count; };
  try { assert.strictEqual(check.inspectFile(file)[0].type, "tensorlake-coverage-incomplete"); }
  finally { fs.readSync = original; }
}));

test("inspection does not mutate, execute or contact network", () => fixture((root, home) => {
  const file = path.join(home, "package.json"); write(file, JSON.stringify({name:"tensorlake",version:"0.5.144"}));
  const before = fs.readFileSync(file), stat = fs.statSync(file), restores = [], attempted = [];
  function block(object, key) {
    const old = object[key]; if (typeof old !== "function") return;
    object[key] = () => { attempted.push(key); throw Error("forbidden action"); };
    restores.push(() => { object[key] = old; });
  }
  for (const key of ["exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork"]) block(require(["child", "process"].join("_")), key);
  for (const module of ["http", "https"]) for (const key of ["get", "request"]) block(require(module), key);
  block(require("net"), "connect"); block(require("net"), "createConnection"); block(global, "fetch");
  for (const key of ["writeFileSync", "appendFileSync", "rmSync", "unlinkSync", "renameSync", "mkdirSync", "chmodSync"]) block(fs, key);
  try { assert(types(scan(root, home)).includes("tensorlake-exact-version")); }
  finally { restores.reverse().forEach(restore => restore()); }
  assert.deepStrictEqual(attempted, []);
  assert(fs.readFileSync(file).equals(before));
  const after = fs.statSync(file);
  for (const key of ["size", "mode", "ino", "mtimeMs"]) assert.strictEqual(after[key], stat[key]);
}));
test("incomplete candidate produces a non-success CLI result", () => fixture((root, home) => {
  write(path.join(home, "package.json"), "null");
  const output = cli(root, home, true);
  assert.strictEqual(output.status, linux ? 1 : 3, output.stderr);
  const report = JSON.parse(output.stdout);
  assert(types(report).includes("tensorlake-coverage-incomplete"));
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false);
}));

if (linux) test("a directory alone does not establish a sequence-sensitive monitor", () => fixture((root, home) => {
  fs.mkdirSync(path.join(home, ".config", marker), {recursive:true});
  const report = scan(root, home);
  assert(types(report).includes("known-supply-chain-persistence-path"));
  assert(!types(report).includes("token-monitor-artifact"));
  assert.strictEqual(report.safeRemovalGuidance.sequenceSensitive, false);
}));

console.log(`${tests} Tensorlake metadata, response-order, CLI, privacy and passive-scan tests passed`);
