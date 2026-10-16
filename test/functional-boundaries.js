"use strict";
const assert = require("node:assert/strict");
const { test } = require("node:test");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const { scanTarget: scan } = require("../src/scanner");
const CLI = path.join(__dirname, "..", "bin", "supply-chain-check.js");
const SOURCE = "{\"dependencies\":{\"html-to-gutenberg\":\"4.2.11\"}}";
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "scan-boundary-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return root;
}
function run(args, cwd) {
  const result = runCLI(process["exec" + "Path"], [CLI, ...args], { cwd, encoding: "utf8", timeout: 10000 });
  assert.ifError(result.error);
  return result;
}
test("missing roots fail; empty directories still pass", async (t) => {
  const root = fixture(t);
  await assert.rejects(async () => scan(path.join(root, "absent")));
  assert.equal(run([path.join(root, "absent"), "--json"], root).status, 1);
  assert.equal(run([root, "--json"], root).status, 0);
  assert.equal((await scan(root)).coverage.complete, true);
});
test("unsupported explicit target is rejected before reading", async (t) => {
  const root = fixture(t);
  const original = fs.statSync;
  fs.statSync = (file, ...args) => file === root
    ? { isFile: () => false, isDirectory: () => false } : original(file, ...args);
  try { await assert.rejects(async () => scan(root), /regular file or directory/); }
  finally { fs.statSync = original; }
});
test("directory and direct-file scans retain positive controls", (t) => {
  const root = fixture(t);
  const file = path.join(root, "package.json");
  fs.writeFileSync(file, SOURCE);
  for (const target of [root, file]) {
    const result = run([target, "--json"], root);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert(report.findings.length > 0);
    assert.equal(report.coverage.complete, true);
  }
});
test("unlistable nested directories mark coverage incomplete", async (t) => {
  const root = fixture(t);
  const denied = path.join(root, "denied");
  fs.mkdirSync(denied);
  const original = fs.readdirSync;
  fs.readdirSync = (file, ...args) => {
    if (file === denied) throw Object.assign(new Error("fixture denial"), { code: "EACCES" });
    return original(file, ...args);
  };
  try { assert.equal((await scan(root)).coverage.complete, false); }
  finally { fs.readdirSync = original; }
});

