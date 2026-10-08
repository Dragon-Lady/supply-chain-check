"use strict";
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawnSync: runFixture } = require(["child", "process"].join("_"));

const TOOL = "supply-chain-check";
const ERROR_EXIT = 1;
const CLI = path.join(__dirname, "..", "bin", `${TOOL}.js`);
let tests = 0;
function run(root, home, report) {
  const args = [CLI, root, "--json", "--report", report];
  if (TOOL === "linux-supply-chain-guard") args.push("--home", home);
  const result = runFixture(process["exec" + "Path"], args, { encoding: "utf8" });
  assert.ifError(result.error);
  return result;
}
function snapshot(target) {
  const info = fs.statSync(target);
  return { bytes: fs.readFileSync(target).toString("hex"), size: info.size, mtimeMs: info.mtimeMs, mode: info.mode, ino: info.ino };
}
for (const alias of ["same", "symlink", "hardlink", "parent-symlink", "parent-dotdot", "dangling-symlink", "unrelated-existing", "new-private"]) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "report-preservation-"));
  try {
    const home = path.join(root, "home", "fixture");
    fs.mkdirSync(home, { recursive: true });
    const target = path.join(home, "package.json");
    fs.writeFileSync(target, JSON.stringify({ name: "ordinary-fixture", version: "1.0.0" }));
    let report = target;
    if (alias === "symlink") {
      report = path.join(root, "report-link"); fs.symlinkSync(target, report);
    } else if (alias === "hardlink") {
      report = path.join(root, "report-hardlink"); fs.linkSync(target, report);
    } else if (alias === "parent-symlink") {
      const parent = path.join(root, "folder-link"); fs.symlinkSync(home, parent, "dir"); report = path.join(parent, "package.json");
    } else if (alias === "parent-dotdot") {
      const inner = path.join(home, "inner"); fs.mkdirSync(inner); report = path.join(inner, "..", "package.json");
    } else if (alias === "dangling-symlink") {
      report = path.join(root, "dangling-report"); fs.symlinkSync(path.join(root, "nonexistent"), report);
    } else if (alias === "unrelated-existing") {
      report = path.join(root, "report.json"); fs.writeFileSync(report, "previous report");
    } else if (alias === "new-private") {
      report = path.join(root, "new-report.json");
    }
    const before = snapshot(target);
    const oldUmask = process.umask(0);
    let result;
    try { result = run(root, home, report); } finally { process.umask(oldUmask); }
    assert.deepStrictEqual(snapshot(target), before);
    if (alias === "new-private") {
      assert([0, 1].includes(result.status));
      assert.strictEqual(result.stderr, "");
      assert.strictEqual(fs.statSync(report).mode & 0o777, 0o600);
      assert.strictEqual(JSON.parse(fs.readFileSync(report, "utf8")).tool, TOOL);
    } else {
      assert.strictEqual(result.status, ERROR_EXIT);
      assert(/already exists/.test(result.stderr));
      if (alias === "unrelated-existing") assert.strictEqual(fs.readFileSync(report, "utf8"), "previous report");
      if (alias === "dangling-symlink") assert(!fs.existsSync(path.join(root, "nonexistent")));
    }
    tests += 1;
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
}
console.log(`${tests} report preservation and private-creation CLI tests passed`);
