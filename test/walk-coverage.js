"use strict";
// Regression: build-output directory names are only skipped in the project
// itself, never inside installed dependencies, and unreadable directories are
// reported instead of silently skipped.
const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");
const { spawnSync: runCLI } = require(["child", "process"].join("_"));
const CLI = path.join(__dirname, "..", "bin", "supply-chain-check.js");

let tests = 0;
const INDICATOR = "hades-pth-startup-hook-file";

function fixture() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "scc-walk-"));
}

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

function types(report) {
  return new Set(report.findings.map((item) => item.type));
}

for (const dir of ["dist", "build", "coverage", ".next"]) {
  const root = fixture();
  try {
    write(path.join(root, "node_modules", "some-package", dir, "loader-setup.pth"), "import os\n");
    assert(types(scanTarget(root)).has(INDICATOR), `node_modules/*/${dir} must be scanned`);
    write(path.join(root, "node_modules", "@scope", "pkg", "node_modules", "inner", dir, "x", "loader-setup.pth"), "import os\n");
    assert(scanTarget(root).findings.filter((item) => item.type === INDICATOR).length === 2);
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

for (const dir of ["dist", "build"]) {
  // Scanning an installed package directly (node_modules/<pkg>, or a symlink
  // to it) must still walk its build output.
  const root = fixture();
  try {
    const pkg = path.join(root, "node_modules", "some-package");
    write(path.join(pkg, dir, "loader-setup.pth"), "import os\n");
    assert(types(scanTarget(pkg)).has(INDICATOR), `direct scan of node_modules/<pkg>/${dir} must find the indicator`);
    const link = path.join(root, "pkg-link");
    fs.symlinkSync(pkg, link);
    assert(types(scanTarget(link)).has(INDICATOR), "symlinked package root must be treated the same");
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

{
  // Project-level build output keeps the existing skip.
  const root = fixture();
  try {
    write(path.join(root, "dist", "loader-setup.pth"), "import os\n");
    assert(!types(scanTarget(root)).has(INDICATOR));
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

if (typeof process.getuid !== "function" || process.getuid() !== 0) {
  const root = fixture();
  const locked = path.join(root, "locked");
  try {
    write(path.join(locked, "package.json"), "{}");
    fs.chmodSync(locked, 0o000);
    const report = scanTarget(root);
    assert(report.findings.some((item) => item.type === "read-error" && item.severity === "low" && item.path === locked),
      "an unreadable directory must be reported");
    assert.strictEqual(report.coverage.complete, false);
    assert.strictEqual(report.coverage.unlistableDirectories, 1);
    const result = runCLI(process["exec" + "Path"], [CLI, root, "--json"], { encoding: "utf8" });
    assert.strictEqual(result.status, 3, `unlistable directory must exit 3, got ${result.status}`);
    const text = runCLI(process["exec" + "Path"], [CLI, root], { encoding: "utf8" });
    assert.strictEqual(text.status, 3);
    assert(text.stdout.includes("Coverage: INCOMPLETE - 1 directory could not be listed"));
    tests += 1;
  } finally {
    fs.chmodSync(locked, 0o700);
    fs.rmSync(root, { recursive: true, force: true });
  }
}

{
  // A fully listable tree stays complete and exits 0.
  const root = fixture();
  try {
    write(path.join(root, "package.json"), "{}");
    const report = scanTarget(root);
    assert.strictEqual(report.coverage.complete, true);
    assert.strictEqual(report.coverage.unlistableDirectories, 0);
    assert.strictEqual(runCLI(process["exec" + "Path"], [CLI, root, "--json"], { encoding: "utf8" }).status, 0);
    tests += 1;
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

console.log(`${tests} walk coverage tests passed`);
