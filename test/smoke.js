const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { scanTarget } = require("../src/scanner");

function makeFixture(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function write(filePath, content) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content);
}

const cleanRoot = makeFixture("scc-clean-");
try {
  write(
    path.join(cleanRoot, "package.json"),
    JSON.stringify({ name: "clean-fixture", version: "1.0.0", dependencies: { leftpad: "1.0.0" } }, null, 2)
  );
  const clean = scanTarget(cleanRoot);
  assert.strictEqual(clean.risk, "no-known-indicators");
  assert.strictEqual(clean.findings.length, 0);
} finally {
  fs.rmSync(cleanRoot, { recursive: true, force: true });
}

const dprkRoot = makeFixture("scc-dprk-rat-");
try {
  write(
    path.join(dprkRoot, "package.json"),
    JSON.stringify({
      name: "dprk-fixture",
      version: "1.0.0",
      dependencies: {
        "terminal-logger-utils": "1.0.0"
      },
      scripts: {
        postinstall: "node utils.cjs"
      }
    }, null, 2)
  );
  write(path.join(dprkRoot, "package-lock.json"), "node_modules/pretty-logger-utils\n/api/validate/keyboard-events\n");
  write(path.join(dprkRoot, "utils.cjs"), "const pwdKeyString = ''; // Telegram Desktop MicrosoftSystem64\n");

  const report = scanTarget(dprkRoot);
  assert.strictEqual(report.risk, "likely-exposed");
  assert(report.findings.some((finding) => finding.type === "known-bad-requested-version"));
  assert(report.findings.some((finding) => finding.type === "known-bad-lockfile-package"));
  assert(report.findings.some((finding) => finding.type === "dprk-npm-rat-postinstall"));
  assert(report.findings.some((finding) => finding.type === "dprk-npm-rat-indicator"));
} finally {
  fs.rmSync(dprkRoot, { recursive: true, force: true });
}

const reviewRoot = makeFixture("scc-review-");
try {
  write(
    path.join(reviewRoot, "package.json"),
    JSON.stringify({
      name: "review-fixture",
      version: "1.0.0",
      scripts: {
        prepare: "npm run build"
      },
      dependencies: {
        "some-tool": "github:example/repo#abcdef"
      }
    }, null, 2)
  );

  const report = scanTarget(reviewRoot);
  assert.strictEqual(report.risk, "review-needed");
  assert(report.findings.some((finding) => finding.type === "lifecycle-script"));
  assert(report.findings.some((finding) => finding.type === "github-dependency"));
} finally {
  fs.rmSync(reviewRoot, { recursive: true, force: true });
}

console.log("smoke tests passed");
