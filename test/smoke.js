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

const stagedPublishRoot = makeFixture("scc-staged-publish-");
try {
  write(
    path.join(stagedPublishRoot, "pnpm-lock.yaml"),
    [
      "packages:",
      "  leftpad@1.0.0:",
      "    resolution:",
      "      integrity: sha512-test",
      "    registryMeta:",
      "      approver: tanya",
      ""
    ].join("\n")
  );
  write(
    path.join(stagedPublishRoot, "package.json"),
    JSON.stringify({
      name: "staged-publish-fixture",
      version: "1.0.0",
      scripts: {
        release: "npm stage publish"
      }
    }, null, 2)
  );

  const report = scanTarget(stagedPublishRoot);
  assert.strictEqual(report.risk, "no-known-indicators");
  assert.strictEqual(report.findings.length, 0);
  assert(report.trustSignals.some((signal) => signal.type === "npm-staged-publish-approver"));
  assert(report.trustSignals.some((signal) => signal.type === "npm-staged-publish-workflow"));
} finally {
  fs.rmSync(stagedPublishRoot, { recursive: true, force: true });
}

const nodeIpcRoot = makeFixture("scc-node-ipc-");
try {
  write(
    path.join(nodeIpcRoot, "package.json"),
    JSON.stringify({ name: "node-ipc-fixture", version: "1.0.0", dependencies: { "node-ipc": "12.0.1" } }, null, 2)
  );
  write(
    path.join(nodeIpcRoot, "package-lock.json"),
    JSON.stringify({ packages: { "node_modules/node-ipc": { version: "9.2.3" } } })
  );

  const report = scanTarget(nodeIpcRoot);
  assert.strictEqual(report.risk, "likely-exposed");
  assert(report.findings.some((finding) => finding.type === "known-bad-requested-version"));
  assert(report.findings.some((finding) => finding.type === "known-bad-lockfile-version"));
} finally {
  fs.rmSync(nodeIpcRoot, { recursive: true, force: true });
}

const liteLlmRoot = makeFixture("scc-litellm-");
try {
  write(path.join(liteLlmRoot, "requirements.txt"), "litellm==1.83.6\nstarlette==1.0.0\n");
  write(
    path.join(liteLlmRoot, "docker-compose.yml"),
    [
      "services:",
      "  litellm:",
      "    image: ghcr.io/berriai/litellm:main",
      "    command: litellm --host 0.0.0.0 --port 4000",
      "    environment:",
      "      - OPENAI_API_KEY=${OPENAI_API_KEY}",
      "    labels:",
      "      - route=/mcp-rest/test/connection",
      "      - route=/mcp-rest/test/tools/list",
    ].join("\n")
  );

  const report = scanTarget(liteLlmRoot);
  assert.strictEqual(report.risk, "likely-exposed");
  assert(report.findings.some((finding) => finding.type === "litellm-cve-2026-42271-vulnerable-version"));
  assert(report.findings.some((finding) => finding.type === "litellm-starlette-host-header-chain"));
  assert(report.findings.some((finding) => finding.type === "litellm-mcp-test-route-reference"));
  assert(report.findings.some((finding) => finding.type === "litellm-public-bind"));
  assert(report.findings.some((finding) => finding.type === "litellm-provider-key-blast-radius"));
} finally {
  fs.rmSync(liteLlmRoot, { recursive: true, force: true });
}

console.log("smoke tests passed");
