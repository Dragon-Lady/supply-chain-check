const assert = require("assert");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { scanTarget } = require("../src/scanner");

const clean = scanTarget(path.join(__dirname, "fixtures", "clean"));
assert.strictEqual(clean.risk, "no-known-indicators");

const compromised = scanTarget(path.join(__dirname, "fixtures", "compromised"));
assert.strictEqual(compromised.risk, "likely-exposed");
assert(compromised.findings.some((finding) => finding.type === "malicious-dependency-name"));
assert(compromised.findings.some((finding) => finding.type === "malicious-dependency-spec"));
assert(compromised.findings.some((finding) => finding.type === "known-bad-requested-version"));
assert(compromised.findings.some((finding) => finding.type === "payload-file"));

const mistralHit = scanTarget(path.join(__dirname, "fixtures", "clean"), {
  advisory: {
    indicators: {
      maliciousOptionalDependencyName: "@tanstack/setup",
      maliciousOptionalDependencySpec: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
      payloadFiles: ["router_init.js", "tanstack_runner.js", "router_runtime.js"],
      payloadFileHashes: {},
      networkIndicators: ["filev2.getsession.org"],
      campaignIndicators: ["A Mini Shai-Hulud has Appeared"]
    },
    packages: {
      "@mistralai/mistralai": ["2.2.4"]
    }
  }
});
assert.strictEqual(mistralHit.risk, "no-known-indicators");

const tmpRoot = fs.mkdtempSync(path.join(__dirname, "tmp-mistral-"));
try {
  fs.writeFileSync(
    path.join(tmpRoot, "package.json"),
    JSON.stringify({ dependencies: { "@mistralai/mistralai": "2.2.4" } }, null, 2)
  );
  fs.writeFileSync(path.join(tmpRoot, "package-lock.json"), "filev2.getsession.org\n");
  const mistralCompromised = scanTarget(tmpRoot);
  assert.strictEqual(mistralCompromised.risk, "likely-exposed");
  assert(mistralCompromised.findings.some((finding) => finding.type === "known-bad-requested-version"));
  assert(mistralCompromised.findings.some((finding) => finding.type === "network-indicator"));
} finally {
  fs.rmSync(tmpRoot, { recursive: true, force: true });
}

const payloadPath = path.join(__dirname, "fixtures", "compromised", "router_init.js");
const payloadHash = crypto.createHash("sha256").update(fs.readFileSync(payloadPath)).digest("hex");
const compromisedWithHash = scanTarget(path.join(__dirname, "fixtures", "compromised"), {
  advisory: {
    indicators: {
      maliciousOptionalDependencyName: "@tanstack/setup",
      maliciousOptionalDependencySpec: "github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c",
      payloadFiles: ["router_init.js", "tanstack_runner.js", "router_runtime.js"],
      payloadFileHashes: {
        "router_init.js": [payloadHash]
      }
    },
    packages: {
      "@tanstack/react-router": ["1.169.5"]
    }
  }
});
assert(compromisedWithHash.findings.some((finding) => finding.type === "payload-hash"));

console.log("smoke tests passed");
