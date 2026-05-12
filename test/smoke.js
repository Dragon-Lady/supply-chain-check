const assert = require("assert");
const path = require("path");
const { scanTarget } = require("../src/scanner");

const clean = scanTarget(path.join(__dirname, "fixtures", "clean"));
assert.strictEqual(clean.risk, "no-known-indicators");

const compromised = scanTarget(path.join(__dirname, "fixtures", "compromised"));
assert.strictEqual(compromised.risk, "likely-exposed");
assert(compromised.findings.some((finding) => finding.type === "malicious-dependency-name"));
assert(compromised.findings.some((finding) => finding.type === "malicious-dependency-spec"));
assert(compromised.findings.some((finding) => finding.type === "known-bad-requested-version"));
assert(compromised.findings.some((finding) => finding.type === "payload-file"));

console.log("smoke tests passed");
