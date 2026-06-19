const assert = require("assert");
const { buildResponsePlan } = require("../src/response-plan");

const report = {
  risk: "likely-exposed",
  findings: [
    {
      severity: "critical",
      type: "jetbrains-ai-key-stealer-indicator",
      path: "/tmp/project/plugin.json",
      message: "JetBrains plugin file references reported JetBrains Marketplace AI-key stealer endpoint: 39.107.60[.]51/api/software/key"
    },
    {
      severity: "critical",
      type: "known-bad-requested-version",
      path: "/tmp/project/package.json",
      message: "dependencies.example requests compromised version 1.0.0."
    }
  ]
};

const plan = buildResponsePlan(report);
assert.strictEqual(plan.mode, "information-only");
assert(plan.boundary.includes("does not clean"));
assert.strictEqual(plan.items.length, 2);
assert(plan.items[0].references.some((reference) => reference.includes("JetBrains")));
assert(plan.items[1].next.some((step) => step.includes("package")));
assert(!JSON.stringify(plan).includes("token persistence marker"));
assert(!JSON.stringify(plan).includes("database monitor marker"));

console.log("response plan tests passed");
