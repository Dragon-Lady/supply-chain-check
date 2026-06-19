const DEFAULT_REFERENCES = [
  "docs/response-guide.md",
  "docs/sources.md"
];

const RULE_REFERENCES = [
  {
    pattern: /easy-day-js|mastra|setup\.cjs|23\.254\.164/i,
    label: "OX Security easy-day-js / Mastra npm supply-chain report",
    sourceHint: "docs/sources.md#easy-day-js-mastra"
  },
  {
    pattern: /procwire|routecraft|endpointmap|bytecraft|staticlayer|catbox|Microsoft-Delivery-Optimization|Zone\.Identifier/i,
    label: "SafeDep procwire / routecraft Windows npm dropper report",
    sourceHint: "docs/sources.md#procwire-routecraft"
  },
  {
    pattern: /jetbrains/i,
    label: "BleepingComputer / Aikido JetBrains Marketplace AI-key stealer report",
    sourceHint: "docs/sources.md#jetbrains"
  },
  {
    pattern: /glasswasm|openvsx|vsix|tinygo/i,
    label: "Socket GlassWASM / Open VSX report",
    sourceHint: "docs/sources.md#glasswasm"
  },
  {
    pattern: /autojack|autogen|server_params|StdioServerParams|\/api\/mcp\/ws|localhost:8081|127\.0\.0\.1:8081/i,
    label: "Microsoft / The Hacker News AutoJack local MCP control-plane research",
    sourceHint: "docs/sources.md#autojack"
  },
  {
    pattern: /hades|pypi|pth|bun|_index|abi3/i,
    label: "Socket Hades / Miasma PyPI reporting",
    sourceHint: "docs/sources.md#hades"
  },
  {
    pattern: /solana|fakefix|cms/i,
    label: "JFrog Solana FakeFix report",
    sourceHint: "docs/sources.md#solana-fakefix"
  },
  {
    pattern: /ottercookie|bjs-|hjs-|sjs-|cloudflare/i,
    label: "Panther OtterCookie npm campaign",
    sourceHint: "docs/sources.md#ottercookie"
  },
  {
    pattern: /astro|gitignore-hidden-pr-tooling/i,
    label: "SafeDep Astro config-as-code report",
    sourceHint: "docs/sources.md#astro"
  },
  {
    pattern: /openclaw/i,
    label: "OpenClaw advisory coverage",
    sourceHint: "docs/sources.md#openclaw"
  },
  {
    pattern: /npm-v12|remote-tarball|git-dependency|install-script/i,
    label: "npm v12 install-script and source-approval guidance",
    sourceHint: "docs/sources.md#npm-v12"
  },
  {
    pattern: /dprk|terminal-logger|utils\.cjs|keyboard-events/i,
    label: "OX Security DPRK npm RAT report",
    sourceHint: "docs/sources.md#dprk-npm-rat"
  }
];

function buildResponsePlan(report) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const items = findings.map((finding) => responseItem(finding));

  return {
    mode: "information-only",
    title: "Supply-chain response plan",
    boundary: "This tool reports matched indicators and next references only; it does not clean, uninstall, revoke, rotate, delete, quarantine, or change files.",
    summary: summaryForReport(report, findings),
    items,
    references: DEFAULT_REFERENCES
  };
}

function summaryForReport(report, findings) {
  if (findings.length === 0) {
    return [
      "No current findings matched this rule set.",
      "This is not an all-clear; keep using normal package review for unknown code."
    ];
  }

  if (report.risk === "likely-exposed") {
    return [
      "STOP: known malicious or high-risk supply-chain indicators matched.",
      "Do not run install, build, test, dev-server, editor-task, or agent-tooling commands in this tree until reviewed.",
      "Use each finding's path and source reference to decide whether this remains package review or must move to host incident response."
    ];
  }

  return [
    "PAUSE: suspicious or campaign-adjacent supply-chain indicators matched.",
    "Review each finding before running package-manager or build commands.",
    "Use the linked source list to confirm whether the match is actionable in this project context."
  ];
}

function responseItem(finding) {
  const reference = referenceForFinding(finding);
  return {
    severity: finding.severity,
    type: finding.type,
    path: finding.path,
    finding: finding.message,
    next: nextStepsForFinding(finding),
    references: reference ? [reference, ...DEFAULT_REFERENCES] : DEFAULT_REFERENCES
  };
}

function nextStepsForFinding(finding) {
  if (isExecutionSurface(finding)) {
    return [
      "Treat this as possible execution surface until reviewed.",
      "Preserve the finding path and surrounding file context for whoever handles response.",
      "If this may already have run, leave package review and use your incident-response process."
    ];
  }

  if (isPackageReference(finding)) {
    return [
      "Identify the package, requested version, and lockfile/manifests that matched.",
      "Compare against the source advisory before changing dependencies.",
      "Regenerate dependency state from a clean or quarantined environment after deciding the replacement."
    ];
  }

  return [
    "Review the matched file and surrounding context.",
    "Compare the string or config shape against the linked source advisory.",
    "Escalate to host incident response if the matched code/config may have executed."
  ];
}

function referenceForFinding(finding) {
  const haystack = `${finding.type || ""}\n${finding.message || ""}`;
  const match = RULE_REFERENCES.find((item) => item.pattern.test(haystack));
  if (!match) return null;
  return `${match.label} (${match.sourceHint})`;
}

function isExecutionSurface(finding) {
  return /postinstall|lifecycle|loader|payload|wasm|astro-config|pth|startup|tool-config|open-dm|public-bind|endpoint|exfil/i.test(`${finding.type}\n${finding.message}`);
}

function isPackageReference(finding) {
  return /package|dependency|lockfile|requested-version|known-bad|active-campaign/i.test(`${finding.type}\n${finding.message}`);
}

module.exports = {
  buildResponsePlan
};
