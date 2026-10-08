const DEFAULT_REFERENCES = [
  "docs/response-guide.md",
  "docs/sources.md"
];

const RULE_REFERENCES = [
  {
    pattern: /PhantomSub|phantomsub-indicator/i,
    label: "OX Security PhantomSub npm report",
    sourceHint: "docs/sources.md#phantomsub"
  },
  {
    pattern: /MemTensor|supplychain\.local|memtensor-indicator|memos-cloud-openclaw|MemoryOS/i,
    label: "Aikido / Socket / SafeDep MemTensor supplychain.local report",
    sourceHint: "docs/sources.md#memtensor"
  },
  {
    pattern: /DirtyBlanket|dirtyblanket-indicator|systemd-fontrenderd|systemd-fontcached/i,
    label: "SafeDep DirtyBlanket npm report",
    sourceHint: "docs/sources.md#dirtyblanket"
  },
  {
    pattern: /Trinitite|trinitite-indicator|openapi-react-query-codegen|systemd-detect-fash/i,
    label: "JFrog Trinitite report",
    sourceHint: "docs/sources.md#trinitite"
  },
  {
    pattern: /CVE-2026-93355|litellm-cve-2026-93355/i,
    label: "OX Security LiteLLM CVE-2026-93355 report",
    sourceHint: "docs/sources.md#litellm-cve-2026-93355"
  },
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
    pattern: /glassworm-/i,
    label: "Socket GlassWorm editor extension investigation",
    sourceHint: "docs/sources.md#glassworm-editor-extension-cluster-october-2026"
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
    summary: [...(report.safeRemovalGuidance?.required ? [report.safeRemovalGuidance.firstAction] : []), ...summaryForReport(report, findings)],
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
  const campaignSteps = campaignNextSteps(finding);
  if (campaignSteps) return campaignSteps;

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

function campaignNextSteps(finding) {
  const haystack = `${finding.type || ""}\n${finding.message || ""}`;
  if (/^tensorlake-|^token-monitor-artifact$/.test(finding.type || "")) return [finding.message, "Source: https://www.stepsecurity.io/blog/tensorlake-npm-compromised-hostage-token-worm"];
  if (finding.type === "glassworm-confirmed-build-identity-review") {
    return [
      "Record the extension registry, exact version, and installed artifact hash. Socket confirmed malicious builds under this identity, not every possible copy or future version.",
      "Do not activate the extension while reviewing it. If a reported malicious build ran, preserve editor-host and network evidence and review credentials reachable from that host.",
      "Follow incident-response order before removal or credential rotation; this scanner changes nothing."
    ];
  }
  if (finding.type === "glassworm-cluster-identity-review") {
    return [
      "Check the extension registry, version, and distributed VSIX contents against Socket's report.",
      "This is a cluster association, not proof that this extension version carried malware.",
      "Review executable entrypoints and update history before deciding whether to disable or remove it."
    ];
  }
  if (/PhantomSub|phantomsub-indicator/i.test(haystack)) {
    return [
      "Remove the PhantomSub package. Do not run it.",
      "If a WhatsApp session was connected through it, report or block unexpected channels.",
      "This campaign is not a credential worm. This tool is notify-only and does not uninstall or edit files."
    ];
  }
  if (/MemTensor|supplychain\.local|memtensor-indicator|memos-cloud-openclaw|MemoryOS/i.test(haystack)) {
    return [
      "Do not load this plugin. Only npm 0.1.21, 0.1.23, and 0.1.25, and PyPI MemoryOS 2.0.34, are reported malicious. npm 0.1.22 and 0.1.24 are clean.",
      "If it ran, preserve evidence and treat credentials reachable from the host or CI runner as exposed. Rotate them from a clean machine and move to host incident response.",
      "Notify-only: this tool does not uninstall the package or revoke credentials."
    ];
  }
  if (/DirtyBlanket|dirtyblanket-indicator|systemd-fontrenderd|systemd-fontcached/i.test(haystack)) {
    return [
      "Do not run the DirtyBlanket package.",
      "If a Linux machine installed one, treat that machine and every SSH key and npm token on it as compromised.",
      "This is host incident response, not a dependency bump. Notify-only: this tool does not clean the host."
    ];
  }
  if (/Trinitite|trinitite-indicator|openapi-react-query-codegen|systemd-detect-fash/i.test(haystack)) {
    return [
      "Isolate the machine. Do not revoke GitHub tokens until the monitor is gone.",
      "Pin @7nohe/openapi-react-query-codegen to a last-safe line: 0.5.3, 1.6.2, 2.2.0, or 3.0.2.",
      "Valid provenance is not a clean bill. After the monitor is gone, rotate credentials from a clean machine. Notify-only."
    ];
  }
  if (/CVE-2026-93355|litellm-cve-2026-93355/i.test(haystack)) {
    return [
      "Treat this LiteLLM version as unpatched for CVE-2026-93355. Version 1.83.7 fixes CVE-2026-42271 only.",
      "Require a verified email before the proxy trusts a JWT. No upstream fix is confirmed.",
      "Notify-only: this tool does not change proxy configuration."
    ];
  }
  return null;
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
