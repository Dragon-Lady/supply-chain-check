# Advisory Summary

On May 11, 2026, TanStack reported a supply-chain compromise affecting 84
malicious versions across 42 `@tanstack/*` npm packages, published between
19:20 and 19:26 UTC. TanStack attributes the attack chain to a
`pull_request_target` workflow issue, GitHub Actions cache poisoning across a
fork-to-base trust boundary, and runtime extraction of an OIDC token from the
GitHub Actions runner process.

Socket's live campaign page reports 416 affected package artifacts across npm,
PyPI, and Composer as of May 12, 2026, including the TanStack wave, Mistral SDK
packages, UiPath packages, Squawk packages, OpenSearch, Guardrails AI, older SAP
CAP packages, Intercom, and PyPI `lightning`. This project does not claim
coverage for additional package artifacts unless exact package/version
indicators have been added to `data/affected-packages.json`.

Socket's May 13, 2026 GemStuffer report describes a separate RubyGems
registry-abuse campaign with 155 package artifacts. The reported technique uses
Ruby payloads to scrape public-facing UK ModernGov council pages, package
responses into `.gem` archives, and publish those archives to RubyGems as a
data-drop/exfiltration channel. This scanner stores non-secret GemStuffer
filenames, hashes, URLs, and Ruby script patterns. It intentionally does not
store the public RubyGems API token strings from the report.

Separate May 12, 2026 Nightmare-Eclipse / Chaotic Eclipse Windows disclosures
for `YellowKey` and `GreenPlasma` are out of scope for this scanner. They are
tracked here only as related public situational awareness because readers may see
the same reporting stream. Do not add those repositories or screenshots to
scanner detection data unless a confirmed TanStack, Mini Shai-Hulud package,
payload, or campaign artifact overlaps. Manual triage strings from the public
reporting include `Nightmare-Eclipse`, `YellowKey`, `GreenPlasma`,
`CSRSS_TEST_SECTION`, and WinRE / `wpeinit` context.

The key local indicators used by this project are:

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- known malicious payload SHA-256 values:
  `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
  and `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- known affected `@tanstack/*` package/version pairs in
  `data/affected-packages.json`
- known affected `@mistralai/mistralai`, `@mistralai/mistralai-azure`, and
  `@mistralai/mistralai-gcp` package/version pairs from Aikido's May 12 update
  in `data/affected-packages.json`
- known affected UiPath, TallyUI, DraftAuth, DraftLab, BeProduct, ML Toolkit,
  TaskFlow, Supersurkhet, Tolka, OpenSearch, Dirigible AI, Mesadev, and selected
  unscoped npm package/version pairs from Aikido's May 12 update in
  `data/affected-packages.json`
- known affected Squawk, SAP CAP, Intercom, and additional Socket-tracked npm
  package/version pairs from Socket's live campaign table
- lower-severity namespace warnings for namespaces reported in the active
  campaign when exact package/version coverage may still be incomplete
- known affected PyPI `mistralai` and `guardrails-ai` package/version pairs from
  OX Security's May 12 update in `data/affected-packages.json`
- known affected PyPI `lightning` and Composer `intercom/intercom-php`
  package/version pairs from Socket's live campaign table
- selected GemStuffer RubyGems package/version pairs, payload filenames, Ruby
  script patterns, and SHA-256 hashes from Socket's May 13 report
- Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json`
  references to known payload, network, token-description, and campaign strings

Additional TanStack-postmortem IOCs retained for investigation context include
the cache key
`Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11`,
the second-stage URLs `litter.catbox.moe/h8nc9u.js` and
`litter.catbox.moe/7rrc6l.mjs`, the Session/Oxen seed domains
`seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`, and the
forged commit identity `claude <claude@users.noreply.github.com>`. The scanner
also searches manifests and lockfiles for selected network, workflow,
token-description, and campaign marker strings stored in the advisory data.

If one of these indicators is found, treat the environment as potentially
exposed until reviewed. If payload execution or credential access is confirmed,
rotate secrets from a clean device and rebuild the affected host.
