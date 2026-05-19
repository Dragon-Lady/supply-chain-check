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
indicators have been added to the relevant file under `data/packages/`.

Socket's May 13, 2026 GemStuffer report describes a separate RubyGems
registry-abuse campaign with 155 package artifacts. The reported technique uses
Ruby payloads to scrape public-facing UK ModernGov council pages, package
responses into `.gem` archives, and publish those archives to RubyGems as a
data-drop/exfiltration channel. This scanner stores non-secret GemStuffer
filenames, hashes, URLs, and Ruby script patterns. It intentionally does not
store the public RubyGems API token strings from the report.

Socket's May 19, 2026 @antv report describes an active npm publish wave tied to
Mini Shai-Hulud and the npm maintainer account `atool`. Socket names the
`@antv` ecosystem, `echarts-for-react`, `timeago.js`, `size-sensor`, and
`canvas-nest.js` as packages to review while the full affected-version list is
still developing. This scanner treats these as lower-confidence package or
namespace review prompts until exact malicious versions are added under
`data/packages/npm.json`.
Socket's technical analysis of the same wave describes a root-level `index.js`
payload launched by `preinstall: bun run index.js`, a direct C2 endpoint at
`t.m-kosche.com`, GitHub fallback exfiltration using `results/results-*.json`
paths and reversed Shai-Hulud repository markers, and npm propagation logic that
validates stolen npm tokens, enumerates maintainable packages, injects payloads,
bumps versions, and republishes under the compromised maintainer identity.

JFrog's May 13 update for `Shai-Hulud: Here We Go Again` reports that the PyPI
second-stage payload served from `83.142.209.194/transformers.pyz` changed from
attribution text into a credential stealer with cloud, Kubernetes, Vault,
password-manager, developer-tooling, persistence, and possible destructive
behavior. This scanner treats those PyPI payload and persistence indicators as
concrete IOCs while keeping broader advisory-only claims as review context.
Additional May 12-13 public reporting describes country/language-gated
destructive behavior in the Python payload, including Russian-language avoidance
and a reported Israel/Iran location check that may randomly trigger audio
playback and file deletion. Treat those details as destructive-payload triage
context, not standalone package exposure indicators.

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
- `transformers.pyz`
- `pgmonitor.py`
- `pgsql-monitor.service`
- `gh-token-monitor.service`
- known malicious payload SHA-256 values:
  `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
  and `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- known updated PyPI `transformers.pyz` SHA-256 value:
  `5245eb032e336b85cff0dbb3450d591826bf2ef214fd30d7eba1a763664e151b`
- known affected `@tanstack/*` package/version pairs in
  `data/packages/npm.json`
- known affected `@mistralai/mistralai`, `@mistralai/mistralai-azure`, and
  `@mistralai/mistralai-gcp` package/version pairs from Aikido's May 12 update
  in `data/packages/npm.json`
- known affected UiPath, TallyUI, DraftAuth, DraftLab, BeProduct, ML Toolkit,
  TaskFlow, Supersurkhet, Tolka, OpenSearch, Dirigible AI, Mesadev, and selected
  unscoped npm package/version pairs from Aikido's May 12 update in
  `data/packages/npm.json`
- known affected Squawk, SAP CAP, Intercom, and additional Socket-tracked npm
  package/version pairs from Socket's live campaign table
- lower-severity namespace and package-name warnings for namespaces and packages
  reported in the active campaign when exact package/version coverage may still
  be incomplete
- developing @antv / atool indicators from Socket's May 19 report: `@antv/*`,
  `echarts-for-react`, `timeago.js`, `size-sensor`, and `canvas-nest.js`
- @antv payload indicators from Socket's technical analysis: `@antv/setup`,
  `github:antvis/G2#1916faa365f2788b6e193514872d51a242876569`,
  `t.m-kosche.com`, `niagA oG eW ereH :duluH-iahS`,
  `niaga og ew ereh :duluh-iahs`, `results/results-`, and `fc2edea72`
- known affected PyPI `mistralai` and `guardrails-ai` package/version pairs from
  OX Security's May 12 update in `data/packages/pypi.json`
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

May 12 public analysis from Ayush Anand / Securityinbits describes an additional
fallback C2 path in the unobfuscated Linux `transformers.pyz` payload. If the
hardcoded `83.142.209.194` C2 fails, the payload searches GitHub commits for
`FIRESCALE`, looks for a commit message matching
`FIRESCALE\s+([A-Za-z0-9+/=]+)\.([A-Za-z0-9+/=]+)`, decodes the URL material,
verifies the attacker signature, and uses the decoded URL as fallback C2. At
the time of that report, the latest checked GitHub commit did not contain a
fresh fallback C2 value.

Manual destructive-payload review strings reported in public analysis include
timezone markers such as `Jerusalem`, `Tel_Aviv`, and `Tehran`, random
one-in-six execution gates, audio playback from `audio.mp3`, and destructive
Linux file-removal logic. Do not treat any one of these generic strings alone as
proof of compromise; use them only when reviewing a confirmed payload or exposed
host.

If one of these indicators is found, treat the environment as potentially
exposed until reviewed. If payload execution or credential access is confirmed,
rotate secrets from a clean device and rebuild the affected host.
