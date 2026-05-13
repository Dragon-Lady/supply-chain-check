# TanStack Incident Scanner

Read-only exposure scanner and recovery guidance for the May 2026 TanStack npm
supply-chain incident, broader Mini Shai-Hulud npm/PyPI/Composer indicators,
and related RubyGems registry-abuse indicators.

This tool helps identify known indicators. It does not remove malware, revoke
credentials, execute package scripts, or prove that a host is clean.

## Safety

The scanner is read-only and dependency-free. It walks local files, parses
package manifests and lockfiles, and hashes known payload filenames. It does
not run `npm install`, execute lifecycle scripts, import project code, contact
package registries, or transmit scan results.

## Scope

This scanner detects exact npm, PyPI, Composer, and selected RubyGems
package/version indicators in `data/packages/` plus shared payload,
tool-persistence, Ruby script, and campaign indicators from
`data/indicators.json`.
TanStack's official postmortem confirms 84 malicious versions across 42
`@tanstack/*` packages, published on May 11, 2026 between 19:20 and 19:26 UTC.
Socket's live campaign page reports 416 affected package artifacts across npm,
PyPI, and Composer as of May 12, 2026. This scanner includes the exact
package/version indicators currently represented in `data/packages/`.
Broader namespaces remain lower-severity review prompts unless an exact
package/version indicator is present.
Socket's GemStuffer report from May 13, 2026 describes 155 RubyGems package
artifacts using RubyGems as an exfiltration/data-drop channel. This scanner
checks non-secret GemStuffer indicators only; published RubyGems API token values
are intentionally not stored in this repository.

## Out-of-Scope Windows Disclosures

On May 12, 2026, Dark Web Informer amplified separate Nightmare-Eclipse /
Chaotic Eclipse disclosures for `YellowKey` and `GreenPlasma`. These are not
TanStack or Mini Shai-Hulud package indicators and this scanner does not test or
reproduce them. For manual defensive triage only, public screenshots and writeups
mention `Nightmare-Eclipse`, `YellowKey`, `GreenPlasma`, `CSRSS_TEST_SECTION`,
and WinRE / `wpeinit` context.

## Quick Start

```powershell
node .\bin\tanstack-incident-scanner.js C:\path\to\project --report report.json
```

```bash
node ./bin/tanstack-incident-scanner.js /path/to/project --report report.json
```

Use `--json` to print a machine-readable report to stdout.

Exit code `2` means likely exposure indicators were found.

Human-readable output starts with a plain-language `STOP`, `PAUSE`, or clean-scan
summary for non-specialist users, followed by exact technical findings for
developers, security teams, and CI logs.

## What It Checks

- Known compromised `@tanstack/*` package versions
- Known compromised `@squawk/*` package versions from Socket's campaign table
- Known compromised `@mistralai/*` package versions from Aikido's May 12 update
- Known compromised UiPath, TallyUI, DraftAuth, DraftLab, BeProduct,
  ML Toolkit, TaskFlow, Supersurkhet, Tolka, OpenSearch, Dirigible AI, Mesadev,
  and selected unscoped package versions from Aikido's May 12 update
- Known compromised SAP CAP, Intercom, and older Mini Shai-Hulud npm artifacts
  from Socket's campaign table
- Known compromised PyPI `mistralai`, `guardrails-ai`, and `lightning` versions
- Known compromised Composer `intercom/intercom-php` version
- Selected GemStuffer RubyGems package/version indicators and non-secret Ruby
  payload indicators from Socket's May 13 report
- Ruby/Bundler files: `Gemfile`, `Gemfile.lock`, `.gemspec`, and `.rb`
- Lower-severity namespace warnings for namespaces reported in the active
  campaign when exact package/version coverage may still be incomplete
- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`, `tanstack_runner.js`, and `router_runtime.js`
- Known malicious payload SHA-256 hashes when a payload file is present
- Selected network, workflow, token-description, and campaign marker strings
- Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json` config
  references to known payload and campaign indicators
- Install lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`
- GitHub-resolved dependencies in manifests

## If Indicators Are Found

Do not start by revoking tokens from the suspected infected host. First stop
builds and package installs, isolate the host if execution is possible, then use
a clean machine to rotate credentials and audit accounts.

See [docs/recovery-playbook.md](docs/recovery-playbook.md).

## Sources

- TanStack official postmortem: https://tanstack.com/blog/npm-supply-chain-compromise-postmortem
- GitHub Security Advisory: https://github.com/advisories/GHSA-g7cv-rxg3-hmpx
- TanStack issue: https://github.com/TanStack/router/issues/7383
- StepSecurity writeup: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
- Socket writeup: https://socket.dev/blog/tanstack-npm-packages-compromised-mini-shai-hulud-supply-chain-attack
- Aikido broader campaign update: https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
- OX Security broader npm/PyPI campaign update: https://www.ox.security/blog/shai-hulud-here-we-go-again-170-packages-hit-across-npm-pypi/
- Snyk TanStack/Mini Shai-Hulud update: https://snyk.io/jp/blog/tanstack-npm-packages-compromised/
- Socket live Mini Shai-Hulud campaign table: https://socket.dev/supply-chain-attacks/mini-shai-hulud
- Socket GemStuffer RubyGems writeup: https://socket.dev/blog/gemstuffer

## License

MIT
