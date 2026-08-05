# supply-chain-check

Read-only supply-chain scanner for checking a project before you run installs,
builds, tests, dev servers, editor tasks, or agent tooling.

It looks for known malicious package names, lockfile entries, payload filenames,
tool-config traps, and high-signal incident strings across npm, PyPI, Composer,
Ruby, editor-extension, and agent-config surfaces.

## Safety

- Read-only: no installs, scripts, registry calls, cleanup, telemetry, or secret
  handling.
- A clean result is not an all-clear; it only means this rule set did not match.
- Findings are review signals. Confirm context before treating a host as clean or
  compromised.

## Run

```bash
node ./bin/supply-chain-check.js /path/to/project
```

Print finding-specific next references:

```bash
node ./bin/supply-chain-check.js /path/to/project --response-plan
```

Write JSON:

```bash
node ./bin/supply-chain-check.js /path/to/project --json --response-plan --report report.json
```

Exit codes:

- `0`: no likely exposure found
- `1`: scanner/runtime error
- `2`: likely exposure indicators found

## What It Catches

Coverage includes current supply-chain and developer-tooling indicators from:

- DPRK npm RAT packages and `utils.cjs` postinstall behavior
- Easy-day-js / Mastra npm package takeover indicators
- July 2026 npm/PyPI campaigns: compromised `jscrambler` and Injective
  versions, Paperclip2 manifest-only reverse shells, `polymarket-kit`, Rollup
  lookalikes, and Paysafe/Skrill/Neteller payment-SDK typosquats
- August 4, 2026 keyv / cacheable (ChainDrop / Shai-Hulud "Here We Go Again")
  exact-version carriers (`keyv@6.0.0` and ten related packages), campaign
  network markers, and package-lock v2/v3 path/tarball matching — credited to
  Snyk, StepSecurity, Aikido, Wiz, and JFrog. **Cross-platform npm ecosystem
  risk** (any OS/lane that installs these versions), not Linux-only.
- SafeDep procwire / routecraft Windows npm dropper indicators
- JFrog / The Hacker News PostCSS-lookalike Windows RAT package and payload
  indicators
- Mini Shai-Hulud / Miasma / Hades npm and PyPI waves
- OX/JFrog June 25 Miasma/Hades npm variant indicators, including affected
  `leo-*`, `serverless-*`, `solo-nav`, `rstreams-*`, and
  `@immobiliarelabs/backstage-*` GitLab and LDAP auth package versions plus
  reported GitHub exfil, raw payload-path, `SEED_PAT`/`Seeder` markers,
  credential-stealing auth-plugin rotation guidance, and SafeDep-reported
  `snapshot-*` / fake `Dependabot Updates` workflow poisoning terms
- Langflow `CVE-2026-10561`, `CVE-2026-7664`, and `CVE-2026-55450`
  vulnerable Python dependency pins before their fixed releases
- Laravel Livewire `CVE-2025-54068` vulnerable Composer pins before `3.6.4`
  and broad v3 Composer constraints requiring lockfile verification
- Solana FakeFix / CMS loader packages and wallet/key exfil strings
- GlassWASM Open VSX extension indicators
- JetBrains Marketplace AI-key stealer plugin IDs, endpoint, static auth token,
  and save/apply exfiltration indicators
- Supply Chain Attack catalog npm malware packages, including `free-claude`,
  `free-anthropic-claude`, `search-from-search`, `node-fetch-utils`,
  `signup-embedder`, `node-core-libs`, and `ts-grok`
- Checkmarx ChainVeil npm package indicators, including `tailwindcss-merge`,
  `sass-format`, `sass-formats`, and `rate-limit-flexible`
- JFrog VS Code folder-open autorun / blockchain dead-drop npm indicators for
  `html-to-gutenberg@4.2.11` and `fetch-page-assets@1.2.9`, including the
  fake `fa-solid-400.woff2` payload filename and reported hashes
- Nextron Research Packagist indicator for malicious
  `dcat-auth-google-2fa@1.0.2.0`, including `r[.]keepex[.]xyz` exfil strings
  and the reported hardcoded 2FA bypass marker
- Browser-extension all-sites permission drift paired with commerce/affiliate
  telemetry SDK signals, including the Volume Booster / Give Freely OSINT watch
- Island/THN Adblock for YouTube extension indicators, including
  `cmedhionkhpnakcndndgjdbohmhepckk`, related removed extension IDs,
  `api.adblock-for-youtube.com`, Unistream infrastructure, and dormant
  `trusted-create-element` / MAIN-world scriptlet injection shape
- OtterCookie npm packages and Vercel-hosted C2 strings
- Astro config-as-code loader traps
- OpenClaw risky versions/configs
- AutoJack / AutoGen Studio local MCP WebSocket control-plane indicators and
  reported vulnerable `autogenstudio` pre-release builds
- npm v12 install-script, Git dependency, and remote tarball readiness checks

For npm v12 readiness findings, treat script/source approval as temporary,
version-scoped trust: keep `allowScripts`, `allow-git`, and `allow-remote`
approvals narrow, pin reviewed package versions, and re-review on upgrade.

Source links live in [docs/sources.md](docs/sources.md).

## If It Finds Something

1. Stop running commands in that tree.
2. If it is only a dependency/source reference, remove it and regenerate
   lockfiles from a clean or quarantined environment.
3. If anything may have executed, stop using the host for credential work and
   move to incident response.
4. Rotate credentials only from a clean machine.

More detail: [docs/response-guide.md](docs/response-guide.md).

## License

MIT
