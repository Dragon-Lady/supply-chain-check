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
- SafeDep procwire / routecraft Windows npm dropper indicators
- Mini Shai-Hulud / Miasma / Hades npm and PyPI waves
- Solana FakeFix / CMS loader packages and wallet/key exfil strings
- GlassWASM Open VSX extension indicators
- JetBrains Marketplace AI-key stealer plugin IDs and endpoint indicators
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
