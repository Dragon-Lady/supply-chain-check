# supply-chain-check

Read-only dependency and source risk checker for pre-execution supply-chain
review.

This tool is the calmer pre-execution lane. It is for checking a project,
package, or cloned repository before trusting it.

## Safety

- Read-only checks only.
- No package installs.
- No lifecycle script execution.
- No registry calls.
- No cleanup automation.
- No credential handling.
- No telemetry or upload of scan results.

## Scope

Current built-in indicators cover OX Security's May 20, 2026 DPRK-linked npm
infostealer/RAT report:

- `terminal-logger-utils`
- `pretty-logger-utils`
- `ts-logger-pack`
- `pinno-loggers`
- `postinstall` scripts that run `utils.cjs`
- `/api/validate/keyboard-events`
- `pwdKeyString`
- `Telegram Desktop`
- `MicrosoftSystem64`

The checker also covers the June 2026 Mini Shai-Hulud / Miasma / Hades PyPI
waves reported by Socket and SecurityWeek:

- affected PyPI package versions from the Hades IOC lists
- `*-setup.pth` Python startup hooks
- Bun bootstrap and `_index.js` launcher behavior
- `sys.path` payload-search loaders
- Hades GitHub/CI exfiltration markers such as `Run Copilot`,
  `format-results`, and the Hades repository-description string
- native `.abi3.so` extension layouts paired with `_index.js`

The checker also covers JFrog's June 2026 Solana FakeFix / CMS Windows loader
report:

- malicious Solana-themed npm and PyPI package names
- CMS-themed npm loader package names
- Solana keypair, wallet, SSH, AWS, `.env`, and Telegram-exfil indicators
- suspicious Solana RPC redirection and fake update URL markers
- Deno `run -A`, hidden PowerShell/Windows loader, Registry Run key, mutex, and
  EXE-dropper indicators

GitHub Advisory `GHSA-g6v5-9xpp-6hpx` also marks the npm package
`google-cloud-secret-manager-config-poc` as malware with all versions affected.

Panther's April 2026 OtterCookie report adds exact-version npm detections for
wrapper and payload packages including `bjs-biginteger`,
`bjs-lint-builder(s)`, `hjs-lint-builders`, `sjs-builder(s)`, and
`npm-doc-builder`, plus Vercel-hosted C2 indicators.

SafeDep's Astro config-as-code report adds review checks for suspicious
`astro.config.*` loader behavior, blockchain/C2 relay markers, horizontally
hidden executable-looking payload lines, and `.gitignore` entries that hide
reported PR helper artifacts.

The Hacker News June 2026 OpenClaw coverage adds review checks for OpenClaw
versions before `2026.4.23` and high-risk OpenClaw configuration that combines
open inbound DMs, wildcard sender allowlists, or host/main/disabled sandbox
mode.

GitHub's June 2026 npm v12 notice adds review checks for old npm pins,
dependency install-script approval readiness, Git dependency sources, remote
tarball dependency sources, and broad repo `.npmrc` opt-ins that bypass the new
default-deny posture. These are local operator notifications only.

The checker also reports package lifecycle scripts and GitHub-resolved
dependencies for review because those are common package-supply-chain risk
surfaces.

The checker records npm staged-publish approval evidence as `trustSignals`, not
as findings. pnpm 11.5 recognizes package registry metadata with an `approver`
field as strong trust evidence because staged publishes require a maintainer 2FA
approval before release. This avoids false positives where approved staged
publishes look like trust downgrades.

## Usage

```powershell
node .\bin\supply-chain-check.js C:\path\to\project --report report.json
```

```bash
node ./bin/supply-chain-check.js /path/to/project --report report.json
```

Use `--json` to print a machine-readable report to stdout.

Exit code `2` means likely exposure indicators were found.

## If Indicators Are Found

Do not run package-manager, build, test, or dev-server commands in the affected
tree until reviewed.

If the indicator is only a dependency reference and nothing executed, remove the
dependency and regenerate lockfiles from a clean/quarantined environment.

If an install hook, binary, editor task, agent hook, or devcontainer may have
executed, move to host incident response. Rotate secrets only from a clean
machine.

## Source

- OX Security DPRK npm RAT writeup:
  https://www.ox.security/blog/north-korean-npm-infostealer-rat/
- Socket Hades PyPI wave analysis:
  https://socket.dev/blog/shai-hulud-descends-to-hades-miasma-pypi-wave
- Socket newer Miasma/Hades PyPI wave analysis:
  https://socket.dev/blog/mini-shai-hulud-miasma-and-hades-worms-target-bioinformatics-and-mcp-developers-via-malicious
- SecurityWeek Shai-Hulud Miasma/Hades summary:
  https://www.securityweek.com/over-100-npm-pypi-packages-hit-in-new-shai-hulud-supply-chain-attacks/
- JFrog Solana FakeFix / CMS Windows loader report:
  https://research.jfrog.com/post/solana-fakefix/
- GitHub Advisory for `google-cloud-secret-manager-config-poc`:
  https://github.com/advisories/GHSA-g6v5-9xpp-6hpx
- Panther OtterCookie npm campaign:
  https://panther.com/blog/tracking-an-ottercookie-infostealer-campaign-across-npm
- SafeDep Astro config blockchain C2 supply-chain report:
  https://safedep.io/astro-config-blockchain-c2-supply-chain/
- The Hacker News OpenClaw prompt-injection and agent-phishing report:
  https://thehackernews.com/2026/06/new-attacks-trick-openclaw-ai-agent.html
- GitHub npm v12 breaking changes notice:
  https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/
- The Hacker News npm v12 install-script default change summary:
  https://thehackernews.com/2026/06/github-to-disable-npm-install-scripts.html
- Socket / pnpm 11.5 staged publish recognition:
  https://socket.dev/blog/pnpm-11-5-adds-support-for-recognizing-npm-staged-publishes
- npm staged publishing docs:
  https://docs.npmjs.com/cli/v11/commands/npm-stage/

## License

MIT
