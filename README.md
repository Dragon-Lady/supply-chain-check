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
- Socket / pnpm 11.5 staged publish recognition:
  https://socket.dev/blog/pnpm-11-5-adds-support-for-recognizing-npm-staged-publishes
- npm staged publishing docs:
  https://docs.npmjs.com/cli/v11/commands/npm-stage/

## License

MIT
