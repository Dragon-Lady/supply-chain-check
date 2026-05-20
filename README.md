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

The checker also reports package lifecycle scripts and GitHub-resolved
dependencies for review because those are common package-supply-chain risk
surfaces.

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

## License

MIT
