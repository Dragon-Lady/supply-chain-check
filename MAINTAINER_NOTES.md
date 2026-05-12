# Maintainer Notes

Current public repo:
https://github.com/Dragon-Lady/tanstack-incident-scanner

Initial release state:

- Branch: `main`
- Initial commit: `15085b4 Initial TanStack incident scanner`
- Runtime: Node.js >= 18
- Dependencies: none
- Safety stance: read-only scanner, no package installs, no script execution, no malware removal claims

## Core Commands

```powershell
cd C:\Users\tanya\tanstack-incident-scanner
npm test
node bin\tanstack-incident-scanner.js C:\path\to\project --report report.json
node bin\tanstack-incident-scanner.js C:\path\to\project --json
```

## Current Indicators

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- affected package/version pairs in `data/affected-packages.json`

## Public Response Rules

- Do not ask users to paste secrets, `.env` files, private keys, tokens, or full logs.
- Do not claim the tool proves a host is clean.
- If indicators are found, advise containment first.
- Do not advise revoking tokens from the suspected infected machine.
- Credential rotation should happen from a clean machine.
- If payload execution, persistence, or secret exposure is plausible, recommend rebuild/reimage.

## Fast Update Flow

1. Update `data/affected-packages.json` for new confirmed package/version indicators.
2. Add a fixture or smoke assertion if the scanner behavior changes.
3. Run `npm test`.
4. Commit with a narrow message.
5. Push `main`.

## Good Next Improvements

- Add `--severity-threshold` for CI use.
- Add `--ignore-review-needed` if lifecycle script findings are too noisy.
- Add examples for npm, pnpm, yarn, and monorepo scans.
- Add a signed GitHub release once public feedback stabilizes.
