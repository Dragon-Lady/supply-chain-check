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
- network/workflow/token/campaign marker strings in `data/affected-packages.json`
- payload SHA-256 `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
- payload SHA-256 `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- affected package/version pairs in `data/affected-packages.json`

## Campaign Scope Note

TanStack's official postmortem confirms 84 malicious versions across 42
`@tanstack/*` packages, published on May 11, 2026 between 19:20 and 19:26 UTC.
The associated GitHub Security Advisory is GHSA-g7cv-rxg3-hmpx /
CVE-2026-45321.

As of the May 12, 2026 update, Aikido reporting puts the broader Mini
Shai-Hulud campaign at 373 malicious package-version entries across 169 npm
package names. The scanner includes exact Mistral SDK package/version
indicators from that update, but additional namespaces should only be added
after exact package/version confirmation.

## Public Response Rules

- Do not ask users to paste secrets, `.env` files, private keys, tokens, or full logs.
- Do not claim the tool proves a host is clean.
- If indicators are found, advise containment first.
- Do not advise revoking tokens from the suspected infected machine.
- Credential rotation should happen from a clean machine.
- If payload execution, persistence, or secret exposure is plausible, recommend rebuild/reimage.

## Public Signal Log

- 2026-05-11: Tanner Linsley (`@tannerlinsley`), creator of TanStack, liked related public activity. Treat as a morale/visibility signal only, not formal endorsement or technical validation.
- 2026-05-11: GitHub analysis showed a user scan reached Ubuntu and reported about 7 seconds per pass. Scope is partial Ubuntu/Linux coverage only; do not treat this as full matrix completion or broad platform validation. No errors were observed in the reported completed portion.

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
