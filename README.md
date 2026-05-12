# TanStack Incident Scanner

Read-only exposure scanner and recovery guidance for the May 2026 TanStack npm
supply-chain incident.

This tool helps identify known indicators. It does not remove malware, revoke
credentials, execute package scripts, or prove that a host is clean.

## Safety

The scanner is read-only and dependency-free. It walks local files, parses
package manifests and lockfiles, and hashes known payload filenames. It does
not run `npm install`, execute lifecycle scripts, import project code, contact
package registries, or transmit scan results.

## Scope

This scanner detects exact package/version indicators in
`data/affected-packages.json` plus shared payload and campaign indicators.
TanStack's official postmortem confirms 84 malicious versions across 42
`@tanstack/*` packages, published on May 11, 2026 between 19:20 and 19:26 UTC.
Aikido's May 12 update reports the broader Mini Shai-Hulud campaign at 373
malicious package-version entries across 169 npm package names. This scanner
now includes the confirmed Mistral SDK package/version indicators from that
update, but broader namespaces are not scanner detections until exact
package/version indicators are added to `data/affected-packages.json`.

## Quick Start

```powershell
node .\bin\tanstack-incident-scanner.js C:\path\to\project --report report.json
```

```bash
node ./bin/tanstack-incident-scanner.js /path/to/project --report report.json
```

Use `--json` to print a machine-readable report to stdout.

Exit code `2` means likely exposure indicators were found.

## What It Checks

- Known compromised `@tanstack/*` package versions
- Known compromised `@mistralai/*` package versions from Aikido's May 12 update
- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`, `tanstack_runner.js`, and `router_runtime.js`
- Known malicious payload SHA-256 hashes when a payload file is present
- Selected network, workflow, token-description, and campaign marker strings
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

## License

MIT
