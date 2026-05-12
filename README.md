# TanStack Incident Scanner

Read-only exposure scanner and recovery guidance for the May 2026 TanStack npm
supply-chain incident.

This tool helps identify known indicators. It does not remove malware, revoke
credentials, execute package scripts, or prove that a host is clean.

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
- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`, `tanstack_runner.js`, and `router_runtime.js`
- Install lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`
- GitHub-resolved dependencies in manifests

## If Indicators Are Found

Do not start by revoking tokens from the suspected infected host. First stop
builds and package installs, isolate the host if execution is possible, then use
a clean machine to rotate credentials and audit accounts.

See [docs/recovery-playbook.md](docs/recovery-playbook.md).

## Sources

- TanStack issue: https://github.com/TanStack/router/issues/7383
- StepSecurity writeup: https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem

## License

MIT
