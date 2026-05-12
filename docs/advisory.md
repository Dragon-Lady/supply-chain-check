# Advisory Summary

On May 11, 2026, public reporting described a supply-chain compromise affecting
multiple `@tanstack/*` npm packages. Reporting from the TanStack issue tracker
and StepSecurity described malicious package versions published through a trusted
release path, with valid provenance for poisoned artifacts.

The key local indicators used by this project are:

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- known affected `@tanstack/*` package/version pairs in
  `data/affected-packages.json`

If one of these indicators is found, treat the environment as potentially
exposed until reviewed. If payload execution or credential access is confirmed,
rotate secrets from a clean device and rebuild the affected host.
