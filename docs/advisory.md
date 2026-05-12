# Advisory Summary

On May 11, 2026, TanStack reported a supply-chain compromise affecting 84
malicious versions across 42 `@tanstack/*` npm packages, published between
19:20 and 19:26 UTC. TanStack attributes the attack chain to a
`pull_request_target` workflow issue, GitHub Actions cache poisoning across a
fork-to-base trust boundary, and runtime extraction of an OIDC token from the
GitHub Actions runner process.

Aikido later reported that the broader Mini Shai-Hulud campaign had expanded to
373 malicious package-version entries across 169 npm package names, including
Mistral SDK packages, enterprise automation, AI/MCP, auth, workflow, and
developer tooling. This project does not claim coverage for additional package
artifacts unless exact package/version indicators have been added to
`data/affected-packages.json`.

The key local indicators used by this project are:

- `@tanstack/setup`
- `github:tanstack/router#79ac49eedf774dd4b0cfa308722bc463cfe5885c`
- `router_init.js`
- `tanstack_runner.js`
- `router_runtime.js`
- known malicious payload SHA-256 values:
  `ab4fcadaec49c03278063dd269ea5eef82d24f2124a8e15d7b90f2fa8601266c`
  and `2ec78d556d696e208927cc503d48e4b5eb56b31abc2870c2ed2e98d6be27fc96`
- known affected `@tanstack/*` package/version pairs in
  `data/affected-packages.json`
- known affected `@mistralai/mistralai`, `@mistralai/mistralai-azure`, and
  `@mistralai/mistralai-gcp` package/version pairs from Aikido's May 12 update
  in `data/affected-packages.json`

Additional TanStack-postmortem IOCs retained for investigation context include
the cache key
`Linux-pnpm-store-6f9233a50def742c09fde54f56553d6b449a535adf87d4083690539f49ae4da11`,
the second-stage URLs `litter.catbox.moe/h8nc9u.js` and
`litter.catbox.moe/7rrc6l.mjs`, the Session/Oxen seed domains
`seed1.getsession.org`, `seed2.getsession.org`, `seed3.getsession.org`, and the
forged commit identity `claude <claude@users.noreply.github.com>`. The scanner
also searches manifests and lockfiles for selected network, workflow,
token-description, and campaign marker strings stored in the advisory data.

If one of these indicators is found, treat the environment as potentially
exposed until reviewed. If payload execution or credential access is confirmed,
rotate secrets from a clean device and rebuild the affected host.
