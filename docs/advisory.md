# Advisory Summary

`supply-chain-check` is a read-only dependency and source risk checker for
pre-execution package-supply-chain review.

The current built-in campaign is OX Security's May 20, 2026 DPRK-linked npm
infostealer/RAT report. OX names `terminal-logger-utils` as the malicious npm
package, with `pretty-logger-utils`, `ts-logger-pack`, and `pinno-loggers` as
dependent packages that trigger malicious behavior when installed.

Reported behavior includes a `postinstall` hook that opens `utils.cjs`, fetches
a second-stage bundled Node executable, and targets developer workstation data
such as Telegram data, SSH keys, cloud configuration, crypto wallets, browser
data, environment variables, clipboard data, and typed password fields.

SupplyChainAttack and GitHub Advisory Database full-compromise npm malware
entries are also included for package-name detection. The checker treats
`ts-grok` as affected for all versions (`>= 0`) with no patched version,
matching GHSA-qp73-r9hh-6vq9, and asks operators to move to credential rotation
and host compromise response if the package was installed or run.

## OX / JFrog Miasma / Hades npm Variant

OX Security's June 25, 2026 report describes another Shai-Hulud / Miasma /
Hades npm variant tied to a compromised maintainer account and 23 affected
package versions across the `leo-*`, `serverless-*`, `solo-nav`, and
`rstreams-*` package set. JFrog's companion analysis confirms the Leo/RStreams
rows and adds affected `@immobiliarelabs/backstage-*` package versions.

The checker flags those exact npm package versions in manifests and lockfiles.
It also flags copied incident notes or source artifacts containing the reported
GitHub exfil repository string `Alright Lets See If This Works`, the
`RevokeAndItGoesKaboom` revocation marker, the `TheBeautifulSandsOfTime` /
`thebeautifulmarchoftime` strings, the `SEED_PAT` / `Seeder` operator-seeding
markers, the reported GitHub raw payload paths, and the public-key fragments
published as malware indicators.

If these package versions or strings are found, stop installs and builds in the
affected tree. If install-time code may have run, move from package review to
host incident response and rotate credentials only from a clean environment.

## Mini Shai-Hulud / Miasma / Hades PyPI Waves

The June 2026 Socket and SecurityWeek reporting is included for pre-execution
review because the Hades branch moved Shai-Hulud-style tradecraft into PyPI
wheels. The checker flags affected PyPI package versions, `*-setup.pth` Python
startup hooks, Bun bootstrap strings, `_index.js` launchers, `sys.path` payload
searching, GitHub/CI exfiltration markers, and suspicious `.abi3.so` native
extension layouts paired with `_index.js`.

The generic pattern matters more than one exact Bun version: executable `.pth`
plus network retrieval plus subprocess execution plus staged JavaScript payload
is a high-risk install/startup execution chain.

## GlassWASM / Open VSX Extensions

Socket's June 2026 GlassWASM report is included for editor-extension and
pre-execution review because the affected Open VSX packages used WASM payloads
and JavaScript host code to retrieve C2 instructions through Solana transaction
memos before spawning platform-specific download/execute commands.

The checker flags affected Open VSX extension references, the reported VSIX and
WASM filenames, published SHA-256 values, `dodod.lat`, Solana memo dead-drop
markers, and loader code that combines TinyGo/WebAssembly fingerprints with
Node `child_process`, `curl | bash`, PowerShell `irm | iex`, or `windowsHide`.

This checker does not perform cleanup and does not claim a host is clean. If
anything may have executed, move from project review to host incident response.

## Browser Extension Permission Drift

An operator-provided June 22, 2026 International Cyber Digest OSINT note
described a Chrome extension named Volume Booster activating the Give Freely
commerce/affiliate SDK after broad all-sites permission had already been granted
in an earlier version. The checker treats this as a watch-only extension
supply-chain signal: `manifest.json` files with broad host permissions are
flagged for review, and Give Freely / commerce telemetry SDK terms are flagged
when they appear alongside extension permission or runtime/network behavior.

This is not a confirmed malware IOC in this rule set. It is meant to catch the
permission-drift pattern before an extension update turns dormant access into
active telemetry.

## npm Staged Publish Trust Signal

As of pnpm 11.5, package registry metadata carrying an `approver` field is
recognized as strong trust evidence because npm staged publishes require
maintainer 2FA approval before a version becomes installable. `supply-chain-check`
records this as a `trustSignals` entry and does not treat staged publish
approval metadata as a supply-chain finding.
