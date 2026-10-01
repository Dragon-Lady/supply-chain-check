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
`ts-grok` and `signup-embedder` as affected for all versions (`>= 0`) with no
patched version, matching GHSA-qp73-r9hh-6vq9 and GHSA-8j4q-hx83-pfq9, and asks
operators to move to credential rotation and host compromise response if either
package was installed or run.

## OX / JFrog Miasma / Hades npm Variant

OX Security's June 25, 2026 report describes another Shai-Hulud / Miasma /
Hades npm variant tied to a compromised maintainer account and 23 affected
package versions across the `leo-*`, `serverless-*`, `solo-nav`, and
`rstreams-*` package set. JFrog's companion analysis confirms the Leo/RStreams
rows and adds affected `@immobiliarelabs/backstage-*` package versions. Aikido
also called out the ImmobiliareLabs Backstage LDAP auth and GitLab plugins as
credential-stealing worm targets, so any hit on these packages should move
directly to clean-device rotation for GitHub, npm, LDAP, Backstage, CI, and
cloud credentials after persistence/exfiltration paths are contained.

The checker flags those exact npm package versions in manifests and lockfiles.
It also flags copied incident notes or source artifacts containing the reported
GitHub exfil repository string `Alright Lets See If This Works`, the
`RevokeAndItGoesKaboom` revocation marker, the `TheBeautifulSandsOfTime` /
`thebeautifulmarchoftime` strings, the `SEED_PAT` / `Seeder` operator-seeding
markers, the reported GitHub raw payload paths, and the public-key fragments
published as malware indicators.

SafeDep's LeoPlatform follow-up confirms the 20 LeoPlatform npm rows and adds
repo-poisoning context around orphan `snapshot-*` branches, fake `Dependabot
Updates` GitHub Actions workflows, `_index.js`, `OIDC_PACKAGES`, `WORKFLOW_ID`,
`REPO_ID_SUFFIX`, and direct `NPM_TOKEN` publication surfaces.

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

JetBrains Marketplace AI-key stealer indicators are included for adjacent IDE
plugin supply-chain review. In addition to the Aikido/BleepingComputer plugin
IDs and `39.107.60[.]51/api/software/key` endpoint, DFIR Radar's June 25 note
adds implementation markers: `F48D2AA7CF341F782C1D`, `BaseUtil.request()`,
`save()`/Apply configuration persistence, `sk-` key validation, and plaintext
HTTP POST behavior from JetBrains processes.

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

Island's June 2026 Adblock for YouTube report, covered by The Hacker News,
adds a stronger browser-extension review lane. The checker flags the live
extension ID `cmedhionkhpnakcndndgjdbohmhepckk`, related removed extension IDs
`onomjaelhagjjojbkcafidnepbfkpnee`, `ogcaehilgakehloljjmajoempaflmdci`, and
`gekoepiplklhniacchbbgbhilidiojmb`, Adblock/Unistream infrastructure strings,
and source shapes where server-selected scriptlets such as
`trusted-create-element` can reach `chrome.scripting.executeScript` /
MAIN-world script creation. These are review findings, not proof that a
malicious payload ran.

## npm Staged Publish Trust Signal

As of pnpm 11.5, package registry metadata carrying an `approver` field is
recognized as strong trust evidence because npm staged publishes require
maintainer 2FA approval before a version becomes installable. `supply-chain-check`
records this as a `trustSignals` entry and does not treat staged publish
approval metadata as a supply-chain finding.

## August 2026 keyv / cacheable (ChainDrop / Shai-Hulud "Here We Go Again")

**Ox Security** (2026-08-04; blog by Moshe Siman Tov Bustan; **Moshe Simon** / @MosheTov posted the findings on X with the Ox blog link) reports a live Shai-Hulud campaign hitting npm at
roughly **444 packages**, **1,600+ versions**, and **over 2 billion monthly
downloads**. The worm continues to spread; Ox publishes a partial package table
and asks operators to treat inventory as incomplete until refreshed.

**Behavior (same family as prior waves):** credential-stealing worm logic,
self-propagation through stolen npm accounts, **IDE/AI persistence** (Claude,
VS Code, and related agent/editor hooks), **GitHub exfiltration** as C2, and a
**dead-man switch** that can react when a stolen GitHub token is revoked.
Payload entry commonly uses `preinstall` → `setup.mjs` / Bun, then
`math_init.js` or `Math_Symbol.js`.

**New Ox-highlighted signals:**
- Extortion / production-crash threat string:
  `IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients`
- Campaign RSA public encryption key published as an IOC (Ox: not yet
  attributed; operator summary treats it as a possible **TeamPCP copycat**
  signal rather than confirmed TeamPCP attribution)
- Campaign strings/files including `Shai-Hulud: Here We Go Again`,
  `Thebeautifulmarchoftime` / `thebeautifulmarchoftime`, `router_runtime.js`,
  and git pin
  `github:opensearch-project/opensearch-js#d446803f4c3bc116263faa3499a1d3f95b2825de`

**Seed exact-version carriers** (peer-confirmed; not the full 444-package set):
`keyv@6.0.0` and ten related jaredwray-family releases. Use Ox's table and the
Wiz Research keyv packages CSV for broader inventory.

**Ox recommended actions (operator-owned; this scanner is read-only):**
1. Rotate keys and enable 2FA from a clean device.
2. Downgrade affected packages to known-safe versions.
3. Search for infected GitHub accounts/repositories and revoke/remove them if
   affected—**after** dead-man persistence is handled under IR direction
   (notify-only: do not blindly revoke while a monitor may still fire).

Credits: **Ox Security**, Snyk, StepSecurity, Aikido, Wiz, JFrog, and npm
Security. Primary Ox writeup:
https://www.ox.security/blog/a-new-infostealer-worm-hits-npm-affecting-keyv-and-cacheable/

Also check **actions-warden** (PyPI read-only auditor for risky or injected GitHub Actions workflow config) when reviewing repos that may have had tokens stolen or CI tampered with: `actions-warden /path/to/repo`. https://github.com/Dragon-Lady/actions-warden · https://pypi.org/project/actions-warden/. Read-only only.
