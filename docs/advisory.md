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

This checker does not perform cleanup and does not claim a host is clean. If
anything may have executed, move from project review to host incident response.

## npm Staged Publish Trust Signal

As of pnpm 11.5, package registry metadata carrying an `approver` field is
recognized as strong trust evidence because npm staged publishes require
maintainer 2FA approval before a version becomes installable. `supply-chain-check`
records this as a `trustSignals` entry and does not treat staged publish
approval metadata as a supply-chain finding.
