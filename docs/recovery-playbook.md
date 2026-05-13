# Recovery Playbook

Use this sequence when the scanner finds likely exposure or when a project may
have installed compromised packages during the incident window.

## 1. Stop Activity

- Stop package installs, builds, test runners, and dev servers.
- Do not run cleanup commands from the suspected infected environment.
- Do not revoke tokens from the suspected infected host first.

## 2. Contain

- If payload execution is possible, disconnect the host from the network.
- Preserve lockfiles, package manifests, install logs, and scanner reports.
- For Ruby findings, preserve `Gemfile`, `Gemfile.lock`, `.gemspec`, suspicious
  `.rb` files, RubyGems publish logs, and any relevant `/tmp` staging paths.
- Preserve Claude Code `.claude/settings*.json` and VS Code `.vscode/tasks.json`
  if persistence indicators are suspected.
- Avoid copying `node_modules`, build caches, unknown scripts, shell profiles, or
  editor extension state into a recovery environment.

## 3. Rotate From A Clean Machine

Rotate credentials from a separate trusted device:

- GitHub personal access tokens, OAuth grants, deploy keys, and Actions secrets
- npm tokens and publish automation credentials
- RubyGems API keys and publish automation credentials
- AWS, GCP, Azure, Vault, Kubernetes, and other cloud credentials
- SSH keys and CI/CD secrets

Audit for recently created tokens, suspicious repositories, unexpected Actions
workflows, self-hosted runners, and unusual cloud API activity.

On Windows developer workstations, also review LSASS/logon-session telemetry for
signs that a logon session was kept alive after user logoff. Microsoft/Windows
security researchers have noted `LSASRV` ETW event `6182` as a delayed detection
signal for Koh-style logon-session preservation; it is timer-based rather than
real-time, so treat it as supporting evidence during host triage.

## 4. Recover Data Carefully

Copy only needed documents and source files from a trusted recovery environment
where possible. Do not preserve executable dependency folders or generated build
artifacts.

## 5. Rebuild And Verify

If payload execution, persistence, or secret access is found, rebuild or reimage
the host from a clean baseline. Reinstall dependencies from a clean lockfile
pinned away from known-bad versions, with install scripts blocked unless a
package has been reviewed.

Before resuming AI/editor tooling, review Claude Code hooks and VS Code tasks
from a clean environment. Remove unexpected commands, package-manager invocations,
payload filenames, network indicators, or campaign marker strings. Do not assume
`npm uninstall` or `pip uninstall` removed persistence from tool config files.

For GemStuffer-style Ruby findings, also block or review outbound publish access
to `rubygems.org/api/v1/gems` from CI jobs that do not intentionally publish
gems. If a RubyGems publish credential may have been exposed or embedded in a
script, revoke it from a clean machine.

## Important Limit

This project cannot prove a machine is clean. A clean scan only means the known
indicators checked by this version were not observed.
