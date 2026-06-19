# Response Guide

## Package Reference Only

Use this lane when the indicator appears in a manifest, lockfile, or source tree
that has not executed.

- Do not run install/build/test/dev-server commands in the tree.
- Remove the dependency or suspicious source reference.
- Regenerate lockfiles in a clean/quarantined environment.
- Scan again before resuming normal work.

## npm v12 Readiness

Use this lane when findings mention install-script approval, Git dependencies,
remote tarballs, or broad `.npmrc` allow rules.

- Keep `allowScripts`, `allow-git`, and `allow-remote` approvals narrow.
- Pair script approvals with exact dependency versions instead of trusting a
  package name across future releases.
- Treat approval as temporary trust and re-review on every upgrade.
- Remember npm v12 reduces silent install-time execution, but it does not stop
  runtime/import-time malicious behavior after a package is used.

## Execution Possible

Use this lane when an install hook, binary, editor task, agent hook, or
devcontainer may have run.

- Stop using the host for account or credential work.
- Preserve enough evidence for review.
- Inspect persistence from a trusted posture.
- Rotate credentials from a clean machine if exposure is plausible.
- Prefer rebuild or restore from a clean baseline over ad hoc cleanup.

## Confirmed Host Incident

If evidence shows payload execution or credential access, stop treating the
case as dependency review and follow your incident-response playbook.
