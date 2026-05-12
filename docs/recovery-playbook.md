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
- Avoid copying `node_modules`, build caches, unknown scripts, shell profiles, or
  editor extension state into a recovery environment.

## 3. Rotate From A Clean Machine

Rotate credentials from a separate trusted device:

- GitHub personal access tokens, OAuth grants, deploy keys, and Actions secrets
- npm tokens and publish automation credentials
- AWS, GCP, Azure, Vault, Kubernetes, and other cloud credentials
- SSH keys and CI/CD secrets

Audit for recently created tokens, suspicious repositories, unexpected Actions
workflows, self-hosted runners, and unusual cloud API activity.

## 4. Recover Data Carefully

Copy only needed documents and source files from a trusted recovery environment
where possible. Do not preserve executable dependency folders or generated build
artifacts.

## 5. Rebuild And Verify

If payload execution, persistence, or secret access is found, rebuild or reimage
the host from a clean baseline. Reinstall dependencies from a clean lockfile
pinned away from known-bad versions, with install scripts blocked unless a
package has been reviewed.

## Important Limit

This project cannot prove a machine is clean. A clean scan only means the known
indicators checked by this version were not observed.
