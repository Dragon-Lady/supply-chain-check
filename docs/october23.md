# October 23, 2026 intelligence refresh

This is offline, read-only inspection. Matches are evidence for review, not proof
of execution or an armed persistence mechanism. No package is imported, installed,
deleted, stopped, or remotely queried by these rules.

## testmetest variant

Exact versions explicitly classified malicious in SafeDep's October 22 table are
checked in npm manifests and npm, Yarn and pnpm lock metadata. Benign decoys,
unknown versions and unresolved ranges are not classified as exact malicious
versions. A binding.gyp command expansion launching index.js is a behavior review,
including in installed packages. Service filenames are review candidates; related
content strengthens the signal without establishing execution.

The reported worm includes a token-revocation wiper. Preserve evidence and have
incident responders assess and safely stop it BEFORE revoking or rotating tokens
from any device. Do not blindly delete files or services. All matching findings
carry this order and activate the report's sequence-sensitive guidance.

Source: https://safedep.io/testmetest-npm-worm-miasma-variant/

## LiteLLM October compromise

The rule identifies exact 1.107.0 pins in requirements.txt, supported pyproject
dependency fields, uv/Poetry package tables, Pipfile.lock and installed Python
METADATA/PKG-INFO. It is separate from older LiteLLM vulnerability checks.
Cook startup hooks are review candidates. Generic sitecustomize.py is not enough;
related payload strings must co-occur. Dockerfile and Compose image declarations
distinguish the confirmed published digest from affected or floating tags needing
pull-window verification. Other image digests and registries are not cleared.

Do not start Python or pip to investigate a suspected environment: startup hooks
can execute before imports. Contain and rebuild affected environments; rotate
reachable credentials from a clean device after containment. A source tag or a
negative scan cannot clear a previously executed compromised artifact.

Source: https://docs.litellm.ai/blog/security-incident-oct-21-2026
Corroboration: https://socket.dev/blog/litellm-compromise

## Forged install-script endpoint

The reported endpoint in preinstall.js requests review. This does not classify
all hugo-paper or mevn-cli versions as malicious; the report concerns Git source
commits, not their npm releases.
Source: https://safedep.io/hugo-paper-mevn-cli-forged-commit-preinstall-dropper/

## Limits and supported runtime

Use patched Node 22.23.4+, 24.22.1+, or 26.12.1+ within those supported major
lines. The package engines field expresses these minima. Node's October 21
security update includes Brotli and certificate-trust fixes. Runtime maintenance
is separate from detecting malware in a scanned project.
Source: https://nodejs.org/en/blog/vulnerability/october-2026-security-releases

Candidate reads are limited to 32 MiB for npm metadata and 2 MiB otherwise.
Unsupported syntax, excluded/generated directories, symlinks and other scan
boundaries mean a negative result is not comprehensive clearance. Detected parse,
read and budget failures are reported without copying candidate contents.
LSCG's dedicated discovery visits virtual environments and node_modules under its
configured roots, with an entry budget per root and no symlink traversal.
Project scanners retain their existing directory/exclusion scope.
