# v0.1.2 GitHub download release

This follow-up documents the independent October 8 Tensorlake analysis from Socket Research and Aikido, with The Hacker News public coverage. It retains the exact `tensorlake@0.5.144` and payload-hash checks from the preceding release. The new research clarifies browser credential exposure, persistence after package removal, and the order for safely handling the `gh-token-monitor` before any token revocation.

This is a documentation and response-context update. No new runtime detector or host-removal action is claimed. See `docs/advisory.md` for citations, limits, and recovery order. The `.tgz` is distributed through the GitHub Release; no npm registry publication is planned.
