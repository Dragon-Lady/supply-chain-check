#!/usr/bin/env bash
set -euo pipefail
# CI supplies the destination commit, never a policy from the proposed changes.
base="${1:-}"
if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
  base=origin/main
fi
base=$(git rev-parse --verify "${base}^{commit}")
python3 -P -m push_guard scan --base "$base" --head HEAD --no-infer
policy=$(mktemp -d)
trap 'rm -rf "$policy"' EXIT
if git cat-file -e "$base:.push-guard-allow" 2>/dev/null; then
  git show "$base:.push-guard-allow" > "$policy/.push-guard-allow"
fi
artifacts=$(mktemp -d)
npm pack --ignore-scripts --pack-destination "$artifacts"
shopt -s nullglob
packages=("$artifacts"/*.tgz)
[[ ${#packages[@]} == 1 ]] || { echo 'Expected exactly one npm tarball' >&2; exit 1; }
privacy=()
if [[ "${REQUIRE_PRIVATE_TERMS:-false}" == true ]]; then
  python3 -P - <<'CHECK'
import os
terms = {line.strip().casefold() for line in os.environ.get('PUSH_GUARD_BLOCKED_TERMS', '').splitlines()
         if len(line.strip()) >= 3 and not line.strip().startswith('#')}
if len(terms) < 3:
    raise SystemExit('The private-term secret must contain at least three distinct terms')
CHECK
  privacy=(--require-explicit-terms --min-terms 3)
fi
python3 -P -m push_guard scan-package --repo "$policy" --no-infer "${privacy[@]}" "${packages[0]}"
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  printf 'tarball=%s\n' "${packages[0]}" >> "$GITHUB_OUTPUT"
fi
