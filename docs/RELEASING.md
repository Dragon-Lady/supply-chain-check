# Release gate

Publishing remains disabled unless the maintainer explicitly approves a release
and sets the repository variable `ENABLE_NPM_PUBLISH` to `true`. Before enabling:

1. Land reviewed workflow policies on `main`; complete consumer migrations and
   release stable Push Guard 0.4.3. CI temporarily pins the independently reviewed
   scanner commit; replace that checkout with the reviewed stable release later.
   Add the verified PyPI wheel SHA-256 to `.github/requirements/push-guard.txt`;
   the exact `==0.4.3` pin with `--require-hashes` blocks publication until then.
2. Configure the GitHub `npm` environment with required maintainer approval
   and restrict deployment to `v*` release tags, with administrator bypass off.
   For a repository with one maintainer, self-review must remain permitted so
   that maintainer can approve a release they initiated. This is manual approval,
   not independent-person review. A workflow environment name alone does not
   establish these protections.
3. Configure npm Trusted Publishing for this repository, `publish.yml`, and the
   `npm` environment. Set the environment secret `PUSH_GUARD_BLOCKED_TERMS` with
   at least three distinct private terms, one per line. Never commit their values. See
   [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/).
4. Review the exact release commit and its passing checks; merge it into `main`.
   Bump to an unpublished stable version, review that commit, then create the
   matching `vX.Y.Z` tag and publish a GitHub release only when authorized.

The workflow requires the matching stable tag to be an ancestor of `main`, runs
all tests, and scans the complete tarball in a preparation job without OIDC.
That job uses the hash-pinned Push Guard wheel and required private terms. It
uploads the scanned tarball and passes its SHA-256 and artifact ID through job
outputs. The separate OIDC job downloads that ID, verifies the exact tarball
digest, and publishes with scripts disabled. It never checks out source or runs
tests. Both jobs use the protected `npm` environment; approve only the reviewed
release. Its private-term secret is used only by the preparation scan. Node 24
provides the npm version needed for trusted publishing. No stored npm token is
used. The release workflow does not run for pull requests or ordinary pushes.

CI runs with no private secrets. It scans every outgoing commit and a complete
npm tarball using the destination-base policy for both scans. A policy added in
the candidate change cannot allow its own findings. Pull requests use the PR
base SHA; all push events use `origin/main`, never the prior branch tip.
Require **Push Guard PR gate** in branch protection with strict/up-to-date checks;
the push job has a distinct name, **Push Guard main-policy scan**, and cannot
satisfy the PR check. Set the required check only after the new workflow has
reported it successfully.
The temporary scanner checkout is pinned and has no install dependencies.
These public checks do not replace the private-term gate before publication.

No account settings, environment protections, repository variables, package
versions or release tags are configured automatically by these files. Keep the
publish variable disabled until every prerequisite is verified.
