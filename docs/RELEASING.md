# Release gate

Publishing remains disabled unless the maintainer explicitly approves a release
and sets the repository variable `ENABLE_NPM_PUBLISH` to `true`. Before enabling:

1. Land reviewed workflow policies on `main`; complete consumer migrations and
   release stable Push Guard 0.4.3. CI temporarily pins the independently reviewed
   scanner commit; replace that checkout with the reviewed stable release later.
2. Configure the GitHub `npm` environment with a required reviewer, prevent
   self-review, and restrict deployment to approved release tags. A workflow's
   environment name alone does not establish these protections.
3. Configure npm Trusted Publishing for this repository, `publish.yml`, and the
   `npm` environment. Set the environment secret `PUSH_GUARD_BLOCKED_TERMS` with
   at least three distinct private terms, one per line. Never commit their values. See
   [npm Trusted Publishing](https://docs.npmjs.com/trusted-publishers/).
4. Review the exact release commit and its passing checks; merge it into `main`.
   Bump to an unpublished stable version, review that commit, then create the
   matching `vX.Y.Z` tag and publish a GitHub release only when authorized.

The workflow requires the matching stable tag to be an ancestor of `main`, runs
all tests, and scans the complete tarball with released Push Guard >=0.4.3 and
required private terms before publishing that same tarball using OIDC. Node 24
provides the npm version needed for trusted publishing. No stored npm token is
used. The release workflow does not run for pull requests or ordinary pushes.

CI runs with no private secrets. It scans every outgoing commit and a complete
npm tarball using the destination-base policy for both scans. A policy added in
the candidate change cannot allow its own findings. Pull requests use the PR
base SHA, existing-branch pushes use the prior SHA, and new branches use main.
The temporary scanner checkout is pinned and has no install dependencies.
These public checks do not replace the private-term gate before publication.

No account settings, environment protections, repository variables, package
versions or release tags are configured automatically by these files. Keep the
publish variable disabled until every prerequisite is verified.
