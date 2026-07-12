# Releasing

Releases are automated: pushing a version tag builds, tests on the full
OS × Node matrix, publishes to npm **with provenance**, and creates a GitHub
Release from the matching `docs/CHANGELOG.md` section.

## Cutting a release

1. Roll the `[Unreleased]` section of `docs/CHANGELOG.md` into a new
   `## [X.Y.Z] - YYYY-MM-DD` section (leave a fresh empty `[Unreleased]`).
2. Bump `version` in `package.json` to `X.Y.Z`.
3. Land those changes on `main` (via PR).
4. Tag and push:

   ```bash
   git checkout main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

That's it. The `Release` workflow does the rest. A version-guard step fails
the release if the tag and `package.json` disagree.

## Rehearsing

Actions → **Release** → *Run workflow* with `dry-run` checked runs the entire
pipeline (matrix, guard, `npm publish --dry-run`) without publishing anything.
Do this after any change to `release.yml`.

## One-time setup (maintainer)

Publishing uses **npm trusted publishing (OIDC)** — no npm token is stored
anywhere in GitHub.

1. **npmjs.com** → package `skopecreep` → Settings → Publishing access →
   *Add trusted publisher*: GitHub Actions, repository
   `Gprad-Work/skopecreep`, workflow `release.yml`, environment `release`.
   Then set publishing access to *Require two-factor authentication and
   disallow tokens*, and revoke any existing automation tokens.
2. **GitHub repo** → Settings → Environments → create `release`
   (optionally restricted to `v*` tag refs).
3. **Branch protection** on `main`: require the `ci-ok` and `CodeQL` checks,
   require one PR review, require branches up to date, block force-pushes.

## Verifying a published release

```bash
npm view skopecreep dist-tags
# in any project that depends on skopecreep:
npm audit signatures
```

The npm package page shows a provenance badge linking the tarball to the
exact workflow run and commit that built it.
