# Maintaining the PubPhys verifier

## Releasing

1. In the PubPhys source, at the commit to release: `bin/ci` (includes the Ruby/JavaScript
   differential tests and the generator's own test).
2. Regenerate into a clean directory: `ruby script/verifier/build_standalone.rb <dir>`; copy it over a
   checkout of this repository (keeping `.git`), commit, and run
   `ruby script/verifier/build_standalone.rb --check <checkout>`: it fails on any changed, missing or
   extra file.
3. Push, wait for CI, then push a signed tag `vX.Y.Z`. The release workflow attests and publishes the
   tarball.
4. Point the PubPhys mirror and the `/verify` page at the release (tag, commit, tarball SHA-256).

## Access

- Only the maintainers named in the organisation can push to `main` or create `v*` tags; protect
  both with rulesets (no force pushes, no deletion, signed tags required).
- Review every change to `.github/workflows/`; actions are pinned by commit SHA and updated
  deliberately.
- When a maintainer leaves: remove their organisation access, review deploy keys and tokens, check
  the tag ruleset and the recent tags, and note it in the next release.
- A bad release: publish a fixed release, mark the bad one as such in its release notes, and say so
  on the PubPhys keys page. Attestations cannot be withdrawn; the notes are the record.
