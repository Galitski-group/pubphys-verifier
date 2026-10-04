# PubPhys verifier

Checks PubPhys proof bundles without trusting PubPhys: the record's content, the PubPhys seal against
keys you pin, inclusion in the public log as logged in Sigstore Rekor, the Bitcoin date from
OpenTimestamps, and the author's ORCID sign-in. Node.js 20 or later; no dependencies.

This repository is generated from the PubPhys source (`script/verifier/build_standalone.rb`). Before
every release the maintainers regenerate it and check that the tag holds exactly the generated files
(see `MAINTAINING.md`); the PubPhys source runs the Ruby/JavaScript differential tests. This
repository's own CI runs the tests on Node 20 and 22 and checks `SHA256SUMS`.

Releases are built and signed by the workflow `.github/workflows/release.yml` of
`Galitski-group/pubphys-verifier` on a `v*` tag, with Sigstore build provenance. To check one:

```
gh attestation verify pubphys-verifier-<tag>.tar.gz --repo Galitski-group/pubphys-verifier \
  --signer-workflow Galitski-group/pubphys-verifier/.github/workflows/release.yml
tar xzf pubphys-verifier-<tag>.tar.gz && cd pubphys-verifier-<tag> && sha256sum --check SHA256SUMS
```

The tarball is `git archive` of the tag, so you can also rebuild it from the tag yourself
(`git archive --format=tar.gz --prefix=pubphys-verifier-<tag>/ <tag>`) and compare its SHA-256 with
the release's, without trusting GitHub Actions. `SOURCE` names the PubPhys source commit.

Paths in code comments and in `SPEC.md` refer to the PubPhys source layout.

## Pinned values

`verifier/defaults.json` holds the values a verifier takes on trust from this release, never from
PubPhys or its mirror: the recovery key fingerprint, the ORCID client id of PubPhys, the witness keys
used to judge inclusion promises, and revoked platform keys with their last good checkpoint. Compare
the fingerprint with the PubPhys keys page, the DNS record `_pubphys.pubphys.com` and people you
trust; `--recovery-key-id` overrides it.

## Use

In a clone of the public log (`git clone https://github.com/Galitski-group/pubphys-log`):

```
node <this repo>/verifier/fetch-trust.mjs --dir . --bitcoin > my-trust.json
node <this repo>/verifier/fetch-witness.mjs --bundle bundle.json --trust my-trust.json --dir . \
  --sigstore-trusted-root trusted_root.json --site https://pubphys.com > my-trust-witness.json
node <this repo>/verifier/fetch-orcid-keys.mjs --trust my-trust-witness.json --dir . --live > my-trust-full.json
node <this repo>/verifier/pubphys-verify.mjs bundle.json --trust my-trust-full.json --bitcoin
```

Never use the log repository's own `trust.json` as trust: PubPhys writes it. `trusted_root.json` is
Sigstore's, obtained through its TUF repository (for example with cosign). How keys are trusted and
revoked: `TRUST.md`. The protocol: `SPEC.md`.

## Tests

`npm test` runs the protocol vectors, the trust rule cases and the promise checks (it writes
`vectors/generated/`, which git ignores). The test of a real ORCID token is skipped here: that
fixture is personal and stays in the PubPhys source.
