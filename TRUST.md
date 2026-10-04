# Which platform keys a verifier trusts

Normative for `fetch-trust`, the browser `/verify` page and the PubPhys server (`trust_graph.js`,
its Ruby twin `trust_graph.rb` in the PubPhys repository, and the cases both pass,
`trust_graph_cases.json`). Trust building is verifier configuration (SPEC section 11):
the validity rules of key records (SPEC section 8) are unchanged; this decides which keys a verifier
treats as PubPhys's.

## Input

The pinned recovery key fingerprints, and every `platform-key` and `platform-key-revocation` bundle
found (the mirror's `keys/`). A bundle takes part only if it verifies on its own (structure, content,
and its envelope signature by the key it names: a recovery key, or a key introduced by some
`platform-key` record in the set). Each such record is an edge: an introduction (signer → key) or a
revocation (signer → key).

## Algorithm

1. **Trusted set for a revoked set Rev** (least fixed point from the recovery keys): a key is trusted
   if some introduction of it is signed by a recovery key, or by a trusted key not in Rev. One clean
   introduction suffices; introductions signed by a key in Rev never count, whatever the anchor order;
   unrooted cycles never enter.
2. **Revoked set**, in rounds, only growing. Round 0: every revocation signed by a recovery key. Each
   later round, with Rev as it stood at the start of the round: a revocation of key R signed by S
   qualifies when S is in the trusted set of step 1 for Rev computed **with every introduction signed
   by R ignored**, and S is not in Rev. All revocations that qualify in a round are added together at
   its end. Stop when a round adds nothing.
3. **Result**: the trusted set of step 1 for the final Rev. Keys in Rev stay in it (their own
   introduction may be clean) so that envelopes they signed before their revocation can still count.

Self-revocations and revocations whose target is a recovery key never count (a recovery key is
replaced by a verifier release, not by a record). Revocations listed in the verifier's pinned
`revoked_keys` count as recovery-signed ones even when the mirror omits their bundles.

Consequences: a key introduced by K never revokes K; a key a thief introduced with a stolen K is not
trusted once K is revoked, and cannot revoke the fresh key; a revocation signed by K stops counting
once K is revoked (the ceremony signs it again with the recovery key).

## Envelopes, checkpoints, anchors

- An envelope signed by a revoked key counts when its earliest Bitcoin anchor is before the
  revocation's block (SPEC 8): the earliest anchor among the key's **counted** revocations (a pinned
  revocation without a bundle has no block, so such envelopes are `not_checked`); an unknown anchor gives `not_checked`, never acceptance. Anchors never
  rescue a key introduction or make a revocation count.
- A checkpoint signed only by revoked keys keeps `log: verified` only when its signed-note SHA-256
  equals the revoked key's `last_good_checkpoint.note_sha256` in `revoked_keys` (the verifier's pinned
  defaults, from the revocation ceremony); otherwise `log` is `not_checked`. The `witness` part never
  restores trust in a revoked key. An inclusion promise, or the checkpoint offered as evidence for it,
  signed only by revoked keys is never judged (`not_judged`).
- The copy of the verifier in the PubPhys mirror carries `defaults.json` too; it is no more an anchor
  than the mirror itself. Use an independently obtained release.
