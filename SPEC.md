# PubPhys protocol, version 1

Status: **frozen, version 1 (2026-10-02)**, after three rounds of independent review of the
specification and both implementations. Normative.
The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

This document fixes every byte that is hashed, signed or stamped by PubPhys, so that anyone can
verify a PubPhys record without trusting the site. Two implementations exist: Ruby
(`lib/pubphys/protocol/`) and JavaScript (`app/javascript/protocol/pubphys_protocol.js`); both
MUST pass every vector in `protocol/vectors/`. The JSON Schemas in `protocol/schemas/` are
normative together with this text.

Design background: `wiki/platform/target-architecture.md`, section 7.

## 1. Encodings

Decoders MUST be strict: any input that is not the canonical encoding of some byte string is
rejected (vectors: `encodings.json`).

- **Text** is UTF-8 without a byte-order mark.
- **Hashes** are SHA-256, written as exactly 64 lowercase hexadecimal characters. Other hex
  values use lowercase, an even number of characters.
- **base64url** (RFC 4648 section 5) is written without padding; a decoder rejects padding,
  characters outside `A-Z a-z 0-9 - _`, a length of 1 modulo 4, and non-zero unused bits.
- **base64** (standard, RFC 4648 section 4) is used only inside signed notes (section 9); it is
  written with padding, and a decoder rejects missing or extra padding and non-zero unused bits.
- **Times** are UTC in the exact form `YYYY-MM-DDTHH:MM:SSZ`, denote a real calendar time, and lie in
  the years 1970 to 9999.
- **Decimal strings** match `^(0|[1-9][0-9]*)$`. Log sizes and indexes are at most
  2^53 - 1 (9007199254740991); the schema limits them to 16 digits and the exact bound is a local
  rule (section 11).
- Numbers and booleans never appear in hashed objects; flags are the strings `"true"` and
  `"false"`.
- **JSON documents** given to a verifier (bundles, trust files, JWT header and payload, JWKs) follow
  one strict profile (vectors: `json.json`): RFC 8259 with no extensions (no comments, no trailing
  commas, no byte-order mark); valid UTF-8; no lone surrogate escapes; no duplicate object keys at
  any depth; nesting depth at most 32; numbers only as integers without fraction or exponent, in
  the range -(2^53 - 1) to 2^53 - 1.

## 2. Canonical form

A hashed object is serialized as follows (vectors: `canonical.json`).

Allowed values: objects, arrays, strings and `null`. A canonicalizer MUST reject numbers,
booleans, keys that are not printable ASCII (0x20 to 0x7E), and strings that are not valid
Unicode (for example lone surrogates).

Serialization (identical to RFC 8785 for this restricted value set):
- no whitespace between tokens;
- object members sorted by key, comparing keys as byte strings;
- strings: `"` and `\` are escaped as `\"` and `\\`; U+0008, U+0009, U+000A, U+000C, U+000D
  are escaped as `\b`, `\t`, `\n`, `\f`, `\r`; every other code point below U+0020 is escaped as
  `\u00` followed by two lowercase hexadecimal digits; every other character, including `/`,
  U+007F, U+2028 and U+2029, is written as itself in UTF-8.

Text typed by people MUST be normalized by the **builder** before hashing: Unicode NFC and line
feeds only. A canonicalizer and a verifier MUST NOT reject a string for not being NFC: they hash
code points exactly as given, so a record's verifiability never depends on a Unicode version.

`H(x)` means SHA-256 of the canonical bytes of object `x`, in lowercase hex.

## 3. Arrays

Every array in a hashed object is sorted and has no duplicates. Strings sort by their UTF-8
bytes. Arrays of objects sort by:

| Array | Sort key |
|---|---|
| `record.files` | `id` |
| `content.parents` (revision) | `parent_revision` |

Any other array of objects in a hashed object is invalid. A verifier MUST reject an unsorted or
duplicated array.

## 4. Record

```
{
  "schema":          "pubphys.record/2",
  "site":            "pubphys.com",
  "type":            <record type>,
  "content_schema":  "pubphys.content.<type>/<version>",
  "content_sha256":  H(content),
  "files":           [ { "id", "name", "media_type", "size", "sha256" } ],
  "parents":         [ <record hashes> ],
  "target":          <record hash> | null,
  "builds_on":       [ <record hashes> ],
  "author":          { "orcid": <ORCID iD> | null, "account_ref": <account ref> | null },
  "origin":          { "kind": "human" | "seed" | "platform", "assisted_by": [ <strings> ] },
  "salt":            <64 lowercase hex characters>,
  "created":         <time>
}
```

`record_hash = H(record)`. Every key is always present.

- `type` matches `^[a-z][a-z-]{0,39}$`; `content_schema` is exactly `pubphys.content.<type>/<n>`
  with `n` a decimal string without leading zeros, at least 1.
- `files[]`: `id` matches `^[a-z0-9-]{1,40}$`; `media_type` is lowercase; `size` is the byte count
  as a decimal string; `sha256` is the hash of the exact file bytes. Only `upload`,
  `import-manifest` and `jwks` records carry files, exactly the one their content names; every
  other record has an empty `files`.
- `author.orcid` matches `^[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{3}[0-9X]$`; `account_ref` matches
  `^[a-z0-9]{8,64}$` (an opaque random identifier, never a username).
- For `origin.kind = human`, exactly one of `orcid` and `account_ref` is non-null. For `seed`
  and `platform`, both are null.
- `salt` is 32 bytes from a cryptographically secure random generator, chosen by the creator.
- `created` is the creator's claim and is never a priority date.

## 5. Content

`content` is a canonical object whose fields are fixed by its content schema
(`protocol/schemas/content.<type>.json` for version 1). Raw bytes (uploads, manifests, JWKS
documents) are never content: they are files listed in `record.files`, and the content object
names them by file id.

References between records are record hashes. A problem is identified by the record hash of its
first revision (`problem_ref`), a topic by the record hash of its first topic revision
(`topic_ref`).

Field keys match `^[a-z]{2,8}$`. The list of fields is a policy document
(`protocol/fields.json`) that may grow; it is not part of the frozen format.

## 6. Record types (content version 1)

| Type | Allowed origin | Content (strings unless noted) | `target` | `parents` |
|---|---|---|---|---|
| `topic` | human, seed | `topic_ref`, `n`, `external_id`, `field`, `title`, `summary`, `why`, `review_cite`, `review_link`, `review_verified` | null | at most one (the prior topic revision) |
| `revision` | human, seed | `problem_ref`, `n`, `external_id`, `topic_ref`, `title`, `plain`, `precise`, `settled_by`, `kind`, `answer_type`, `references`, `literature_status`, `status_note`, `posed_since`, `assisted_by` (array), `parents` (array of `{parent_revision, relation, note}`) | null | prior revision, declared parent revisions, source uploads, import manifest |
| `upload` | human | `purpose`, `ai_consent`, `file_id` | null | none |
| `claim` | human | `problem_ref`, `kind`, `body`, `references`, `assisted_by` (array) | the revision answered | source uploads |
| `contest` | human | `grounds`, `quoted_locator`, `quoted_text`, `body`, `references` | the claim or review contested | source uploads |
| `appeal` | human | `reasons` | the review appealed | none |
| `review` | human, platform | `decision`, `reasons`, `params` (object of strings) | the record decided on | none |
| `withdrawal` | human | `reason` | the claim withdrawn | none |
| `reveal` | human | `note` | the sealed record | none |
| `appointment` | human, platform | `subject_orcid`, `field` (a field key or `*`), `role`, `action` | null for `appoint`; the appointment record for `revoke` | none |
| `attribution` | human, platform | `subject`, `new_author_orcid`, `new_account_ref`, `reason` | null | none |
| `import-manifest` | platform | `source`, `as_of`, `predicate`, `counts` (object of decimal strings), `items_file_id` | null | none |
| `platform-key` | platform | `key_id`, `public_key`, `previous_key_id`, `new_key_signature` | null | the prior `platform-key` record, if any |
| `platform-key-revocation` | platform | `key_id`, `reason` | the `platform-key` record | none |
| `jwks` | platform | `url`, `jwks_file_id`, `captures` (array of URLs) | null | none |

Rules a verifier checks (vectors: `records.json`):
- `n` is a decimal string, at least 1.
- `topic`: `topic_ref` is null exactly when `n` is `1`; `parents` is empty when `n` is `1`.
- `revision`: `problem_ref` is null exactly when `n` is `1`; `topic_ref` is non-null exactly when
  `n` is `1`; `content.parents` is empty unless `n` is `1`; `external_id` is non-null only for
  `origin.kind = seed`.
- File ids named in content (`file_id`, `items_file_id`, `jwks_file_id`) exist in `record.files`.
- `revision`: every `content.parents[].parent_revision` also appears in `record.parents`.
- `appointment`: subjects of appointments are always ORCID iDs (moderators and referees must have
  ORCID).
- `attribution`: exactly one of `new_author_orcid` and `new_account_ref` is non-null.
- `platform-key`: `previous_key_id` differs from `key_id`; `parents` is empty when
  `previous_key_id` is null and holds exactly one hash (the predecessor's record) otherwise.
- Review params: `problem_ref` and `topic_ref` are record hashes; `credited` is a non-empty string.

These are **local** rules: a bundle carries one record, so a verifier cannot check what a
referenced hash points to (that a claim targets a revision, that a parent is the predecessor key's
record). Those graph relationships are checked by whoever resolves the referenced records, such as
the site or an archive, and are outside the bundle verdict.

Enumerations are listed in the schemas. Review decisions and their exact `params`:

| Decision | `params` keys (all required, no others) |
|---|---|
| `accept`, `reject`, `screening_reject`, `recommend`, `not_recommend`, `triage_substantive`, `triage_not_substantive`, `uphold`, `dismiss`, `reverse`, `remove`, `appeal_grant`, `appeal_deny` | none |
| `credit` | `credited` (a record hash, or a citation of the earlier work) |
| `carry_acceptance`, `verify_note` | `problem_ref` |
| `reassign_topic` | `problem_ref`, `topic_ref` (the new topic) |

`new_key_signature` in `platform-key` is the new key's Ed25519 signature, base64url, over the
ASCII bytes `pubphys.platform-key/1\n` followed by `key_id`.

## 7. Attested record

```
{
  "schema": "pubphys.attested/1",
  "record_hash": <record hash>,
  "attestation": {
    "kind": "orcid-oidc" | "platform" | "none",
    "batch": [ <record hashes> ] | null,
    "id_token_sha256": <hash> | null,
    "client_id": <ORCID client id> | null
  }
}
```

`attested_hash = H(attested)`. A record has exactly one attested object.

| Kind | Required origin and author | `batch`, `id_token_sha256`, `client_id` |
|---|---|---|
| `orcid-oidc` | `human`, `author.orcid` non-null | all non-null; `batch` sorted, unique, containing `record_hash` |
| `platform` | `seed` or `platform` | all null |
| `none` | `human`; `author.orcid` null except for `upload` records (attested through the revision that uses them) | all null |

### 7.1 Batch nonce

1. Take the batch: record hashes, lowercase hex, sorted, deduplicated.
2. Join them with a single LF (0x0A) between hashes, no trailing LF.
3. `inner = hex(SHA-256(joined))`.
4. `nonce = hex(SHA-256("pubphys.attest/1\n" || inner))`.

### 7.2 ORCID id_token checks

For `orcid-oidc`, a verifier MUST check:
1. the token is exactly three base64url segments separated by `.`; header and payload are JSON
   objects without duplicate keys;
2. `SHA-256(token ASCII) = id_token_sha256`;
3. header `alg` is `RS256` and `kid` is a string; the signature verifies with a **trusted** ORCID
   key (7.3) whose `kid` matches; the key is RSA with a modulus of at least 2048 bits;
4. payload `iss` is the string `https://orcid.org`;
5. payload `aud` is a string equal to `client_id`, and `client_id` is one the verifier trusts;
6. payload `sub` equals `record.author.orcid`;
7. payload `nonce` equals the nonce of `batch`, and `record_hash` is in `batch` (the latter is also
   a structure rule, checked even when the token is withheld);
8. payload `iat` is a non-negative integer; if the earliest valid Bitcoin anchor time `A` of the
   record is known, `A - 72 h <= iat <= A + 2 h`;
9. `exp` and `auth_time` are ignored.

Claims 4 to 8 are checked before the key lookup, so a token whose claims contradict the record
fails even when no trusted key is available. Every trusted key with a matching `kid` is tried.

### 7.3 ORCID keys come from the verifier

The bundle never supplies trusted keys. A verifier obtains ORCID keys itself: from ORCID's live
JWKS (`https://orcid.org/oauth/jwks`), fetched by the verifier over HTTPS, or from captured keys
the verifier has validated independently (a capture is valid for tokens whose `iat` lies between
24 hours before its first and 24 hours after its last independent capture). If no trusted key
matches the token's `kid`, identity is `not_checked`, never `verified`.

A bundle MAY carry `orcid_key_evidence`: copies of keys and capture URLs to help a verifier find
them. A verifier MUST NOT use this evidence as a trust anchor.

## 8. Envelope and platform keys

```
{
  "schema": "pubphys.envelope/1",
  "attested_hash": <attested hash>,
  "platform_signature": { "key_id": <key id>, "sig": <base64url> }
}
```

`envelope_hash = H(envelope)`.

- Platform keys are Ed25519. `key_id` = hex SHA-256 of the 32-byte raw public key.
- `sig` is the Ed25519 signature over the ASCII bytes `pubphys.platform/1\n` followed by
  `attested_hash` (64 lowercase hex characters).
- A verifier is configured with trusted **signing keys** and trusted **recovery keys** (pinned
  out of band: documentation, DNS, the verifier repository). Envelopes MUST be signed by a signing
  key.
- **Rotation.** A `platform-key` record is valid when: `key_id` matches `public_key`;
  `new_key_signature` verifies with `public_key`; and its envelope is signed by the key named in
  `previous_key_id`, or by a recovery key. The first key has `previous_key_id = null` and its
  envelope is signed by a recovery key.
- **Revocation** (`platform-key-revocation`, signed by a recovery key or by a signing key other than
  the revoked one; a key never revokes itself):
  envelopes signed by the revoked key whose earliest anchor is in the revocation's anchor block or
  later no longer count as platform-received. Evaluating this needs anchors (section 14).

### 8.1 Domain separation

Every signed or hashed message family starts differently, so no message of one family can be
read as another: `pubphys.platform/1\n...`, `pubphys.platform-key/1\n...`, `pubphys.attest/1\n...`,
signed notes starting `pubphys.com/log/v1\n` (checkpoints) or `pubphys.com/log/v1 promise\n`
(promises), leaf hashes prefixed with 0x00, node hashes prefixed with 0x01.

## 9. Transparency log

**Leaf.** Leaf data is the canonical bytes of `{"envelope_hash": ..., "record_type": ...}`.
Tree hashing, inclusion proofs and consistency proofs follow RFC 9162 sections 2.1.1 to 2.1.4:
`leaf_hash = SHA-256(0x00 || data)`, `node = SHA-256(0x01 || left || right)`, the empty tree's
hash is SHA-256 of the empty string. Conventions where the RFC is silent: the consistency proof
between equal sizes is empty and requires equal roots; from size 0 it is empty. Indexes start at 0.

**Signed notes** follow C2SP signed-note as implemented by `golang.org/x/mod/sumdb/note`:
- the whole note is valid UTF-8 and contains no ASCII control character except LF;
- it is split at the **last** occurrence of an empty line (`\n\n`): the text is everything up to
  and including the first of those two LFs, and the signature block follows and ends with LF;
- each signature line is `— <name> <base64>`: U+2014, a space, the name up to the next space, then
  standard base64 with padding, canonical; the name is non-empty and contains neither `+` nor any
  character of Go's `unicode.IsSpace` (tab, LF, VT, FF, CR, space, U+0085, U+00A0, U+1680,
  U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F, U+3000); the decoded value is a 4-byte key hash
  followed by the 64-byte Ed25519 signature; at most 100 signature lines;
- lines by unknown keys are ignored, but any line by a known name and key hash whose signature
  does not verify makes the whole note invalid (stricter than Go, which skips a repeated name and
  key hash before verifying it);
- the key name is `pubphys.com/log/v1`; the key hash is the first 4 bytes of
  `SHA-256(name || 0x0A || 0x01 || public key)`; the signed message is the text.

**Checkpoint** text (C2SP tlog-checkpoint, exactly three lines, no extension lines):
```
pubphys.com/log/v1
<tree size, decimal string>
<root hash, standard base64 with padding, 32 bytes>
```

**Inclusion promise** text (exactly five lines):
```
pubphys.com/log/v1 promise
<leaf hash, lowercase hex>
<leaf index, decimal string>
<issued, time>
<deadline, time>
```
The deadline is at most two hours after the issue time. When a bundle carries a promise, the
verifier checks its signature, its format and that it names the bundle's leaf hash and index. That
the leaf reached a witnessed checkpoint before the deadline is judged against the witness's
publication time (section 14).

**Witnessing.** Every checkpoint is stamped and published to Sigstore Rekor. A verifier obtains a
witnessed checkpoint independently (from Rekor or a mirror it trusts) of the **same size or
larger** than the bundle's checkpoint, together with a consistency proof from the bundle's
checkpoint to the witnessed one. An older witnessed checkpoint proves nothing about the bundle's
leaf (a private fork could extend it), so it leaves the witness part `not_checked`; so does having
no witnessed checkpoint.

## 10. Bundle

A bundle is one JSON document (not hashed itself, no duplicate keys):

```
{
  "schema": "pubphys.bundle/1",
  "record": {...},
  "content": {...} | null,
  "content_withheld": "true" | "false",
  "files": [ { "id": ..., "data": <base64url> | null } ],
  "attested": {...},
  "id_token": <compact JWT> | null,
  "id_token_withheld": "true" | "false",
  "envelope": {...},
  "ots": { "attested": [ <base64url .ots> ], "envelope": [ <base64url .ots> ] },
  "log": { "leaf_index": <decimal>, "tree_size": <decimal>, "proof": [ <hex> ], "checkpoint": <signed note>, "promise": <signed note> | null },
  "orcid_key_evidence": [ { "jwk": {...}, "captures": [ <urls> ] } ],
  "attesting": <bundle> | null
}
```

- `files` lists exactly the record's files, each id once; `data: null` means withheld.
- **Withheld content** (removal for copyright, personal data or abuse): `content: null` and
  `content_withheld: "true"`. Otherwise `content` is present and `content_withheld` is `"false"`.
- **Withheld identity** (account deletion): `id_token: null` and `id_token_withheld: "true"`.
  Otherwise the token is present and the flag is `"false"`; for kinds other than `orcid-oidc` the
  token is null and the flag `"false"`.
- **OpenTimestamps**: each entry is non-empty canonical base64url (checked as structure); each array
  holds every stamping attempt for that digest (the browser's and
  the server's, and resubmissions). An `.ots` proof's initial digest is the 32 raw bytes of
  `attested_hash` or `envelope_hash`, which equals the OpenTimestamps file digest of the
  canonical attested or envelope bytes. The earliest valid anchor of any proof counts.
- `attesting` (only for an `upload` record) is the bundle of a record that lists the upload in
  `parents`, whose attestation kind is `orcid-oidc`, whose type is not `upload`, and whose own
  `attesting` is null (depth one).

## 11. Verification

A verifier reports each part as `verified`, `failed`, `withheld`, `not_checked` or
`not_applicable` (vectors: `bundles.json`):

| Part | Checks |
|---|---|
| `structure` | the JSON profile, schemas, array order, the local rules of sections 4, 6, 7 and 10, and the same checks on an `attesting` bundle; `not_checked` when the content schema is unknown or the content is withheld (content rules cannot be checked) |
| `content` | `content_sha256`, every file's `sha256` and `size`, the `record_hash` -> `attested_hash` -> `envelope_hash` chain; `withheld` when content or file data is withheld and everything present checks out |
| `identity` | section 7.2 for `orcid-oidc` (`not_checked` without a trusted key, `withheld` for a withheld token); for an `upload` naming an ORCID iD, the attesting bundle must not fail content, platform or log and its identity and author must match (`not_checked` without an attesting bundle); otherwise `not_applicable` (no ORCID iD is claimed) |
| `platform` | the envelope signature with a trusted signing key; rotation rules for `platform-key` records |
| `log` | the checkpoint signature with a trusted signing key, the leaf hash, the inclusion proof, and the inclusion promise when present |
| `witness` | consistency between the bundle's checkpoint and an independently obtained witnessed checkpoint |
| `time` | OpenTimestamps proofs against Bitcoin block headers |

If `structure` fails, every other part is `not_checked`: a verifier never draws conclusions from
a malformed bundle. A verifier never throws on malformed input; it reports `failed`. Strings that
are not valid Unicode fail structure. Trust is verifier configuration: a missing or malformed
trust entry is treated as absent. An `attesting` bundle is verified with the same trust except
`earliest_anchor` and `witness`, which describe the outer record. For `platform-key` and
`platform-key-revocation` records with withheld content or an unknown content version, platform
is `not_checked`.

An unknown record type or content schema version yields `structure: not_checked` (the verifier is
older than the record); array-order rules are then not applied to the content, and the hash chain
is still checked. An unknown version of the record, attested, envelope or bundle schema fails
structure: those are the frame every verifier must understand. In particular, a new attestation
kind requires `pubphys.attested/2`.

Priority: records whose earliest anchors are within 36 blocks of each other are simultaneous;
otherwise the lower block height has priority.

## 12. Schemas

`protocol/schemas/` holds JSON Schema (draft 2020-12) documents. Implementations validate with
this keyword subset: `type`, `required`, `properties`, `additionalProperties` (false or a
schema), `enum`, `const`, `pattern`, `items`, `minItems`, `maxItems`. `pattern` uses ECMA-262
semantics without the multiline flag, matched against the whole string (every pattern begins with
`^` and ends with `$`, which anchor the whole string, never a line; patterns use ASCII only, so the
Unicode flag makes no difference). Property names are compared as own keys.

## 13. Versioning and freeze

After the freeze, `pubphys.record/2`, `pubphys.attested/1`, `pubphys.envelope/1`,
`pubphys.bundle/1`, every `pubphys.content.<type>/1`, the log formats and the vectors MUST NOT
change. New record types and new content schema versions (`pubphys.content.<type>/2`) are added
under new names, which the record schema already admits; new attestation kinds need a new
attested schema version. Verifiers keep supporting every frozen version.

## 14. Not covered by phase 0 vectors

These depend on live Bitcoin anchors or live services and are tested from phase 1b on: `time`
verification with real OpenTimestamps proofs (parsing included), the `iat` window against an anchor
computed from proofs, revocation by anchor block, the simultaneity window, fetching witnessed
checkpoints from Rekor, and judging promise fulfillment against the witness's publication time.

Besides the vectors, `protocol/test/differential/` runs a deterministic differential fuzz of both
implementations (mutated bundles, strict JSON, times, signed notes), and `protocol/bin/check` runs
it with every test. The vectors exercise the witness check with a supplied witnessed checkpoint.
