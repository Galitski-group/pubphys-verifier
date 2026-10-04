// Builds the platform key trust from pinned recovery keys and key record bundles, under the rule of
// protocol/verifier/TRUST.md. Shared by fetch-trust (bundles from a mirror checkout) and the browser
// /verify page (bundles fetched from the mirror); neither reads anything else.
//
// buildTrust({ recovery: [public key], bundleTexts: [string], pinnedRevoked: [key id], anchorOf, warn })
//   anchorOf(text, bundle) -> earliest Bitcoin block height or null; warn(message) for diagnostics.
// Returns { platform_keys, revocations: [{ key_id, anchor_height }] } or throws TrustError.

import { verifyBundle, parseJsonStrict, keyId } from "./pubphys_protocol.js";
import { computeTrust } from "./trust_graph.js";

export class TrustError extends Error {}

export async function buildTrust({ recovery, bundleTexts, pinnedRevoked = [], anchorOf = async () => null, warn = () => {} }) {
  const recoveryIds = new Set(await Promise.all(recovery.map(k => keyId(k))));
  const signerOf = b => b?.envelope?.platform_signature?.key_id;
  const parsed = [];
  for (const text of bundleTexts) {
    try { parsed.push({ text, b: parseJsonStrict(text) }); } catch { warn("a key bundle is not strict JSON; ignored"); }
  }
  // 1. Validate every key and revocation bundle on its own: the signer must be a recovery key or a
  // key some platform-key record in the set introduces, and the bundle must verify against exactly
  // that key. Nothing is trusted yet.
  const candidateKeys = new Map(); // key_id -> public key
  for (const { b } of parsed) {
    if (b?.record?.type === "platform-key" && typeof b.content?.public_key === "string" && (await keyId(b.content.public_key)) === b.content.key_id) {
      candidateKeys.set(b.content.key_id, b.content.public_key);
    }
  }
  const valid = [];
  for (const { text, b } of parsed) {
    const type = b?.record?.type;
    if (type !== "platform-key" && type !== "platform-key-revocation") continue;
    const signer = signerOf(b);
    const keys = recoveryIds.has(signer) ? { recovery_keys: recovery, platform_keys: [] }
      : candidateKeys.has(signer) ? { recovery_keys: recovery, platform_keys: [candidateKeys.get(signer)] } : null;
    if (!keys) continue;
    const { parts } = await verifyBundle(text, keys);
    if (parts.structure === "verified" && parts.content === "verified" && parts.platform === "verified") valid.push({ text, b, type, signer });
  }

  // 2. The trust rule (protocol/verifier/TRUST.md): descendants of a revoked key are trusted only when
  // introduced again by a recovery key or a non-revoked chain, whatever the anchor order; a revocation
  // counts only if its signer's trust does not descend from the key it revokes.
  // Revocations pinned in the verifier's defaults (the revoked-key manifest) count like recovery-signed
  // ones even when the mirror omits their bundles.
  const revocationRecords = valid.filter(v => v.type === "platform-key-revocation");
  const graph = {
    recovery: [...recoveryIds],
    intros: valid.filter(v => v.type === "platform-key").map(v => ({ key: v.b.content.key_id, signer: v.signer })),
    revocations: [...revocationRecords.map(v => ({ target: v.b.content.key_id, signer: v.signer })),
      ...pinnedRevoked.map(k => ({ target: k, signer: [...recoveryIds][0] }))]
  };
  const result = computeTrust(graph);
  const trusted = new Set(result.trusted);
  const revokedSet = new Set(result.revoked);
  const chain = { signing: result.trusted.filter(k => !recoveryIds.has(k)).map(k => candidateKeys.get(k)).filter(Boolean), revoked: new Map(), accepted: [] };
  for (const v of valid) {
    if (v.type === "platform-key") {
      const clean = recoveryIds.has(v.signer) || (trusted.has(v.signer) && !revokedSet.has(v.signer));
      if (clean) chain.accepted.push(v);
      else if (!trusted.has(v.b.content.key_id)) warn(`key ${v.b.content.key_id.slice(0, 16)}… is left out (introduced only by revoked or untrusted key ${v.signer.slice(0, 16)}…)`);
    }
  }
  // Exactly the revocations the rule counted (a counted revocation's signer may since have lost trust);
  // a revoked key's effective record is the counted one with the earliest anchor.
  for (const i of result.counted) {
    const v = revocationRecords[i];
    if (!v) continue; // a pinned revocation: added below if no counted record names the key
    chain.accepted.push(v);
    const prior = chain.revoked.get(v.b.content.key_id);
    if (!prior || (await anchorOf(v.text, v.b) ?? Infinity) < (await anchorOf(prior.text, prior.b) ?? Infinity)) chain.revoked.set(v.b.content.key_id, { text: v.text, b: v.b });
  }
  if (chain.signing.length === 0) throw new TrustError("no platform-key record verifies against the pinned recovery key");

  // Every accepted key record must also be in the log signed by the chain.
  for (const { text } of chain.accepted) {
    const { parts, notes } = await verifyBundle(text, { recovery_keys: recovery, platform_keys: chain.signing });
    if (parts.log !== "verified") throw new TrustError(`a key record is not in a log signed by the chain: ${notes.join("; ")}`);
  }

  const revocations = [];
  for (const kid of pinnedRevoked) {
    if (chain.revoked.has(kid)) continue;
    revocations.push({ key_id: kid, anchor_height: null });
    warn(`key ${kid.slice(0, 16)}… is revoked in the pinned defaults but its revocation is missing from the mirror`);
  }
  for (const [kid, { text, b }] of chain.revoked) {
    const height = await anchorOf(text, b);
    revocations.push({ key_id: kid, anchor_height: height });
    warn(`key ${kid.slice(0, 16)}… revoked${height === null ? " (anchor unknown: records it signed report platform as not checked)" : ` at block ${height}`}`);
  }
  return { platform_keys: chain.signing, revocations };
}
