// The platform key trust rule (wiki/platform/phase-2-plan.md section 11; normative text in
// protocol/verifier/TRUST.md). Trust building is verifier configuration (SPEC 11): record validity is
// unchanged, only which keys a verifier trusts. Pure function over a graph of already validated key
// records, shared by fetch-trust and the browser; lib/pubphys/protocol/trust_graph.rb is its twin and
// protocol/test/trust_graph_cases.json keeps them identical.
//
// graph: { recovery: [keyId], intros: [{ key, signer }], revocations: [{ target, signer }] }
// result: { trusted: [keyId] (sorted), revoked: [keyId] (sorted), counted: [index into revocations] (sorted) }
// Only counted revocations take effect; a caller that needs a revocation's record (its anchor) must
// pick it among the counted ones.

// Least fixed point from the recovery keys: a key is trusted if some introduction of it is signed by
// a recovery key, or by a trusted key that is not revoked. Introductions signed by +ignore+ do not
// count (used when judging a revocation of that key).
function trustedSet(graph, revoked, ignore = null) {
  const recovery = new Set(graph.recovery);
  const trusted = new Set();
  let grew = true;
  while (grew) {
    grew = false;
    for (const { key, signer } of graph.intros) {
      if (trusted.has(key) || signer === ignore) continue;
      if (recovery.has(signer) || (trusted.has(signer) && !revoked.has(signer))) { trusted.add(key); grew = true; }
    }
  }
  return trusted;
}

export function computeTrust(graph) {
  const recovery = new Set(graph.recovery);
  const revoked = new Set();
  const counted = new Set();
  const id = (_r, i) => i;
  // Self-revocations and revocations of recovery keys never count (replacing a recovery key is a
  // verifier release, not a record).
  const inert = r => r.target === r.signer || recovery.has(r.target);
  // Round 0: revocations signed by a recovery key.
  graph.revocations.forEach((r, i) => { if (!inert(r) && recovery.has(r.signer)) { revoked.add(r.target); counted.add(id(r, i)); } });
  // Later rounds: every revocation that qualifies against the revoked set as it stood at the start of
  // the round is added together at the end of it. The revoked set only grows, so this terminates.
  for (;;) {
    const qualifying = [];
    graph.revocations.forEach((r, i) => {
      if (counted.has(id(r, i)) || recovery.has(r.signer) || inert(r)) return;
      const withoutTarget = trustedSet(graph, revoked, r.target); // the signer must not owe its trust to the target
      if (withoutTarget.has(r.signer) && !revoked.has(r.signer)) qualifying.push([r, i]);
    });
    if (qualifying.length === 0) break;
    for (const [r, i] of qualifying) { revoked.add(r.target); counted.add(id(r, i)); }
  }
  return { trusted: [...trustedSet(graph, revoked)].sort(), revoked: [...revoked].sort(), counted: [...counted].sort((a, b) => a - b) };
}
