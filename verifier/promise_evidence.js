// Judging an inclusion promise (wiki/platform/phase-2-plan.md section 7, decision 6). fetch-witness
// collects the evidence from the mirror; pubphys-verify and the browser /verify page re-check it here
// with nothing but the bundle and the verifier's trust (platform keys and pinned witness keys).
//
// evidence: { checkpoint: <PubPhys signed note>, consistency: [hex], rekor_entry: <Rekor v2 entry> }
// A promise is "kept" when a PubPhys checkpoint with size > leaf_index, consistent with the bundle's
// checkpoint, was logged in Rekor and a pinned witness cosigned a Rekor checkpoint covering that entry
// at or before the deadline. Otherwise "not_judged": the mirror is written by PubPhys and may omit
// entries, so offline verifiers never report "missed".

import { parseNote, verifyNote, parseCheckpoint, parsePromise, verifyConsistency, verifyInclusion, leafHashRaw,
  sha256, ed25519Verify, fromB64, fromHex, b64, b64url, keyId, LOG_NAME, parseTime, leafHash, canonical, hex as toHex } from "./pubphys_protocol.js";

const enc = new TextEncoder();
const hex = bytes => Array.from(bytes, x => x.toString(16).padStart(2, "0")).join("");

async function keyHash(name, key) {
  return (await sha256(new Uint8Array([...enc.encode(name), 0x0a, 0x04, ...key]))).slice(0, 4);
}

// A witness verifier key in the C2SP vkey form "name+keyhash+base64(0x04 || key)".
export async function parseWitnessKey(vkey) {
  if (typeof vkey !== "string") return null;
  const i = vkey.indexOf("+"), j = vkey.indexOf("+", i + 1); // the base64 key may itself contain "+"
  if (i <= 0 || j < 0) return null;
  const [name, hashHex, keyB64] = [vkey.slice(0, i), vkey.slice(i + 1, j), vkey.slice(j + 1)];
  if (!/^[0-9a-f]{8}$/.test(hashHex)) return null;
  let raw;
  try { raw = fromB64(keyB64); } catch { return null; }
  if (raw.length !== 33 || raw[0] !== 0x04) return null;
  const key = raw.slice(1);
  if (hex(await keyHash(name, key)) !== hashHex) return null;
  return { name, key, keyHash: hashHex };
}

// The cosignature/v1 lines of a note that verify against pinned witness keys. A line counts only by
// pinned name and key hash (never by its length); the rest are reported as unverified.
export async function cosignatures(noteText, witnessKeys) {
  const note = parseNote(noteText);
  const origin = note.lines[0];
  const verified = [], unverified = [];
  for (const s of note.sigs) {
    if (s.name === origin) continue; // the log's own signature line
    let ok = false;
    for (const w of witnessKeys) {
      if (w.name !== s.name || hex(s.keyHash) !== w.keyHash || s.signature.length !== 72) continue;
      const ts = s.signature.slice(0, 8);
      let t = 0n;
      for (const b of ts) t = (t << 8n) | BigInt(b);
      if (t > BigInt(Number.MAX_SAFE_INTEGER)) continue;
      const msg = enc.encode(`cosignature/v1\ntime ${t}\n` + note.body);
      if (await ed25519Verify(w.key, s.signature.slice(8), msg)) { verified.push({ name: s.name, time: Number(t) }); ok = true; break; }
    }
    if (!ok) unverified.push(s.name);
  }
  return { body: note.body, lines: note.lines, verified, unverified };
}

// The key ids among +platformKeys+ whose signature on a PubPhys note verifies.
async function signersOf(text, platformKeys) {
  const out = [];
  for (const pk of platformKeys) if (await verifyNote(text, LOG_NAME, [pk])) out.push(await keyId(pk));
  return out;
}

// A Rekor shard from Sigstore's trusted root, as fetch-witness wrote it: { url, log_id, public_key }
// (base64 raw Ed25519). The log id must be the C2SP key hash of host and key.
async function shardFor(entry, shards) {
  for (const s of shards || []) {
    if (s?.log_id !== entry?.logId?.keyId) continue;
    let raw, host;
    try { raw = fromB64(s.public_key); host = new URL(s.url).host; } catch { continue; }
    if (raw.length !== 32) continue;
    if (b64(await sha256(new Uint8Array([...enc.encode(host), 0x0a, 0x01, ...raw]))) === s.log_id) return { host, raw };
  }
  return null;
}

// Returns null without a promise, else { status: "kept" | "not_judged", notes }. A promise or an
// evidence checkpoint signed only by revoked keys is never judged (revoked keys stay in
// platform_keys for history, so a thief could sign a fresh promise with one).
export async function judgePromise(bundle, trust) {
  const promiseText = bundle?.log?.promise;
  if (typeof promiseText !== "string") return null;
  const notJudged = note => ({ status: "not_judged", notes: [`promise: ${note}`] });
  try {
    const promise = parsePromise(parseNote(promiseText));
    const deadline = parseTime(promise.deadline);
    // The promise must be for this bundle's leaf (verifyBundle checks it too; this function does not rely on it).
    const envelopeHash = toHex(await sha256(enc.encode(canonical(bundle.envelope))));
    if (promise.leafIndex !== Number(bundle.log.leaf_index) || promise.leafHash !== toHex(await leafHash(envelopeHash, bundle.record?.type))) {
      return notJudged("the promise is for another leaf");
    }
    const evidence = trust?.promise_evidence;
    if (!evidence || typeof evidence !== "object") return notJudged("no witness evidence (run fetch-witness)");
    const witnessKeys = (await Promise.all((trust.witness_keys || []).map(parseWitnessKey))).filter(Boolean);
    if (witnessKeys.length === 0) return notJudged("no pinned witness keys");

    const revoked = new Set([...(trust.revocations || []), ...(trust.revoked_keys || [])].map(r => r?.key_id));
    const promiseSigners = await signersOf(promiseText, trust.platform_keys || []);
    if (!promiseSigners.length || promiseSigners.every(k => revoked.has(k))) return notJudged("the promise is signed only by a revoked or unknown key");
    const note = await verifyNote(evidence.checkpoint, LOG_NAME, trust.platform_keys || []);
    if (!note) return notJudged("the evidence checkpoint is not signed by a trusted platform key");
    if ((await signersOf(evidence.checkpoint, trust.platform_keys || [])).every(k => revoked.has(k))) return notJudged("the evidence checkpoint is signed only by a revoked key");
    const cp = parseCheckpoint(note);
    if (!(cp.treeSize > promise.leafIndex)) return notJudged("the evidence checkpoint does not cover the promised leaf");
    const own = parseCheckpoint(parseNote(bundle.log.checkpoint));
    const proof = (evidence.consistency || []).map(fromHex);
    const [small, big] = own.treeSize <= cp.treeSize ? [own, cp] : [cp, own];
    if (!(await verifyConsistency(small.treeSize, big.treeSize, proof, small.root, big.root))) return notJudged("the evidence checkpoint is not consistent with the bundle's");

    const entry = evidence.rekor_entry;
    const body = fromB64(entry?.canonicalizedBody || "");
    const data = JSON.parse(new TextDecoder().decode(body))?.spec?.hashedRekordV002?.data;
    if (data?.algorithm !== "SHA2_256" || b64url(fromB64(data.digest || "")) !== b64url(await sha256(enc.encode(evidence.checkpoint)))) {
      return notJudged("the Rekor entry is not for the evidence checkpoint");
    }
    const p = entry.inclusionProof;
    const shard = await shardFor(entry, trust.rekor_shards);
    if (!shard) return notJudged("the Rekor entry's log is not a Sigstore shard in the trust file (run fetch-witness)");
    if (!(await verifyNote(p.checkpoint.envelope, shard.host, [b64url(shard.raw)]))) return notJudged("the Rekor checkpoint is not signed by its shard key");
    const cos = await cosignatures(p.checkpoint.envelope, witnessKeys);
    if (cos.lines[0] !== shard.host) return notJudged("the Rekor checkpoint's origin is not its shard");
    const [, rekorSize, rekorRoot] = cos.lines;
    if (rekorSize !== p.treeSize || rekorRoot !== p.rootHash) return notJudged("the Rekor checkpoint does not match the inclusion proof");
    if (!(await verifyInclusion(Number(p.logIndex), Number(p.treeSize), await leafHashRaw(body), p.hashes.map(h => fromB64(h)), fromB64(p.rootHash)))) {
      return notJudged("the Rekor inclusion proof does not verify");
    }
    const notes = [...new Set(cos.unverified)].slice(0, 5).map(n => `promise: cosignature by ${n} unverified (ignored)`);
    if (cos.verified.length === 0) return { status: "not_judged", notes: [...notes, "promise: no verified witness cosignature"] };
    const first = cos.verified.reduce((a, b) => (b.time < a.time ? b : a));
    const when = new Date(first.time * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
    if (first.time <= deadline) return { status: "kept", notes: [...notes, `promise: kept, cosigned by ${first.name} at ${when} (deadline ${promise.deadline})`] };
    return { status: "not_judged", notes: [...notes, `promise: earliest verified cosignature ${when} is after the deadline ${promise.deadline}; an earlier witnessed checkpoint may exist`] };
  } catch (e) {
    return notJudged(e.message);
  }
}
