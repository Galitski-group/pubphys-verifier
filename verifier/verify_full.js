// The complete verification of a bundle as pubphys-verify and the browser /verify page run it: the
// frozen verifier (verifyBundle, SPEC 11) plus the verifier-side policy around it. Time first (the
// earliest Bitcoin anchor feeds the ORCID iat window and the revocation comparison), live ORCID keys
// only while fresh, envelopes and checkpoints of revoked keys (protocol/verifier/TRUST.md), and the
// inclusion promise (kept or not judged).
//
// verifyFull(bundleText, trust, { getHeader }) -> { parts, notes, recordHash, promise }
//   trust is modified (earliest_anchor, orcid_keys); getHeader is an Esplora header source or null.

import { verifyBundle, parseJsonStrict, fromB64url, fromHex, canonical, verifyNote, keyId, LOG_NAME, sha256hex } from "./pubphys_protocol.js";
import { verifyOts } from "./ots.js";
import { judgePromise } from "./promise_evidence.js";

async function sha256Hex(obj) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(obj))));
  return Array.from(d, x => x.toString(16).padStart(2, "0")).join("");
}

// An envelope of a revoked key against the revocation's block: the earliest anchor of the envelope
// hash itself must come before it; anything unknown is not_checked, never acceptance.
export function judgeRevocation(envelopeHeight, revocationHeight) {
  if (!Number.isSafeInteger(envelopeHeight) || !Number.isSafeInteger(revocationHeight)) {
    return { platform: "not_checked", note: "platform: signed by a revoked key; the anchors of the envelope and of the revocation needed to compare them are not known" };
  }
  if (envelopeHeight >= revocationHeight) {
    return { platform: "failed", note: `platform: signed by a key revoked at block ${revocationHeight}, after which this envelope was anchored` };
  }
  return { platform: "verified", note: `platform: signed by a key revoked later (block ${revocationHeight}); the envelope was anchored before, so it counts` };
}

export async function verifyFull(bundleText, trust, { getHeader = null } = {}) {
  // time first: the earliest valid Bitcoin anchor of any proof of the attested or envelope hash
  // (SPEC 10); it also feeds the ORCID iat window and the revocation comparison.
  let time = null;
  let envelopeHeight = null; // earliest anchor of the envelope hash alone, for the revocation comparison
  const timeNotes = [];
  let bundleForTime = null;
  try { bundleForTime = parseJsonStrict(bundleText); } catch { bundleForTime = null; }
  // A malformed bundle must not make the time step throw (SPEC 11: a verifier never throws; review
  // F27, A17): it is skipped, and the structure part reports the bundle.
  const otsLists = bundleForTime?.ots;
  const timeable = getHeader && otsLists && typeof otsLists === "object" && bundleForTime.attested && bundleForTime.envelope &&
    ["attested", "envelope"].every(k => otsLists[k] === undefined || (Array.isArray(otsLists[k]) && otsLists[k].every(p => typeof p === "string")));
  if (timeable) {
    let hashes = null;
    try { hashes = { attested: await sha256Hex(bundleForTime.attested), envelope: await sha256Hex(bundleForTime.envelope) }; } catch { hashes = null; }
    if (hashes) {
      time = { status: "not_checked", height: null, time: null };
      let invalid = false;
      for (const kind of ["attested", "envelope"]) {
        for (const proof of bundleForTime.ots[kind] || []) {
          let r;
          try { r = await verifyOts(fromB64url(proof), fromHex(hashes[kind]), getHeader); } catch (e) { r = { status: "failed", notes: [e.message] }; }
          r.notes.forEach(n => timeNotes.push(`time: ${kind}: ${n}`));
          if (r.status === "failed") invalid = true;
          if (r.status === "verified" && (time.height === null || r.height < time.height)) Object.assign(time, { status: "verified", height: r.height, time: r.time });
          if (r.status === "verified" && kind === "envelope" && (envelopeHeight === null || r.height < envelopeHeight)) envelopeHeight = r.height;
        }
      }
      // The earliest valid anchor counts (SPEC 10); invalid attempts fail the part only when none is valid.
      if (time.status !== "verified" && invalid) time.status = "failed";
      if (time.status === "verified" && trust.earliest_anchor == null) trust.earliest_anchor = new Date(time.time * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
    }
  }

  // Live ORCID keys (fetch-orcid-keys --live) count only while fresh: a key ORCID has since removed must
  // not keep verifying from an old trust file. Entries without times count only as live ones.
  if (Array.isArray(trust.orcid_keys)) {
    const before = trust.orcid_keys.length;
    trust.orcid_keys = trust.orcid_keys.filter(k => {
      if (k?.first_capture != null || k?.last_capture != null) return true;
      const t = Date.parse(k?.fetched_at || "");
      return k?.source === "live" && t <= Date.now() + 300000 && Date.now() - t <= 86400000;
    });
    if (trust.orcid_keys.length < before) timeNotes.push(`identity: ${before - trust.orcid_keys.length} ORCID key(s) without capture times ignored (live keys older than a day or of unknown origin; run fetch-orcid-keys --live again)`);
  }
  const { parts, notes, recordHash } = await verifyBundle(bundleText, trust);
  notes.push(...timeNotes);
  if (time && parts.structure === "verified") {
    parts.time = time.status;
    if (time.status === "verified") notes.push(`time: earliest anchor in Bitcoin block ${time.height} (${new Date(time.time * 1000).toISOString()})`);
  }

  // Revoked keys (from fetch-trust): an envelope signed by a revoked key counts only if the envelope
  // hash was anchored before the revocation (protocol/verifier/TRUST.md). Only proofs of the envelope
  // hash count here: the attested hash needs no key, so anyone could have stamped it early.
  const signer = bundleForTime?.envelope?.platform_signature?.key_id;
  const revocation = Array.isArray(trust.revocations) ? trust.revocations.find(r => r?.key_id === signer) : null;
  if (revocation && parts.platform === "verified") {
    const verdict = judgeRevocation(envelopeHeight, revocation.anchor_height);
    parts.platform = verdict.platform;
    notes.push(verdict.note);
  }

  // A checkpoint signed by a revoked key (protocol/verifier/TRUST.md): the log part stands only for the
  // revoked key's named last good checkpoint (revoked_keys in the verifier's pinned defaults, from the
  // revocation ceremony); any other checkpoint signed by that key is not checked. The witness part is
  // reported separately and never restores trust in a revoked key.
  const checkpointNote = bundleForTime?.log?.checkpoint;
  const revokedIds = new Set([...(trust.revocations || []), ...(trust.revoked_keys || [])].map(r => r?.key_id));
  if (parts.log === "verified" && typeof checkpointNote === "string" && revokedIds.size) {
    const byId = new Map();
    for (const pk of trust.platform_keys || []) byId.set(await keyId(pk), pk);
    const signedBy = [];
    for (const [kid, pk] of byId) if (await verifyNote(checkpointNote, LOG_NAME, [pk])) signedBy.push(kid);
    if (signedBy.length && signedBy.every(k => revokedIds.has(k))) {
      const sha = await sha256hex(new TextEncoder().encode(checkpointNote));
      const good = (trust.revoked_keys || []).some(r => signedBy.includes(r?.key_id) && r?.last_good_checkpoint?.note_sha256 === sha);
      if (!good) {
        parts.log = "not_checked";
        notes.push("log: the checkpoint is signed by a revoked key and is not its named last good checkpoint");
      }
    }
  }

  // The inclusion promise is reported beside the parts and never fails a record: kept, or not judged.
  const promise = typeof bundleForTime?.log?.promise !== "string" ? null
    : parts.log === "verified" ? await judgePromise(bundleForTime, trust) : { status: "not_judged", notes: ["promise: not judged (log not verified)"] };
  if (promise) notes.push(...promise.notes);
  return { parts, notes, recordHash, promise };
}
