#!/usr/bin/env node
// Adds a witnessed checkpoint to verifier trust (protocol/SPEC.md section 9, phase-1b plan section 9):
// picks the mirror's checkpoint of the bundle's size (or the smallest larger one), checks that
// Rekor logged its digest (the stored entry's inclusion proof against a Rekor checkpoint signed by
// the shard key), and adds the consistency proof (empty for the same size; fetched from --site
// otherwise, where it is only data: the verifier checks it).
//
//   node verifier/fetch-witness.mjs --bundle b.json --trust trust.json [--dir <mirror>] [--site https://pubphys.com]
//        --sigstore-trusted-root trusted_root.json | --fetch-sigstore-root-unverified > trust-with-witness.json
//
// Rekor shard keys never come from the mirror (PubPhys writes it). They come from Sigstore's own
// trusted root, obtained through Sigstore's TUF repository (for example with cosign or
// sigstore-python) and passed as a file. --fetch-sigstore-root-unverified downloads the copy in
// Sigstore's root-signing repository on GitHub instead, without TUF verification, and the result
// then says so. Each shard's log id must derive from its key (C2SP key hash of host and key).
//
// When the bundle carries an inclusion promise, it also adds promise_evidence (plan section 7): among
// the mirror's checkpoints with size > the promised leaf index that Rekor logged and that are
// consistent with the bundle's checkpoint, the one whose Rekor checkpoint has the earliest
// cosignature verified against the pinned witness keys (trust.witness_keys from fetch-trust).
// pubphys-verify re-checks it and reports the promise kept or not judged.

import fs from "node:fs";
import path from "node:path";
import { parseJsonStrict, sha256, fromB64, b64, b64url, verifyInclusion, leafHashRaw, verifyNote, parseNote, parsePromise } from "./pubphys_protocol.js";
import { parseWitnessKey, cosignatures, rekorSubmitterPinned } from "./promise_evidence.js";

const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const dir = opt("--dir") || ".";
const site = opt("--site");
if (!opt("--bundle") || !opt("--trust")) { console.error("usage: fetch-witness --bundle <b.json> --trust <trust.json> [--dir <mirror>] [--site <url>]"); process.exit(2); }
const fail = msg => { console.error("fetch-witness: " + msg); process.exit(1); };
const read = p => parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(p)));
const enc = new TextEncoder();

const bundle = read(opt("--bundle"));
const trust = read(opt("--trust"));
const SPKI_ED25519 = "302a300506032b6570032100";
const rootPath = opt("--sigstore-trusted-root");
let trustedRoot;
if (!rootPath && !args.includes("--fetch-sigstore-root-unverified")) {
  console.error("fetch-witness: pass --sigstore-trusted-root <file> (Sigstore's trusted root obtained through TUF), or --fetch-sigstore-root-unverified");
  process.exit(2);
}
if (!Array.isArray(trust.rekor_submission_keys) || trust.rekor_submission_keys.length === 0) {
  fail("the trust file has no rekor_submission_keys; run fetch-trust from this verifier release again");
}
if (rootPath) trustedRoot = read(rootPath);
else if (args.includes("--fetch-sigstore-root-unverified")) {
  const url = "https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json";
  const res = await fetch(url);
  if (!res.ok) fail(`cannot fetch Sigstore's trusted root (${res.status})`);
  trustedRoot = await res.json();
  console.error(`fetch-witness: WARNING: Rekor shard keys downloaded from ${url} without TUF verification; the witness result is only as good as that download`);
} else {
  console.error("fetch-witness: pass --sigstore-trusted-root <file> (Sigstore's trusted root obtained through TUF), or --fetch-sigstore-root-unverified");
  process.exit(2);
}
// Rekor v2 shards: Ed25519 keys whose log id is the C2SP key hash of (host, key), already valid.
const shards = [];
for (const t of trustedRoot.tlogs || []) {
  const der = fromB64(t?.publicKey?.rawBytes || "");
  if (t?.publicKey?.keyDetails !== "PKIX_ED25519" || der.length !== 44 || Array.from(der.slice(0, 12), x => x.toString(16).padStart(2, "0")).join("") !== SPKI_ED25519) continue;
  const host = new URL(t.baseUrl).host;
  const raw = der.slice(12);
  const derived = await sha256(new Uint8Array([...enc.encode(host), 0x0a, 0x01, ...raw]));
  if (b64(derived) !== t?.logId?.keyId) continue;
  const start = Date.parse(t?.publicKey?.validFor?.start || "");
  if (!(start <= Date.now())) continue;
  shards.push({ url: t.baseUrl, log_id: t.logId.keyId, raw });
}
if (shards.length === 0) fail("no usable Rekor v2 shard keys in the trusted root");
const size = Number(bundle.log.tree_size);

const sizes = fs.readdirSync(path.join(dir, "checkpoints")).map(f => f.match(/^(\d+)\.note$/)).filter(Boolean).map(m => Number(m[1])).filter(n => n >= size).sort((a, b) => a - b);

async function rekorLogged(note, entry) {
  const shard = shards.find(s => s.log_id === entry?.logId?.keyId);
  if (!shard) return false;
  const body = fromB64(entry.canonicalizedBody);
  const parsed = JSON.parse(new TextDecoder().decode(body));
  if (!rekorSubmitterPinned(parsed, trust.rekor_submission_keys)) return false; // another key: not PubPhys's entry
  const data = parsed?.spec?.hashedRekordV002?.data;
  const digest = await sha256(enc.encode(note));
  if (data?.algorithm !== "SHA2_256" || b64url(fromB64(data.digest)) !== b64url(digest)) return false;
  const proof = entry.inclusionProof;
  const host = new URL(shard.url).host;
  const rekorNote = await verifyNote(proof.checkpoint.envelope, host, [b64url(shard.raw)]);
  if (!rekorNote) return false;
  const [, treeSize, root] = rekorNote.lines;
  if (treeSize !== proof.treeSize || root !== proof.rootHash) return false;
  return verifyInclusion(Number(proof.logIndex), Number(proof.treeSize), await leafHashRaw(body), proof.hashes.map(h => fromB64(h)), fromB64(proof.rootHash));
}

async function consistencyProof(from, to) {
  if (from === to) return [];
  if (!site) return null;
  try {
    const res = await fetch(`${site}/log/proof/consistency?from=${from}&to=${to}`);
    if (!res.ok) { console.error(`fetch-witness: consistency proof ${from}→${to}: HTTP ${res.status}`); return null; }
    return (await res.json()).proof;
  } catch (e) { console.error(`fetch-witness: consistency proof ${from}→${to}: ${e.message}`); return null; }
}

async function loggedEntry(s, note) {
  const entryDir = path.join(dir, "rekor", String(s));
  for (const f of fs.existsSync(entryDir) ? fs.readdirSync(entryDir) : []) {
    try {
      const e = read(path.join(entryDir, f));
      if (await rekorLogged(note, e)) return e;
    } catch { console.error(`fetch-witness: rekor/${s}/${f} is unreadable; skipped`); }
  }
  return null;
}

if (typeof bundle.log?.promise === "string") {
  const promise = parsePromise(parseNote(bundle.log.promise));
  const witnessKeys = (await Promise.all((trust.witness_keys || []).map(parseWitnessKey))).filter(Boolean);
  if (witnessKeys.length === 0) console.error("fetch-witness: no pinned witness keys in the trust file; the promise cannot be judged");
  const candidates = fs.readdirSync(path.join(dir, "checkpoints")).map(f => f.match(/^(\d+)\.note$/)).filter(Boolean)
    .map(m => Number(m[1])).filter(n => n > promise.leafIndex).sort((a, b) => a - b);
  const deadline = Date.parse(promise.deadline) / 1000;
  let best = null;
  for (const s of witnessKeys.length ? candidates : []) {
    const note = fs.readFileSync(path.join(dir, "checkpoints", `${s}.note`), "utf8");
    const entry = await loggedEntry(s, note);
    if (!entry) continue;
    const cos = await cosignatures(entry.inclusionProof.checkpoint.envelope, witnessKeys);
    if (cos.verified.length === 0) continue;
    const first = Math.min(...cos.verified.map(c => c.time));
    if (best && first >= best.published) continue;
    const proof = await consistencyProof(Math.min(size, s), Math.max(size, s));
    if (proof === null) { console.error(`fetch-witness: checkpoint ${s} skipped for the promise: no consistency proof (pass --site)`); continue; }
    if (!best || first < best.published) best = { published: first, evidence: { checkpoint: note, consistency: proof, rekor_entry: entry,
      published_at: new Date(first * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"), witnesses: [...new Set(cos.verified.map(c => c.name))] } };
    if (best.published <= deadline) break; // evidence enough for "kept"; tree size does not order publication times otherwise
  }
  if (best) {
    trust.promise_evidence = best.evidence;
    trust.rekor_shards = shards.map(s => ({ url: s.url, log_id: s.log_id, public_key: b64(s.raw) }));
  }
  else console.error("fetch-witness: no witnessed checkpoint covers the promised leaf; the promise is not judged");
}

for (const s of sizes) {
  const note = fs.readFileSync(path.join(dir, "checkpoints", `${s}.note`), "utf8");
  const entryDir = path.join(dir, "rekor", String(s));
  const entries = fs.existsSync(entryDir) ? fs.readdirSync(entryDir).map(f => read(path.join(entryDir, f))) : [];
  let logged = false;
  for (const e of entries) if (await rekorLogged(note, e)) { logged = true; break; }
  if (!logged) { console.error(`fetch-witness: checkpoint ${s} has no Rekor entry that verifies; skipped`); continue; }
  let proof = [];
  if (s !== size) {
    if (!site) fail(`the nearest witnessed checkpoint is ${s}, larger than the bundle's ${size}; pass --site to fetch a consistency proof`);
    const res = await fetch(`${site}/log/proof/consistency?from=${size}&to=${s}`);
    if (!res.ok) fail(`consistency proof request failed: HTTP ${res.status}`);
    proof = (await res.json()).proof;
  }
  parseNote(note);
  trust.witness = { checkpoint: note, proof };
  process.stdout.write(JSON.stringify(trust, null, 2) + "\n");
  process.exit(0);
}
fail("no checkpoint of the bundle's size or larger is witnessed in the mirror");
