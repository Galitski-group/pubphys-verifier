// Runs every vector in protocol/vectors against the JavaScript implementation, checks it against
// independent oracles, and builds bundles with the JavaScript implementation alone (including an
// ORCID-attested one) for the Ruby suite to verify.
//
//   node --test protocol/test

import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import * as P from "../verifier/pubphys_protocol.js";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "..");
const vec = name => JSON.parse(fs.readFileSync(path.join(root, "vectors", name), "utf8"));
const S = P.SCHEMA_SET;
const throwsProtocol = (fn, msg) => assert.throws(fn, e => e instanceof P.ProtocolError, msg);

test("strict encodings and times", () => {
  const v = vec("encodings.json");
  for (const c of v.hex.valid) assert.equal(P.hex(P.fromHex(c.input)), c.bytes);
  for (const c of v.hex.invalid) throwsProtocol(() => P.fromHex(c), "hex " + c);
  for (const c of v.base64url.valid) assert.equal(P.hex(P.fromB64url(c.input)), c.bytes, c.input);
  for (const c of v.base64url.invalid) throwsProtocol(() => P.fromB64url(c), "base64url " + c);
  for (const c of v.base64.valid) assert.equal(P.hex(P.fromB64(c.input)), c.bytes, c.input);
  for (const c of v.base64.invalid) throwsProtocol(() => P.fromB64(c), "base64 " + c);
  for (const t of v.time.valid) assert.notEqual(P.parseTime(t), null, t);
  for (const t of v.time.invalid) assert.equal(P.parseTime(t), null, t);
});

test("canonical form", async () => {
  for (const c of vec("canonical.json").cases) {
    const value = c.json ? JSON.parse(c.json) : c.value;
    if (c.error) assert.throws(() => P.canonical(value), P.CanonicalError, c.name);
    else {
      assert.equal(P.canonical(value), c.canonical, c.name);
      assert.equal(await P.hashObject(value), c.sha256, c.name);
    }
  }
});

test("canonical strings equal ECMAScript JSON.stringify (the RFC 8785 string rule)", () => {
  let seed = 7;
  const rand = n => ((seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) >>> 8) % n;
  const pool = [0x00, 0x08, 0x0a, 0x0d, 0x1f, 0x22, 0x2f, 0x5c, 0x7f, 0xe9, 0x2028, 0x2029, 0xfeff, 0x1f600, 0x0301];
  for (let i = 0; i < 5000; i++) {
    let s = "";
    for (let j = rand(12); j > 0; j--) s += String.fromCodePoint(rand(3) ? pool[rand(pool.length)] : 0x20 + rand(0x5f));
    assert.equal(P.canonical(s), JSON.stringify(s));
  }
});

test("strict JSON", () => {
  const v = vec("json.json");
  for (const t of v.valid) assert.deepEqual(P.parseJsonStrict(t), JSON.parse(t));
  for (const t of v.invalid) throwsProtocol(() => P.parseJsonStrict(t), t);
  for (const b of v.invalid_bytes_b64) {
    assert.throws(() => P.parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(P.fromB64(b))), "invalid UTF-8 " + b);
  }
});

function recordProblems(record, content) {
  let ps = P.validateSchema(record, S.record);
  const cs = S["content." + record.type];
  if (cs) ps = ps.concat(P.validateSchema(content, cs));
  ps = ps.concat(P.arrayOrderProblems(record), P.arrayOrderProblems(content));
  if (record.content_schema !== `pubphys.content.${record.type}/1`) ps.push("content_schema mismatch");
  if (ps.length === 0) ps = P.recordRuleProblems(record, content);
  return ps;
}

test("records", async () => {
  const v = vec("records.json");
  for (const c of v.valid) {
    assert.deepEqual(recordProblems(c.record, c.content), [], c.name);
    assert.equal(await P.hashObject(c.content), c.record.content_sha256, c.name);
    assert.equal(await P.hashObject(c.record), c.record_hash, c.name);
  }
  for (const c of v.invalid) assert.ok(recordProblems(c.record, c.content).length > 0, c.name);
});

test("batch nonce and the real ORCID token", async t => {
  const v = vec("attestation.json");
  for (const c of v.nonce_cases) assert.equal(await P.batchNonce(c.batch), c.nonce, c.name);
  // The real token is a personal one and is not published with the standalone verifier.
  if (!fs.existsSync(path.join(root, "vectors", v.production_case.fixture))) { t.diagnostic("real ORCID token fixture not present; skipped"); return; }
  const fx = JSON.parse(fs.readFileSync(path.join(root, "vectors", v.production_case.fixture), "utf8"));
  const { payload } = P.decodeJwt(fx.id_token);
  assert.equal(await P.verifyRs256(fx.id_token, fx.orcid_jwk), true);
  assert.equal(payload.nonce, await P.batchNonce(fx.batch));
  assert.equal(payload.aud, v.production_case.expected.aud);
  assert.equal(payload.iss, v.production_case.expected.iss);
});

test("envelope", async () => {
  const v = vec("envelope.json");
  assert.equal(await P.keyId(v.public_key), v.key_id);
  for (const c of v.cases) {
    assert.equal(await P.hashObject(c.envelope), c.envelope_hash);
    assert.equal(await P.verifyEnvelopeSignature(c.envelope, [v.public_key]), true);
  }
});

test("transparency log", async () => {
  const v = vec("log.json");
  const leaves = [];
  for (const [i, l] of v.leaf_inputs.entries()) {
    const h = await P.leafHash(l.envelope_hash, l.record_type);
    assert.equal(P.hex(h), v.leaf_hashes[i]);
    leaves.push(h);
  }
  const rootOf = n => P.fromHex(v.roots[n]);
  for (let n = 0; n <= leaves.length; n++) assert.equal(P.hex(await P.merkleRoot(leaves.slice(0, n))), v.roots[n]);
  for (const c of v.inclusion) assert.equal(await P.verifyInclusion(c.index, c.tree_size, leaves[c.index], c.proof.map(P.fromHex), rootOf(c.tree_size)), true);
  for (const c of v.consistency) assert.equal(await P.verifyConsistency(c.size1, c.size2, c.proof.map(P.fromHex), rootOf(c.size1), rootOf(c.size2)), true);
  for (const c of v.invalid_inclusion) assert.equal(await P.verifyInclusion(c.index, c.tree_size, leaves[Math.min(c.index, 16)], c.proof.map(P.fromHex), rootOf(c.tree_size)), false);
  for (const c of v.invalid_consistency) assert.equal(await P.verifyConsistency(c.size1, c.size2, c.proof.map(P.fromHex), rootOf(Math.min(c.size1, 17)), rootOf(c.size2)), false);
  assert.equal(await P.verifyInclusion(2 ** 53, 2 ** 53 + 1, leaves[0], [], rootOf(1)), false, "sizes above 2^53 - 1 are rejected");
});

test("signed notes", async () => {
  const v = vec("notes.json");
  assert.equal(P.hex(await P.noteKeyHash(P.LOG_NAME, P.fromB64url(v.public_key))), v.key_hash);
  for (const c of v.valid) {
    const note = await P.verifyNote(c.note, P.LOG_NAME, [v.public_key]);
    assert.ok(note, c.name);
    if (c.tree_size) {
      const cp = P.parseCheckpoint(note);
      assert.equal(String(cp.treeSize), c.tree_size);
      assert.equal(P.hex(cp.root), c.root);
    }
  }
  for (const c of v.invalid) {
    let note = null;
    try { note = await P.verifyNote(c.note, P.LOG_NAME, [v.public_key]); } catch (e) { assert.ok(e instanceof P.ProtocolError, c.name); }
    assert.equal(note, null, c.name);
  }
  for (const c of v.valid.filter(x => x.promise)) P.parsePromise(await P.verifyNote(c.note, P.LOG_NAME, [v.public_key]));
  for (const c of v.bad_promises) {
    const note = await P.verifyNote(c.note, P.LOG_NAME, [v.public_key]);
    assert.ok(note, c.name);
    throwsProtocol(() => P.parsePromise(note), c.name);
  }
  for (const c of v.bad_checkpoints) {
    const note = await P.verifyNote(c.note, P.LOG_NAME, [v.public_key]);
    assert.ok(note, c.name);
    throwsProtocol(() => P.parseCheckpoint(note), c.name);
  }
});

test("independent oracles", async () => {
  const o = vec("oracles.json");
  for (const c of o.ed25519) {
    assert.equal(await P.ed25519Verify(P.fromHex(c.public), P.fromHex(c.signature), P.fromHex(c.message)), true, c.name);
    const pkcs8 = new Uint8Array([...P.fromHex("302e020100300506032b657004220420"), ...P.fromHex(c.secret)]);
    const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    assert.equal(P.hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key, P.fromHex(c.message)))), c.signature, c.name);
  }
  const leaves = await Promise.all(o.merkle_rfc6962.leaf_inputs.map(x => P.leafHashRaw(P.fromHex(x))));
  for (let n = 0; n <= leaves.length; n++) assert.equal(P.hex(await P.merkleRoot(leaves.slice(0, n))), o.merkle_rfc6962.roots[n], "root " + n);
  const raw = P.fromB64(o.note.verifier_key);
  assert.equal(raw[0], 1, "Ed25519 algorithm byte");
  const pub = P.b64url(raw.slice(1));
  assert.equal(P.hex(await P.noteKeyHash(o.note.name, raw.slice(1))), o.note.key_hash);
  assert.ok(await P.verifyNote(o.note.text, o.note.name, [pub]), "Go note example verifies");
});

test("bundles", async () => {
  const v = vec("bundles.json");
  for (const c of v.cases) {
    const trust = { ...v.trust, ...(c.trust_overrides || {}) };
    const r = await P.verifyBundle(c.text ?? c.bundle, trust);
    assert.deepEqual(r.parts, c.expected, `${c.name}: ${r.notes.join(" | ")}`);
  }
});

test("object input with ill-formed strings never throws", async () => {
  const v = vec("bundles.json");
  const base = v.cases.find(c => c.name === "seed revision").bundle;
  for (const mutate of [b => { b.record.origin.assisted_by = ["\ud800"]; }, b => { b.content.title = "x\udfff"; }, b => { b.files = [{ id: "a", data: "\ud800" }]; }]) {
    const b = JSON.parse(JSON.stringify(base));
    mutate(b);
    const r = await P.verifyBundle(b, v.trust);
    assert.equal(r.parts.structure, "failed");
  }
  assert.equal((await P.verifyBundle(base, null)).parts.platform, "failed", "null trust is treated as empty");
});

// ---------- bundles built by JavaScript alone, for the Ruby suite ----------

async function ed25519FromSeed(seedBytes) {
  const pkcs8 = new Uint8Array([...P.fromHex("302e020100300506032b657004220420"), ...seedBytes]);
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  return { key, publicKey: (await crypto.subtle.exportKey("jwk", key)).x };
}

test("build bundles with JavaScript only", async () => {
  const { key, publicKey } = await ed25519FromSeed(await P.sha256("pubphys js test platform key"));
  const sign = async msg => new Uint8Array(await crypto.subtle.sign("Ed25519", key, typeof msg === "string" ? new TextEncoder().encode(msg) : msg));
  const rsa = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const pubJwk = await crypto.subtle.exportKey("jwk", rsa.publicKey);
  const jwk = { kty: "RSA", kid: "js-test-key", n: pubJwk.n, e: pubJwk.e };
  const orcid = "0000-0002-1825-0097", client = "APP-JSTEST0000000000";
  const enc = s => P.b64url(new TextEncoder().encode(JSON.stringify(s)));

  const fileBytes = new TextEncoder().encode("Built by the JavaScript implementation.\n");
  const upContent = { purpose: "claim", ai_consent: "true", file_id: "note" };
  const record = (type, content, extra) => ({
    schema: "pubphys.record/2", site: P.SITE, type, content_schema: `pubphys.content.${type}/1`, content_sha256: null,
    files: [], parents: [], target: null, builds_on: [], author: { orcid, account_ref: null }, origin: { kind: "human", assisted_by: [] },
    salt: null, created: "2026-10-02T12:00:00Z", ...extra,
  });
  const upload = record("upload", upContent, { files: [{ id: "note", name: "note.txt", media_type: "text/plain", size: String(fileBytes.length), sha256: await P.sha256hex(fileBytes) }], salt: await P.sha256hex("js salt 1") });
  upload.content_sha256 = await P.hashObject(upContent);
  const claimContent = { problem_ref: await P.sha256hex("problem"), kind: "progress", body: P.normalizeText("A result built in JavaScript.\r\n"), references: "", assisted_by: [] };
  const claim = record("claim", claimContent, { target: await P.sha256hex("revision"), parents: [await P.hashObject(upload)], salt: await P.sha256hex("js salt 2") });
  claim.content_sha256 = await P.hashObject(claimContent);

  const claimHash = await P.hashObject(claim);
  const batch = [claimHash];
  const header = { kid: jwk.kid, alg: "RS256" };
  const payload = { iss: P.ORCID_ISSUER, sub: orcid, aud: client, iat: 1790931600, exp: 1791018000, nonce: await P.batchNonce(batch), jti: "js" };
  const input = enc(header) + "." + enc(payload);
  const token = input + "." + P.b64url(new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", rsa.privateKey, new TextEncoder().encode(input))));

  const attestedOf = async (rec, kind) => ({ schema: "pubphys.attested/1", record_hash: await P.hashObject(rec), attestation: kind === "orcid-oidc"
    ? { kind, batch, id_token_sha256: await P.sha256hex(token), client_id: client } : { kind, batch: null, id_token_sha256: null, client_id: null } });
  const envelopeOf = async attested => {
    const ah = await P.hashObject(attested);
    return { schema: "pubphys.envelope/1", attested_hash: ah, platform_signature: { key_id: await P.keyId(publicKey), sig: P.b64url(await sign("pubphys.platform/1\n" + ah)) } };
  };
  const upAtt = await attestedOf(upload, "none"), claimAtt = await attestedOf(claim, "orcid-oidc");
  const upEnv = await envelopeOf(upAtt), claimEnv = await envelopeOf(claimAtt);
  const leaves = [await P.leafHash(await P.hashObject(upEnv), "upload"), await P.leafHash(await P.hashObject(claimEnv), "claim")];
  const text = `${P.LOG_NAME}\n2\n${P.b64(await P.merkleRoot(leaves))}\n`;
  const checkpoint = `${text}\n— ${P.LOG_NAME} ${P.b64(new Uint8Array([...(await P.noteKeyHash(P.LOG_NAME, P.fromB64url(publicKey))), ...(await sign(text))]))}\n`;
  const log = i => ({ leaf_index: String(i), tree_size: "2", proof: [P.hex(leaves[1 - i])], checkpoint, promise: null });

  const claimBundle = { schema: "pubphys.bundle/1", record: claim, content: claimContent, content_withheld: "false", files: [], attested: claimAtt,
    id_token: token, id_token_withheld: "false", envelope: claimEnv, ots: { attested: [], envelope: [] }, log: log(1), orcid_key_evidence: [], attesting: null };
  const uploadBundle = { schema: "pubphys.bundle/1", record: upload, content: upContent, content_withheld: "false", files: [{ id: "note", data: P.b64url(fileBytes) }],
    attested: upAtt, id_token: null, id_token_withheld: "false", envelope: upEnv, ots: { attested: [], envelope: [] }, log: log(0), orcid_key_evidence: [], attesting: claimBundle };

  const trust = { platform_keys: [publicKey], recovery_keys: [], orcid_keys: [{ jwk, first_capture: null, last_capture: null }], orcid_client_ids: [client], earliest_anchor: null, witness: null };
  const human = { structure: "verified", content: "verified", identity: "verified", platform: "verified", log: "verified", witness: "not_checked", time: "not_checked" };
  for (const b of [claimBundle, uploadBundle]) assert.deepEqual((await P.verifyBundle(b, trust)).parts, human);

  fs.mkdirSync(path.join(root, "vectors", "generated"), { recursive: true });
  fs.writeFileSync(path.join(root, "vectors", "generated", "js-bundles.json"), JSON.stringify({ trust, expected: human, bundles: [claimBundle, uploadBundle] }, null, 2) + "\n");
});
