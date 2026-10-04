// judgePromise against a synthetic log, Rekor entry and witness (real keys and signatures, generated
// here). The cosignature format itself is also checked against a real witness line in the fixtures.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { noteKeyHash, leafHashRaw, leafHash, canonical, hex, sha256, b64, b64url, keyId, LOG_NAME } from "../verifier/pubphys_protocol.js";
import { judgePromise, parseWitnessKey, cosignatures } from "../verifier/promise_evidence.js";

const enc = new TextEncoder();
const keypair = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { raw: new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(12)), privateKey };
};
const sign = (k, msg) => new Uint8Array(crypto.sign(null, Buffer.from(msg), k.privateKey));
const iso = t => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

async function setup({ cosignTime, deadlineOffset = 3600, tamper = false } = {}) {
  const platform = keypair(), witness = keypair(), shard = keypair();
  const issued = 1790990000;
  const envelope0 = { schema: "pubphys.envelope/1", attested_hash: "cd".repeat(32), platform_signature: { key_id: "ef".repeat(32), sig: "x" } };
  const leaf = hex(await leafHash(hex(await sha256(enc.encode(canonical(envelope0)))), "topic"));
  const signNote = async (body, name, k) => `${body}\n— ${name} ${b64(new Uint8Array([...(await noteKeyHash(name, k.raw)), ...sign(k, enc.encode(body))]))}\n`;
  const root = b64(crypto.randomBytes(32));
  const checkpoint = await signNote(`${LOG_NAME}\n1\n${root}\n`, LOG_NAME, platform);
  const promise = await signNote(`${LOG_NAME} promise\n${leaf}\n0\n${iso(issued)}\n${iso(issued + deadlineOffset)}\n`, LOG_NAME, platform);
  const body = enc.encode(JSON.stringify({ spec: { hashedRekordV002: { data: { algorithm: "SHA2_256", digest: b64(await sha256(enc.encode(checkpoint))) } } } }));
  const rekorRoot = b64(await leafHashRaw(body));
  const rekorBody = `rekor.test\n1\n${rekorRoot}\n`;
  const wname = "witness.test";
  const wkh = (await sha256(new Uint8Array([...enc.encode(wname), 0x0a, 0x04, ...witness.raw]))).slice(0, 4);
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(cosignTime));
  const sig = sign(witness, enc.encode(`cosignature/v1\ntime ${cosignTime}\n${rekorBody}`));
  if (tamper) new DataView(ts.buffer).setBigUint64(0, BigInt(cosignTime - 1000));
  const shardSig = new Uint8Array([...(await noteKeyHash("rekor.test", shard.raw)), ...sign(shard, enc.encode(rekorBody))]);
  const envelope = `${rekorBody}\n— rekor.test ${b64(shardSig)}\n— ${wname} ${b64(new Uint8Array([...wkh, ...ts, ...sig]))}\n`;
  const logId = b64(await sha256(new Uint8Array([...enc.encode("rekor.test"), 0x0a, 0x01, ...shard.raw])));
  const entry = { logId: { keyId: logId }, canonicalizedBody: b64(body), inclusionProof: { logIndex: "0", treeSize: "1", rootHash: rekorRoot, hashes: [], checkpoint: { envelope } } };
  const vkey = `${wname}+${Buffer.from(wkh).toString("hex")}+${b64(new Uint8Array([0x04, ...witness.raw]))}`;
  const bundle = { record: { type: "topic" }, envelope: envelope0, log: { leaf_index: "0", tree_size: "1", checkpoint, promise } };
  const trust = { platform_keys: [b64url(platform.raw)], witness_keys: [vkey], promise_evidence: { checkpoint, consistency: [], rekor_entry: entry },
                  rekor_shards: [{ url: "https://rekor.test", log_id: logId, public_key: b64(shard.raw) }] };
  return { bundle, trust, issued, platformId: await keyId(b64url(platform.raw)) };
}

test("a cosignature before the deadline keeps the promise", async () => {
  const { bundle, trust } = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise(bundle, trust)).status, "kept");
});

test("a cosignature after the deadline does not judge (never missed offline)", async () => {
  const { bundle, trust } = await setup({ cosignTime: 1790990000 + 7200 });
  assert.equal((await judgePromise(bundle, trust)).status, "not_judged");
});

test("an altered cosignature time is unverified and does not judge", async () => {
  const { bundle, trust } = await setup({ cosignTime: 1790990000 + 7200, tamper: true });
  const r = await judgePromise(bundle, trust);
  assert.equal(r.status, "not_judged");
  assert.match(r.notes.join("\n"), /witness\.test unverified/);
});

test("without pinned witness keys, a foreign platform key or a Rekor entry for another note, nothing is judged", async () => {
  const { bundle, trust } = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise(bundle, { ...trust, witness_keys: [] })).status, "not_judged");
  assert.equal((await judgePromise(bundle, { ...trust, platform_keys: [b64url(keypair().raw)] })).status, "not_judged");
  const other = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise(bundle, { ...trust, promise_evidence: { ...trust.promise_evidence, rekor_entry: other.trust.promise_evidence.rekor_entry } })).status, "not_judged");
  assert.equal(await judgePromise({ log: { ...bundle.log, promise: null } }, trust), null);
});

test("a real witness line verifies; lines of unpinned witnesses do not", async () => {
  const e = JSON.parse(fs.readFileSync(new URL("./fixtures/rekor-entry-cosigned.json", import.meta.url)));
  const k = await parseWitnessKey("witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv");
  const r = await cosignatures(e.inclusionProof.checkpoint.envelope, [k]);
  assert.deepEqual(r.verified, [{ name: "witness.stagemole.eu", time: 1790993553 }]);
  assert.equal(r.unverified.length, 2);
  assert.equal(await parseWitnessKey("witness.stagemole.eu+00000000+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv"), null);
});

test("a promise signed by a revoked key, a Rekor log outside the trust file or a forked checkpoint is not judged", async () => {
  const { bundle, trust, platformId } = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise(bundle, { ...trust, revocations: [{ key_id: platformId, anchor_height: null }] })).status, "not_judged");
  assert.equal((await judgePromise(bundle, { ...trust, revoked_keys: [{ key_id: platformId }] })).status, "not_judged");
  assert.equal((await judgePromise(bundle, { ...trust, rekor_shards: [] })).status, "not_judged");
  const other = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise(bundle, { ...trust, rekor_shards: other.trust.rekor_shards })).status, "not_judged");
  const fork = await setup({ cosignTime: 1790990000 + 600 });
  const r = await judgePromise(bundle, { ...trust, platform_keys: [...trust.platform_keys, ...fork.trust.platform_keys], promise_evidence: fork.trust.promise_evidence });
  assert.equal(r.status, "not_judged");
});

test("a promise for another leaf, or a Rekor checkpoint whose origin is not its shard, is not judged", async () => {
  const { bundle, trust } = await setup({ cosignTime: 1790990000 + 600 });
  assert.equal((await judgePromise({ ...bundle, record: { type: "problem" } }, trust)).status, "not_judged");
  assert.equal((await judgePromise({ ...bundle, log: { ...bundle.log, leaf_index: "1" } }, trust)).status, "not_judged");
  const foreign = { ...trust, rekor_shards: [{ ...trust.rekor_shards[0], url: "https://other.test" }] };
  assert.equal((await judgePromise(bundle, foreign)).status, "not_judged");
});
