#!/usr/bin/env node
// Builds verifier trust from a pinned recovery key and the key records of the public mirror
// (wiki/platform/phase-1b-plan.md section 4). The mirror's trust.json is only a source of candidate
// public keys: a key is trusted only when its record bundle verifies against keys already trusted,
// starting from the recovery key whose fingerprint you pinned (DNS, documentation).
//
//   node verifier/fetch-trust.mjs [--recovery-key-id <hex>] [--dir <mirror checkout>] [--bitcoin [url]] > trust.json
//   (without --recovery-key-id, the fingerprint pinned in verifier/defaults.json)
//
// The trust rule of protocol/verifier/TRUST.md decides which keys are trusted. A revoked key stays in
// the chain for envelopes anchored before its revocation (SPEC section 8); the revocations are written
// with their anchor block when --bitcoin can establish it, and pubphys-verify compares the blocks.
// The ORCID client id comes from --orcid-client-id or the verifier's pinned defaults
// (verifier/defaults.json), never from the mirror's trust.json.
//
// Exit codes: 0 trust written; 1 the chain could not be built; 2 usage error.

import fs from "node:fs";
import path from "node:path";
import { parseJsonStrict, keyId, canonical, fromB64url, fromHex, hex } from "./pubphys_protocol.js";
import { verifyOts, esploraHeaders } from "./ots.js";
import { buildTrust, TrustError } from "./trust_builder.js";

const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const defaultsEarly = (() => { try { return parseJsonStrict(fs.readFileSync(new URL("./defaults.json", import.meta.url), "utf8")); } catch { return {}; } })();
// The recovery key fingerprint: yours (--recovery-key-id), or the one pinned in this verifier release.
const pinned = (opt("--recovery-key-id") || (defaultsEarly.recovery_key_ids || [])[0] || "").toLowerCase();
const dir = opt("--dir") || ".";
if (!/^[0-9a-f]{64}$/.test(pinned)) { console.error("usage: fetch-trust --recovery-key-id <64 hex> [--dir <mirror checkout>]"); process.exit(2); }
const fail = msg => { console.error("fetch-trust: " + msg); process.exit(1); };
const read = p => parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(p)));

const published = read(path.join(dir, "trust.json"));
const recovery = [];
for (const k of published.recovery_keys || []) if (typeof k.public_key === "string" && (await keyId(k.public_key)) === pinned) recovery.push(k.public_key);
if (recovery.length === 0) fail("no recovery key in trust.json matches the pinned fingerprint");

const keysDir = path.join(dir, "keys");
const bundles = fs.existsSync(keysDir) ? fs.readdirSync(keysDir).filter(f => f.endsWith(".json")).sort().map(f => fs.readFileSync(path.join(keysDir, f), "utf8")) : [];

const bitcoinArg = args.includes("--bitcoin") ? (args[args.indexOf("--bitcoin") + 1] || "") : null;
const getHeader = bitcoinArg === null ? null : esploraHeaders(/^https?:\/\//.test(bitcoinArg) ? bitcoinArg : undefined);
const digestHex = async obj => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical(obj)))));

// Earliest valid Bitcoin anchor of a bundle (block height), or null without headers or anchors.
const anchors = new Map();
async function anchorOf(text, b) {
  if (anchors.has(text)) return anchors.get(text);
  let height = null;
  if (getHeader) {
    for (const kind of ["attested", "envelope"]) {
      const expected = fromHex(await digestHex(b[kind]));
      for (const proof of b.ots?.[kind] || []) {
        const r = await verifyOts(fromB64url(proof), expected, getHeader);
        if (r.status === "verified" && (height === null || r.height < height)) height = r.height;
      }
    }
  }
  anchors.set(text, height);
  return height;
}

const defaults = (() => { try { return read(new URL("./defaults.json", import.meta.url)); } catch { return {}; } })();
const pinnedRevoked = (defaults.revoked_keys || []).map(r => r?.key_id).filter(k => /^[0-9a-f]{64}$/.test(k || ""));
let built;
try {
  built = await buildTrust({ recovery, bundleTexts: bundles, pinnedRevoked, anchorOf: getHeader ? anchorOf : async () => null,
    warn: m => console.error("fetch-trust: " + m) });
} catch (e) {
  if (e instanceof TrustError) fail(e.message);
  throw e;
}
const { platform_keys: signing, revocations } = built;
const clientIds = opt("--orcid-client-id") ? [opt("--orcid-client-id")] : (defaults.orcid_client_ids || []);
process.stdout.write(JSON.stringify({ platform_keys: signing, recovery_keys: recovery, orcid_keys: [],
  orcid_client_ids: clientIds, earliest_anchor: null, witness: null, revocations,
  revoked_keys: defaults.revoked_keys || [],
  witness_keys: args.includes("--witness-key") ? args.flatMap((x, i) => (x === "--witness-key" ? [args[i + 1]] : [])) : (defaults.witness_keys || []) }, null, 2) + "\n");
