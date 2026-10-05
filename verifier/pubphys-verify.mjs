#!/usr/bin/env node
// PubPhys bundle verifier (SPEC section 11). No dependencies beyond the protocol module.
//
//   node protocol/verifier/pubphys-verify.mjs bundle.json --trust trust.json [--live-orcid] [--require parts]
//
// trust.json: { "platform_keys": [...], "recovery_keys": [...], "orcid_keys": [...], "orcid_client_ids": [...],
//               "earliest_anchor": <time or null>, "witness": <{checkpoint, proof} or null> }
// --live-orcid  fetches ORCID's live JWKS (https://orcid.org/oauth/jwks) and adds it to the trusted
//               ORCID keys. Keys inside the bundle are never trusted.
// --require     comma-separated parts that must be "verified" for exit code 0
//               (default: structure,content,platform,log, plus identity for a record signed with ORCID).
//               Example: --require structure,content,identity
// Exit codes: 0 every required part verified; 1 a part failed or a required part is not verified;
// 2 usage error or unreadable input.
// --bitcoin [url] checks the OpenTimestamps proofs against Bitcoin block headers from an
//               Esplora-compatible explorer (default https://blockstream.info/api; that means trusting
//               the explorer for the headers, a Bitcoin node behind an Esplora API removes it). Without
//               it, time is reported as not_checked.

import fs from "node:fs";
import { parseJsonStrict } from "./pubphys_protocol.js";
import { esploraHeaders } from "./ots.js";
import { verifyFull } from "./verify_full.js";

const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
const bitcoinArg = args.includes("--bitcoin") ? (args[args.indexOf("--bitcoin") + 1] || "") : null;
const bitcoinUrl = bitcoinArg === null ? null : (/^https?:\/\//.test(bitcoinArg) ? bitcoinArg : "https://blockstream.info/api");
const valueArgs = new Set([opt("--trust"), opt("--require"), /^https?:\/\//.test(bitcoinArg || "") ? bitcoinArg : undefined]);
const positionals = args.filter(a => !a.startsWith("--") && !valueArgs.has(a));
if (positionals.length > 1) { console.error("pubphys-verify: exactly one bundle path expected"); process.exit(2); }
const bundlePath = positionals[0];
const trustPath = opt("--trust");
if (!bundlePath || !trustPath) {
  console.error("usage: pubphys-verify <bundle.json> --trust <trust.json> [--live-orcid] [--require parts]");
  process.exit(2);
}
const required = (opt("--require") || "structure,content,platform,log").split(",").filter(Boolean);
const requireGiven = Boolean(opt("--require"));

const decode = bytes => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes);
const usage = msg => { console.error("pubphys-verify: " + msg); process.exit(2); };
let trust, bundleText;
try { trust = parseJsonStrict(decode(fs.readFileSync(trustPath))); } catch (e) { usage(`cannot read trust file: ${e.message}`); }
if (!trust || typeof trust !== "object" || Array.isArray(trust)) usage("trust file must be a JSON object");
try { bundleText = decode(fs.readFileSync(bundlePath)); } catch (e) { usage(`cannot read bundle (it must be UTF-8 JSON): ${e.message}`); }
if (args.includes("--live-orcid")) {
  try {
    const jwks = parseJsonStrict(decode(new Uint8Array(await (await fetch("https://orcid.org/oauth/jwks")).arrayBuffer())));
    const fetchedAt = new Date().toISOString();
    trust.orcid_keys = [...(trust.orcid_keys || []), ...jwks.keys.map(jwk => ({ jwk, first_capture: null, last_capture: null, source: "live", fetched_at: fetchedAt }))];
  } catch (e) {
    usage(`cannot fetch ORCID keys: ${e.message}`);
  }
}

const { parts, notes, recordHash, promise } = await verifyFull(bundleText, trust, { getHeader: bitcoinUrl ? esploraHeaders(bitcoinUrl) : null });
// A record signed with ORCID is about a person: by default its identity is required too (review F27, A19).
try {
  if (!requireGiven && JSON.parse(bundleText)?.attested?.attestation?.kind === "orcid-oidc" && !required.includes("identity")) required.push("identity");
} catch { /* structure reports it */ }

console.log(`record ${recordHash || "(not computed)"}`);
for (const [part, result] of Object.entries(parts)) console.log(`  ${part.padEnd(10)} ${result}${required.includes(part) ? "  (required)" : ""}`);
if (promise) console.log(`  ${"promise".padEnd(10)} ${promise.status}`);
for (const n of notes) console.log(`  note: ${n}`);
const ok = !Object.values(parts).includes("failed") && required.every(p => parts[p] === "verified");
const unchecked = Object.entries(parts).filter(([p, r]) => !required.includes(p) && r === "not_checked").map(([p]) => p);
console.log(ok ? `result: all required parts verified${unchecked.length ? ` (not checked: ${unchecked.join(", ")})` : ""}` : "result: NOT verified");
process.exit(ok ? 0 : 1);
