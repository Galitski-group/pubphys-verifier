#!/usr/bin/env node
// Adds ORCID keys to verifier trust (protocol/SPEC.md section 7.3; wiki/platform/phase-2-plan.md
// sections 6 and 10). Bundles never supply trusted keys: this tool takes the jwks records of the
// mirror only as pointers to archive captures, and trusts a key only from what the archives
// themselves say.
//
//   node verifier/fetch-orcid-keys.mjs --trust trust.json [--dir <mirror>] [--live]
//        > trust-with-orcid-keys.json
//
// - A jwks bundle is used only if its platform and log parts verify against the trust file (from
//   fetch-trust) and content.url is exactly https://orcid.org/oauth/jwks.
// - A Wayback capture counts only if the archive's CDX index lists exactly that URL at the capture's
//   timestamp with HTTP 200 and the raw (id_) capture is a JWKS containing the key. Its time is the
//   archive's timestamp.
// - A key is emitted with first_capture and last_capture from its verified Wayback captures (SPEC 7.3:
//   valid for tokens issued from 24 hours before the first to 24 hours after the last capture).
//   Captures in other archives (archive.today, added by hand before 2026-10-04) and of other URLs are
//   reported and ignored.
// - --live adds the keys ORCID serves now, fetched here over HTTPS, marked with the fetch time. They
//   replace earlier live entries; pubphys-verify ignores live entries older than a day, so fetch
//   again for each verification.
//
// Exit codes: 0 trust written; 1 an error; 2 usage error.

import fs from "node:fs";
import path from "node:path";
import { verifyBundle, parseJsonStrict } from "./pubphys_protocol.js";

const args = process.argv.slice(2);
const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
if (!opt("--trust")) { console.error("usage: fetch-orcid-keys --trust <trust.json> [--dir <mirror>] [--live]"); process.exit(2); }
const dir = opt("--dir") || ".";
const fail = msg => { console.error("fetch-orcid-keys: " + msg); process.exit(1); };
const warn = msg => console.error("fetch-orcid-keys: " + msg);
const read = p => parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(fs.readFileSync(p)));

const ORCID_URL = "https://orcid.org/oauth/jwks";
const WAYBACK = "https://web.archive.org";
const MAX = 64 * 1024;
const trust = read(opt("--trust"));

const usable = k => k && typeof k === "object" && k.kty === "RSA" && ["kid", "n", "e"].every(f => typeof k[f] === "string" && k[f] !== "") &&
  (k.use === undefined || k.use === "sig") && (k.alg === undefined || k.alg === "RS256");
const triple = k => JSON.stringify([k.kid, k.n, k.e]);
function jwksKeys(bytes) {
  const doc = parseJsonStrict(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  if (!doc || !Array.isArray(doc.keys)) throw new Error("not a JWKS");
  return doc.keys.filter(usable).map(k => ({ kty: "RSA", kid: k.kid, n: k.n, e: k.e }));
}
async function get(url) {
  const res = await fetch(url, { redirect: "manual" });
  const chunks = [];
  let size = 0;
  if (res.body) {
    for await (const chunk of res.body) {
      size += chunk.length;
      if (size > MAX) throw new Error(`answer from ${url} larger than ${MAX} bytes`);
      chunks.push(chunk);
    }
  }
  const buf = new Uint8Array(size);
  let at = 0;
  for (const c of chunks) { buf.set(c, at); at += c.length; }
  return { status: res.status, bytes: buf };
}

// Wayback: the archive's own index must name exactly the ORCID URL at that timestamp.
async function wayback(url) {
  const m = url.match(/^https:\/\/web\.archive\.org\/web\/(\d{14})\/(.+)$/);
  if (!m) return { error: "not a Wayback capture URL" };
  if (m[2] !== ORCID_URL) return { error: `a capture of another URL (${m[2]})` };
  const ts = m[1];
  const cdx = await get(`${WAYBACK}/cdx/search/cdx?url=${encodeURIComponent(ORCID_URL)}&from=${ts}&to=${ts}&output=json`);
  if (cdx.status !== 200) return { error: `CDX answered HTTP ${cdx.status}` };
  const rows = JSON.parse(new TextDecoder().decode(cdx.bytes));
  const header = Array.isArray(rows) ? rows[0] : null;
  const atTs = Array.isArray(header) ? rows.slice(1).filter(r => Array.isArray(r) && r.length === header.length && r[header.indexOf("timestamp")] === ts) : [];
  if (atTs.some(r => r[header.indexOf("original")] !== ORCID_URL)) return { error: `the archive holds another URL at ${ts} too; the raw bytes would be ambiguous` };
  const ok = atTs.some(r => r[header.indexOf("statuscode")] === "200");
  if (!ok) return { error: `the archive does not list ${ORCID_URL} at ${ts} with HTTP 200` };
  const raw = await get(`${WAYBACK}/web/${ts}id_/${ORCID_URL}`);
  if (raw.status !== 200) return { error: `the raw capture answered HTTP ${raw.status}` };
  const time = `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}T${ts.slice(8, 10)}:${ts.slice(10, 12)}:${ts.slice(12, 14)}Z`;
  return { archive: "wayback", time, keys: jwksKeys(raw.bytes) };
}

const jwksDir = path.join(dir, "jwks");
const files = fs.existsSync(jwksDir) ? fs.readdirSync(jwksDir).filter(f => f.endsWith(".json")).sort() : [];
const seen = new Map(); // triple -> { jwk, archives: Set, times: [] }
const checked = new Set();
for (const f of files) {
  const text = fs.readFileSync(path.join(jwksDir, f), "utf8");
  let b;
  try { b = parseJsonStrict(text); } catch { warn(`${f}: not strict JSON; ignored`); continue; }
  const { parts, notes } = await verifyBundle(text, trust);
  if (b?.record?.type !== "jwks" || parts.platform !== "verified" || parts.log !== "verified" || parts.content !== "verified") {
    warn(`${f}: not a jwks record that verifies against the trust file (${notes.slice(0, 2).join("; ")}); ignored`);
    continue;
  }
  if (b.content?.url !== ORCID_URL) { warn(`${f}: a record of another URL; ignored`); continue; }
  for (const url of b.content.captures || []) {
    if (checked.has(url)) continue;
    checked.add(url);
    let host = null;
    try { host = new URL(url).host.toLowerCase(); } catch { /* reported below */ }
    let r;
    if (host === "web.archive.org") {
      try { r = await wayback(url); } catch (e) { r = { error: e.message }; }
    } else r = { error: "not a Wayback capture (only those are checked)" };
    if (r.error) { warn(`${url}: ${r.error}; ignored`); continue; }
    for (const k of r.keys) {
      const t = triple(k);
      if (!seen.has(t)) seen.set(t, { jwk: k, archives: new Set(), times: [] });
      seen.get(t).archives.add(r.archive);
      if (r.time) seen.get(t).times.push(r.time);
    }
  }
}

const orcidKeys = [];
for (const { jwk, archives, times } of seen.values()) {
  if (times.length === 0) { warn(`key ${jwk.kid}: no verified Wayback capture shows it`); continue; }
  times.sort();
  orcidKeys.push({ jwk, first_capture: times[0], last_capture: times.at(-1), archives: [...archives] });
}
if (args.includes("--live")) {
  try {
    const live = await get(ORCID_URL);
    if (live.status !== 200) throw new Error(`HTTP ${live.status}`);
    const fetchedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
    for (const jwk of jwksKeys(live.bytes)) orcidKeys.push({ jwk, first_capture: null, last_capture: null, source: "live", fetched_at: fetchedAt });
  } catch (e) { fail(`cannot fetch ORCID's live keys: ${e.message}`); }
}
if (orcidKeys.length === 0) warn("no ORCID key qualifies; identity will be not_checked");
// Earlier live entries are replaced, never accumulated.
const kept = (trust.orcid_keys || []).filter(k => !(args.includes("--live") && k?.source === "live"));
trust.orcid_keys = [...kept, ...orcidKeys];
process.stdout.write(JSON.stringify(trust, null, 2) + "\n");
