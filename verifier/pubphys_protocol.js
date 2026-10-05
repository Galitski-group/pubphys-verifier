// PubPhys protocol, version 1 (see protocol/SPEC.md). Dependency-free ES module that runs in
// the browser and under Node. It builds and checks the hashed objects, the batch nonce, the
// transparency-log proofs and signed notes, and verifies whole bundles. Hashing uses WebCrypto,
// so most functions are async.

import SCHEMAS from "./schemas.js";

const enc = new TextEncoder();
// ignoreBOM: a byte-order mark is kept and then refused (SPEC 1), as in Ruby (review F27, A12).
const dec = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const subtle = globalThis.crypto.subtle;

export const SITE = "pubphys.com";
export const LOG_NAME = "pubphys.com/log/v1";
export const ORCID_ISSUER = "https://orcid.org";
export const MAX_LOG = Number.MAX_SAFE_INTEGER;
export const SCHEMA_SET = SCHEMAS;

export class ProtocolError extends Error {}
export class CanonicalError extends ProtocolError {}

// ---------- strict encodings (SPEC section 1) ----------

export function hex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, "0")).join("");
}

export function fromHex(s) {
  if (typeof s !== "string" || !/^(?:[0-9a-f]{2})*$/.test(s)) throw new ProtocolError("invalid hex");
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function b64(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64url(bytes) {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64(s) {
  if (typeof s !== "string" || s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) throw new ProtocolError("invalid base64");
  let bytes;
  try { bytes = Uint8Array.from(atob(s), c => c.charCodeAt(0)); } catch { throw new ProtocolError("invalid base64"); }
  if (b64(bytes) !== s) throw new ProtocolError("non-canonical base64");
  return bytes;
}

export function fromB64url(s) {
  if (typeof s !== "string" || s.length % 4 === 1 || !/^[A-Za-z0-9_-]*$/.test(s)) throw new ProtocolError("invalid base64url");
  let std = s.replace(/-/g, "+").replace(/_/g, "/");
  while (std.length % 4) std += "=";
  let bytes;
  try { bytes = Uint8Array.from(atob(std), c => c.charCodeAt(0)); } catch { throw new ProtocolError("invalid base64url"); }
  if (b64url(bytes) !== s) throw new ProtocolError("non-canonical base64url");
  return bytes;
}

function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest("SHA-256", typeof bytes === "string" ? enc.encode(bytes) : bytes));
}

export async function sha256hex(bytes) {
  return hex(await sha256(bytes));
}

const TIME_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/;

// Years 1970 to 9999 only (SPEC section 1).
export function parseTime(s) {
  const m = TIME_RE.exec(s);
  if (!m || +m[1] < 1970) return null;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]);
  return new Date(t).toISOString().replace(".000Z", "Z") === s ? t / 1000 : null;
}

// ---------- strict JSON: duplicate keys rejected (SPEC section 1) ----------

// The protocol's JSON profile: RFC 8259 without extensions, valid UTF-8 (strings given here are
// already decoded), no lone surrogates, no duplicate keys, depth at most 32, numbers only as
// integers without fraction or exponent in the safe range. Mirrors Ruby StrictJson.
const JSON_STRING = /^"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"/;
const JSON_NUMBER = /^-?(?:0|[1-9][0-9]*)(?![0-9.eE])/;
const JSON_MAX_DEPTH = 32;

export function parseJsonStrict(text) {
  if (typeof text !== "string" || !text.isWellFormed()) throw new ProtocolError("invalid JSON: not valid Unicode");
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const fail = msg => { throw new ProtocolError(`invalid JSON at ${i}: ${msg}`); };
  const str = () => {
    const m = JSON_STRING.exec(text.slice(i));
    if (!m) fail("invalid string");
    i += m[0].length;
    const v = JSON.parse(m[0]);
    if (!v.isWellFormed()) fail("string is not valid Unicode");
    return v;
  };
  const value = depth => {
    ws();
    const c = text[i];
    if (c === "{" || c === "[") {
      if (depth >= JSON_MAX_DEPTH) fail(`nesting deeper than ${JSON_MAX_DEPTH}`);
      i++;
      ws();
      if (c === "[") {
        const out = [];
        if (text[i] === "]") { i++; return out; }
        for (;;) {
          out.push(value(depth + 1));
          ws();
          if (text[i] === ",") { i++; continue; }
          if (text[i] === "]") { i++; return out; }
          fail("expected , or ]");
        }
      }
      const out = {};
      if (text[i] === "}") { i++; return out; }
      for (;;) {
        ws();
        if (text[i] !== "\"") fail("expected key");
        const k = str();
        if (Object.hasOwn(out, k)) fail(`duplicate key ${JSON.stringify(k)}`);
        ws();
        if (text[i] !== ":") fail("expected :");
        i++;
        Object.defineProperty(out, k, { value: value(depth + 1), enumerable: true, writable: true, configurable: true });
        ws();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return out; }
        fail("expected , or }");
      }
    }
    if (c === "\"") return str();
    const rest = text.slice(i);
    const m = JSON_NUMBER.exec(rest);
    if (m) {
      i += m[0].length;
      const n = Number(m[0]);
      if (!Number.isSafeInteger(n)) fail("integer out of range");
      return n === 0 ? 0 : n;
    }
    for (const [word, v] of [["true", true], ["false", false], ["null", null]]) {
      if (rest.startsWith(word) && !/^[A-Za-z0-9_]/.test(rest.slice(word.length))) { i += word.length; return v; }
    }
    fail("unexpected token");
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail("trailing data");
  return v;
}

// ---------- canonical form (SPEC section 2) ----------

function escapeString(s) {
  if (!s.isWellFormed()) throw new CanonicalError("string is not valid Unicode");
  let out = "\"";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === "\"") out += "\\\"";
    else if (ch === "\\") out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u00" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out + "\"";
}

export function canonical(value) {
  if (value === null) return "null";
  if (typeof value === "string") return escapeString(value);
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value);
    for (const k of keys) if (!/^[\x20-\x7e]*$/.test(k)) throw new CanonicalError("key is not printable ASCII: " + JSON.stringify(k));
    return "{" + keys.sort().map(k => escapeString(k) + ":" + canonical(value[k])).join(",") + "}";
  }
  throw new CanonicalError("value of type " + typeof value + " is not allowed");
}

export async function hashObject(value) {
  return sha256hex(canonical(value));
}

// Builders call this on every text field typed by people (SPEC section 2).
export function normalizeText(s) {
  return s.replace(/\r\n?/g, "\n").normalize("NFC");
}

// ---------- array order (SPEC section 3) ----------

function compareUtf8(a, b) {
  const x = enc.encode(a), y = enc.encode(b);
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function sortedUnique(list) {
  for (let i = 1; i < list.length; i++) if (typeof list[i] !== "string" || compareUtf8(list[i - 1], list[i]) >= 0) return false;
  return true;
}

export function arrayOrderProblems(value, path = "$") {
  const problems = [];
  if (Array.isArray(value)) {
    if (value.every(v => typeof v === "string")) {
      if (!sortedUnique(value)) problems.push(path + " is not sorted and unique");
    } else if (value.every(v => v && typeof v === "object" && !Array.isArray(v))) {
      const last = path.split(".").pop();
      const key = last === "files" ? "id" : last === "parents" ? "parent_revision" : null;
      if (!key) problems.push(path + " is an array of objects without a defined sort key");
      else if (!sortedUnique(value.map(v => v[key]))) problems.push(path + " is not sorted by " + key);
    } else {
      problems.push(path + " mixes value types");
    }
    value.forEach((v, i) => problems.push(...arrayOrderProblems(v, path + "[" + i + "]")));
  } else if (value && typeof value === "object") {
    for (const [k, v] of Object.entries(value)) problems.push(...arrayOrderProblems(v, path + "." + k));
  }
  return problems;
}

// ---------- schema subset (SPEC section 12) ----------

function typeOf(v) {
  if (v === null) return "null";
  if (Array.isArray(v)) return "array";
  if (typeof v === "number") return Number.isInteger(v) ? "integer" : "number";
  if (typeof v === "string" && !v.isWellFormed()) return "invalid string";
  return typeof v;
}

export function validateSchema(value, schema, path = "$") {
  const errors = [];
  if (Object.hasOwn(schema, "const") && value !== schema.const) errors.push(`${path} must be ${JSON.stringify(schema.const)}`);
  if (schema.type) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.includes(typeOf(value))) return [...errors, `${path} must be of type ${types.join("|")}`];
  }
  if (schema.enum && !schema.enum.includes(value)) errors.push(`${path} must be one of ${schema.enum.join(", ")}`);
  if (schema.pattern && typeof value === "string" && !new RegExp(schema.pattern, "u").test(value)) errors.push(`${path} does not match ${schema.pattern}`);
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${path} has too few items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${path} has too many items`);
    if (schema.items) value.forEach((v, i) => errors.push(...validateSchema(v, schema.items, `${path}[${i}]`)));
  }
  if (typeOf(value) === "object") {
    for (const k of schema.required || []) if (!Object.hasOwn(value, k)) errors.push(`${path}.${k} is required`);
    const props = schema.properties || {};
    for (const k of Object.keys(value)) {
      if (Object.hasOwn(props, k)) errors.push(...validateSchema(value[k], props[k], `${path}.${k}`));
      else if (schema.additionalProperties === false) errors.push(`${path}.${k} is not allowed`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === "object") errors.push(...validateSchema(value[k], schema.additionalProperties, `${path}.${k}`));
    }
  }
  return errors;
}

// ---------- cross-field rules (SPEC sections 4, 6, 7, 10) ----------

const ORIGINS = {
  topic: ["human", "seed"], revision: ["human", "seed"], upload: ["human"], claim: ["human"], contest: ["human"],
  appeal: ["human"], review: ["human", "platform"], withdrawal: ["human"], reveal: ["human"],
  appointment: ["human", "platform"], attribution: ["human", "platform"], "import-manifest": ["platform"],
  "platform-key": ["platform"], "platform-key-revocation": ["platform"], jwks: ["platform"],
};
const TARGET_REQUIRED = new Set(["claim", "contest", "appeal", "review", "withdrawal", "reveal", "platform-key-revocation"]);
const NO_PARENTS = new Set(["upload", "appeal", "review", "withdrawal", "reveal", "appointment", "attribution", "import-manifest", "platform-key-revocation", "jwks"]);
const REVIEW_PARAMS = {
  credit: ["credited"], carry_acceptance: ["problem_ref"], verify_note: ["problem_ref"], reassign_topic: ["problem_ref", "topic_ref"],
};
const FILE_REFS = { upload: "file_id", "import-manifest": "items_file_id", jwks: "jwks_file_id" };

export function recordRuleProblems(record, content) {
  const p = [];
  const { orcid, account_ref } = record.author;
  const kind = record.origin.kind;
  if (kind === "human" && (orcid === null) === (account_ref === null)) p.push("human record needs exactly one of orcid and account_ref");
  if (kind !== "human" && (orcid !== null || account_ref !== null)) p.push(`${kind} record must have a null author`);
  if (parseTime(record.created) === null) p.push("created is not a real time");
  const type = record.type;
  if (Object.hasOwn(ORIGINS, type) && !ORIGINS[type].includes(kind)) p.push(`${type} records cannot have origin ${kind}`);
  if (TARGET_REQUIRED.has(type) && record.target === null) p.push(`${type} requires a target`);
  if (["topic", "revision", "upload", "attribution", "import-manifest", "platform-key", "jwks"].includes(type) && record.target !== null) p.push(`${type} must not have a target`);
  if (NO_PARENTS.has(type) && record.parents.length) p.push(`${type} must not have parents`);
  if (content === null) return p;
  if (type === "topic") {
    if ((content.topic_ref === null) !== (content.n === "1")) p.push("topic_ref must be null exactly for n = 1");
    if (content.n === "1" && record.parents.length) p.push("first topic revision has no parents");
    if (record.parents.length > 1) p.push("topic has at most one parent");
  }
  if (type === "revision") {
    if ((content.problem_ref === null) !== (content.n === "1")) p.push("problem_ref must be null exactly for n = 1");
    if ((content.topic_ref !== null) !== (content.n === "1")) p.push("topic_ref must be set exactly for n = 1");
    if (content.n !== "1" && content.parents.length) p.push("only revision 1 declares parents");
    if (content.external_id !== null && kind !== "seed") p.push("external_id is only for seed revisions");
    if (content.parents.some(x => !record.parents.includes(x.parent_revision))) p.push("declared parents must appear in record.parents");
  }
  if (type === "platform-key") {
    if (content.previous_key_id === content.key_id) p.push("previous_key_id must differ from key_id");
    const want = content.previous_key_id === null ? 0 : 1;
    if (record.parents.length !== want) p.push(`platform-key needs exactly ${want} parent(s)`);
  }
  if (type === "attribution" && (content.new_author_orcid === null) === (content.new_account_ref === null)) p.push("attribution needs exactly one new author");
  if (type === "appointment" && (content.action === "revoke") === (record.target === null)) p.push("appointment target must be set exactly for revoke");
  if (type === "review") {
    const want = Object.hasOwn(REVIEW_PARAMS, content.decision) ? REVIEW_PARAMS[content.decision] : [];
    const have = Object.keys(content.params).sort();
    if (canonical(have) !== canonical([...want].sort())) p.push(`review ${content.decision} params must be exactly [${want.join(", ")}]`);
    for (const k of ["problem_ref", "topic_ref"]) {
      if (Object.hasOwn(content.params, k) && !/^[0-9a-f]{64}$/.test(content.params[k])) p.push(`review param ${k} must be a record hash`);
    }
    if (content.params.credited === "") p.push("review param credited must not be empty");
  }
  if (Object.hasOwn(FILE_REFS, type)) {
    if (canonical(record.files.map(f => f.id)) !== canonical([content[FILE_REFS[type]]])) p.push(`${type} must list exactly the file named by ${FILE_REFS[type]}`);
  } else if (record.files.length) {
    p.push(`${type} records carry no files`);
  }
  return p;
}

export function attestationRuleProblems(record, attested) {
  const a = attested.attestation;
  const p = [];
  const nulls = a.batch === null && a.id_token_sha256 === null && a.client_id === null;
  if (a.kind === "orcid-oidc") {
    if (record.origin.kind !== "human" || record.author.orcid === null) p.push("orcid-oidc needs a human record with an ORCID iD");
    if (a.batch === null || a.id_token_sha256 === null || a.client_id === null) p.push("orcid-oidc needs batch, id_token_sha256 and client_id");
    if (a.batch !== null && !a.batch.includes(attested.record_hash)) p.push("batch must contain the record hash");
  } else {
    if (!nulls) p.push(`${a.kind} attestation must have null batch, id_token_sha256 and client_id`);
    if (a.kind === "platform" && !["seed", "platform"].includes(record.origin.kind)) p.push("platform attestation needs origin seed or platform");
    if (a.kind === "none" && record.origin.kind !== "human") p.push("none attestation needs origin human");
    if (a.kind === "none" && record.author.orcid !== null && record.type !== "upload") p.push("only uploads may name an ORCID iD without ORCID attestation");
  }
  return p;
}

function bundleRuleProblems(bundle) {
  const p = [];
  const { record, attested } = bundle;
  if ((bundle.content === null) !== (bundle.content_withheld === "true")) p.push("content and content_withheld disagree");
  const kind = attested.attestation.kind;
  if (kind === "orcid-oidc") {
    if ((bundle.id_token === null) !== (bundle.id_token_withheld === "true")) p.push("id_token and id_token_withheld disagree");
  } else if (bundle.id_token !== null || bundle.id_token_withheld !== "false") {
    p.push("only orcid-oidc bundles carry an id_token");
  }
  for (const k of ["leaf_index", "tree_size"]) if (Number(bundle.log[k]) > MAX_LOG) p.push(`log ${k} exceeds 2^53 - 1`);
  for (const k of ["attested", "envelope"]) {
    for (const proof of bundle.ots[k]) {
      try { if (fromB64url(proof).length === 0) p.push(`ots.${k} entry is empty`); } catch { p.push(`ots.${k} entry is not canonical base64url`); }
    }
  }
  const declared = record.files.map(f => f.id);
  const given = bundle.files.map(f => f.id);
  if (canonical([...given].sort()) !== canonical([...declared].sort()) || new Set(given).size !== given.length) p.push("bundle files must list each record file exactly once");
  if (bundle.attesting !== null) {
    const at = bundle.attesting;
    if (record.type !== "upload") p.push("only upload bundles may carry an attesting bundle");
    else if (!at || typeof at !== "object" || !at.record || !at.attested) p.push("attesting bundle is malformed");
    else {
      if (at.attesting !== null) p.push("attesting bundle must not nest further");
      if (at.record.type === "upload") p.push("attesting record cannot be an upload");
      if (!at.attested.attestation || at.attested.attestation.kind !== "orcid-oidc") p.push("attesting record must be orcid-oidc");
    }
  }
  return p;
}

// ---------- attestation (SPEC section 7) ----------

export function normalizeBatch(hashes) {
  return [...new Set(hashes)].sort();
}

export async function batchNonce(hashes) {
  return sha256hex("pubphys.attest/1\n" + (await sha256hex(normalizeBatch(hashes).join("\n"))));
}

export function decodeJwt(jwt) {
  const segs = jwt.split(".");
  if (segs.length !== 3) throw new ProtocolError("JWT must have three segments");
  const [h, p, s] = segs;
  const header = parseJsonStrict(dec.decode(fromB64url(h)));
  const payload = parseJsonStrict(dec.decode(fromB64url(p)));
  if (typeOf(header) !== "object" || typeOf(payload) !== "object") throw new ProtocolError("JWT header and payload must be objects");
  return { header, payload, signingInput: enc.encode(h + "." + p), signature: fromB64url(s) };
}

async function importRsa(jwk) {
  if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") throw new ProtocolError("ORCID key is not an RSA JWK");
  const n = fromB64url(jwk.n);
  // Bits from the first non-zero byte on, as OpenSSL counts them (review F27, A15).
  let i = 0;
  while (i < n.length && n[i] === 0) i++;
  const bits = i < n.length ? (n.length - i) * 8 - (Math.clz32(n[i]) - 24) : 0;
  if (bits < 2048) throw new ProtocolError("ORCID key modulus is shorter than 2048 bits");
  fromB64url(jwk.e);
  return subtle.importKey("jwk", { kty: "RSA", n: jwk.n, e: jwk.e, ext: true }, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
}

export async function verifyRs256(jwt, jwk) {
  const { signingInput, signature } = decodeJwt(jwt);
  return subtle.verify("RSASSA-PKCS1-v1_5", await importRsa(jwk), signature, signingInput);
}

const DAY = 24 * 3600;

// Trusted keys come only from the verifier (SPEC 7.3): live keys have null capture times.
function trustedOrcidKeys(header, payload, trustedKeys) {
  const out = [];
  for (const k of trustedKeys || []) {
    if (!k || !k.jwk || k.jwk.kid !== header.kid) continue;
    if ((k.first_capture ?? null) === null && (k.last_capture ?? null) === null) { out.push(k.jwk); continue; }
    const first = parseTime(k.first_capture), last = parseTime(k.last_capture);
    if (first !== null && last !== null && payload.iat >= first - DAY && payload.iat <= last + DAY) out.push(k.jwk);
  }
  return out;
}

// Returns { status: "verified" | "failed" | "not_checked", reason }.
export async function checkOrcidAttestation({ record, recordHash, attested, idToken, trustedKeys, trustedClientIds, earliestAnchor }) {
  const a = attested.attestation;
  const failed = reason => ({ status: "failed", reason });
  if (!a.batch.includes(recordHash)) return failed("record is not in the batch");
  if ((await sha256hex(idToken)) !== a.id_token_sha256) return failed("id_token hash mismatch");
  let d;
  try { d = decodeJwt(idToken); } catch (e) { return failed(e.message); }
  const { header, payload } = d;
  if (header.alg !== "RS256" || typeof header.kid !== "string") return failed("id_token header must have alg RS256 and a kid");
  if (!Number.isSafeInteger(payload.iat) || payload.iat < 0) return failed("iat must be a non-negative integer");
  if (payload.iss !== ORCID_ISSUER) return failed("iss is not ORCID");
  if (typeof payload.aud !== "string" || payload.aud !== a.client_id || !(trustedClientIds || []).includes(a.client_id)) return failed("aud or client_id not trusted");
  if (payload.sub !== record.author.orcid) return failed("sub does not match author.orcid");
  if (payload.nonce !== (await batchNonce(a.batch))) return failed("nonce does not match batch");
  if (earliestAnchor) {
    const t = parseTime(earliestAnchor);
    if (t === null || payload.iat < t - 72 * 3600 || payload.iat > t + 2 * 3600) return failed("iat outside the window around the earliest anchor");
  }
  const jwks = trustedOrcidKeys(header, payload, trustedKeys);
  if (!jwks.length) return { status: "not_checked", reason: "no trusted ORCID key for this token" };
  for (const jwk of jwks) {
    try { if (await subtle.verify("RSASSA-PKCS1-v1_5", await importRsa(jwk), d.signature, d.signingInput)) return { status: "verified" }; } catch { /* try the next key */ }
  }
  return failed("id_token signature invalid");
}

// ---------- platform keys (SPEC section 8) ----------

export async function keyId(publicKeyB64url) {
  return sha256hex(fromB64url(publicKeyB64url));
}

export async function ed25519Verify(publicKeyBytes, signature, message) {
  if (publicKeyBytes.length !== 32 || signature.length !== 64) return false;
  const key = await subtle.importKey("raw", publicKeyBytes, { name: "Ed25519" }, false, ["verify"]);
  return subtle.verify("Ed25519", key, signature, message);
}

async function keyById(id, keys) {
  for (const pk of keys || []) if ((await keyId(pk)) === id) return pk;
  return null;
}

export async function verifyEnvelopeSignature(envelope, keys) {
  const pk = await keyById(envelope.platform_signature.key_id, keys);
  if (!pk) return false;
  return ed25519Verify(fromB64url(pk), fromB64url(envelope.platform_signature.sig), enc.encode("pubphys.platform/1\n" + envelope.attested_hash));
}

async function rotationProblems(content, envelope, trust) {
  if ((await keyId(content.public_key)) !== content.key_id) return "key_id does not match public_key";
  const selfOk = await ed25519Verify(fromB64url(content.public_key), fromB64url(content.new_key_signature), enc.encode("pubphys.platform-key/1\n" + content.key_id));
  if (!selfOk) return "new key signature invalid";
  const signer = envelope.platform_signature.key_id;
  const byRecovery = await verifyEnvelopeSignature(envelope, trust.recovery_keys);
  const byPrevious = content.previous_key_id !== null && signer === content.previous_key_id && (await verifyEnvelopeSignature(envelope, trust.platform_keys));
  if (!byRecovery && !byPrevious) return "rotation must be signed by the previous key or a recovery key";
  return null;
}

async function revocationProblems(content, envelope, trust) {
  if (envelope.platform_signature.key_id === content.key_id) return "a key cannot revoke itself";
  if (await verifyEnvelopeSignature(envelope, trust.recovery_keys)) return null;
  return (await verifyEnvelopeSignature(envelope, trust.platform_keys)) ? null : "revocation must be signed by a recovery key or another signing key";
}

// ---------- transparency log (SPEC section 9, RFC 9162) ----------

export async function leafHashRaw(data) {
  return sha256(concat(new Uint8Array([0]), typeof data === "string" ? enc.encode(data) : data));
}

export async function leafHash(envelopeHash, recordType) {
  return leafHashRaw(canonical({ envelope_hash: envelopeHash, record_type: recordType }));
}

export async function nodeHash(left, right) {
  return sha256(concat(new Uint8Array([1]), left, right));
}

const half = n => Math.floor(n / 2);
const odd = n => n % 2 === 1;

function isPowerOfTwo(n) {
  while (n > 1 && n % 2 === 0) n /= 2;
  return n === 1;
}

function largestPowerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

export async function merkleRoot(leafHashes) {
  if (leafHashes.length === 0) return sha256(new Uint8Array());
  if (leafHashes.length === 1) return leafHashes[0];
  const k = largestPowerOfTwoBelow(leafHashes.length);
  return nodeHash(await merkleRoot(leafHashes.slice(0, k)), await merkleRoot(leafHashes.slice(k)));
}

function validSize(n) {
  return Number.isSafeInteger(n) && n >= 0;
}

export async function verifyInclusion(leafIndex, treeSize, leaf, proof, root) {
  if (!validSize(leafIndex) || !validSize(treeSize) || leafIndex >= treeSize) return false;
  let fn = leafIndex, sn = treeSize - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      r = await nodeHash(p, r);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      r = await nodeHash(r, p);
    }
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && hex(r) === hex(root);
}

export async function verifyConsistency(size1, size2, proof, root1, root2) {
  if (!validSize(size1) || !validSize(size2) || size1 > size2) return false;
  if (size1 === size2) return proof.length === 0 && hex(root1) === hex(root2);
  if (size1 === 0) return proof.length === 0;
  if (proof.length === 0) return false;
  const path = isPowerOfTwo(size1) ? [root1, ...proof] : proof;
  let fn = size1 - 1, sn = size2 - 1;
  while (odd(fn)) { fn = half(fn); sn = half(sn); }
  let fr = path[0], sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if (odd(fn) || fn === sn) {
      fr = await nodeHash(c, fr);
      sr = await nodeHash(c, sr);
      if (!odd(fn)) while (!odd(fn) && fn !== 0) { fn = half(fn); sn = half(sn); }
    } else {
      sr = await nodeHash(sr, c);
    }
    fn = half(fn); sn = half(sn);
  }
  return sn === 0 && hex(fr) === hex(root1) && hex(sr) === hex(root2);
}

// ---------- signed notes (SPEC section 9; golang.org/x/mod/sumdb/note rules) ----------

// Characters Go's unicode.IsSpace accepts, plus "+": none may appear in a key name.
const NOTE_NAME = /^[^\t\n\v\f\r \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000+]+$/u;

export async function noteKeyHash(name, publicKeyBytes) {
  return (await sha256(concat(enc.encode(name), new Uint8Array([0x0a, 0x01]), publicKeyBytes))).slice(0, 4);
}

export function parseNote(text) {
  if (typeof text !== "string" || !text.isWellFormed() || /[\x00-\x09\x0b-\x1f]/.test(text)) throw new ProtocolError("note has invalid characters");
  const split = text.lastIndexOf("\n\n");
  if (split < 0) throw new ProtocolError("note has no signature block");
  const body = text.slice(0, split + 1);
  const block = text.slice(split + 2);
  if (!block.endsWith("\n")) throw new ProtocolError("signature block must end with a newline");
  const lines = block.slice(0, -1).split("\n");
  if (lines.length > 100) throw new ProtocolError("too many signatures");
  const sigs = lines.map(line => {
    if (!line.startsWith("\u2014 ")) throw new ProtocolError("malformed signature line");
    const rest = line.slice(2);
    const sp = rest.indexOf(" ");
    const name = sp < 0 ? rest : rest.slice(0, sp), b64text = sp < 0 ? "" : rest.slice(sp + 1);
    if (!NOTE_NAME.test(name) || b64text === "") throw new ProtocolError("malformed signature line");
    const raw = fromB64(b64text);
    if (raw.length < 5) throw new ProtocolError("signature too short");
    return { name, keyHash: raw.slice(0, 4), signature: raw.slice(4) };
  });
  return { body, lines: body.slice(0, -1).split("\n"), sigs };
}

// As in Go's note.Open, a signature line by a known key that does not verify invalidates the note.
export async function verifyNote(text, name, keys) {
  const note = parseNote(text);
  let verified = false;
  for (const pk of keys || []) {
    const pub = fromB64url(pk);
    const kh = hex(await noteKeyHash(name, pub));
    for (const s of note.sigs) {
      if (s.name !== name || hex(s.keyHash) !== kh) continue;
      if (!(await ed25519Verify(pub, s.signature, enc.encode(note.body)))) return null;
      verified = true;
    }
  }
  return verified ? note : null;
}

export function parsePromise(note) {
  if (note.lines.length !== 5) throw new ProtocolError("promise must have exactly five lines");
  const [origin, leaf, index, issued, deadline] = note.lines;
  if (origin !== LOG_NAME + " promise") throw new ProtocolError(`promise origin is not ${LOG_NAME} promise`);
  if (!/^[0-9a-f]{64}$/.test(leaf)) throw new ProtocolError("promise leaf hash is not a hash");
  if (!DECIMAL.test(index) || !Number.isSafeInteger(Number(index))) throw new ProtocolError("promise index is not a valid decimal");
  const t0 = parseTime(issued), t1 = parseTime(deadline);
  if (t0 === null || t1 === null || t1 < t0 || t1 - t0 > 7200) throw new ProtocolError("promise deadline must be at most two hours after issue");
  return { leafHash: leaf, leafIndex: Number(index), issued, deadline };
}

const DECIMAL = /^(0|[1-9][0-9]*)$/;

export function parseCheckpoint(note) {
  if (note.lines.length !== 3) throw new ProtocolError("checkpoint must have exactly three lines");
  const [origin, size, root] = note.lines;
  if (origin !== LOG_NAME) throw new ProtocolError("checkpoint origin is not " + LOG_NAME);
  if (!DECIMAL.test(size) || !Number.isSafeInteger(Number(size))) throw new ProtocolError("checkpoint size is not a valid decimal");
  const rootBytes = fromB64(root);
  if (rootBytes.length !== 32) throw new ProtocolError("checkpoint root must be 32 bytes");
  return { treeSize: Number(size), root: rootBytes };
}

// ---------- bundle verification (SPEC section 11) ----------

function schemaFor(name) {
  return Object.hasOwn(SCHEMAS, name) ? SCHEMAS[name] : null;
}

// Structure checks. Returns { status: "verified" | "not_checked" | "failed", notes }.
export function checkStructure(bundle) {
  const failed = notes => ({ status: "failed", notes: notes.slice(0, 3) });
  try {
    const errs = validateSchema(bundle, SCHEMAS.bundle);
    if (errs.length) return failed(errs);
    const { record, attested, envelope, content } = bundle;
    for (const [v, name] of [[record, "record"], [attested, "attested"], [envelope, "envelope"]]) {
      const e = validateSchema(v, SCHEMAS[name]);
      if (e.length) return failed(e);
    }
    const version = record.content_schema.split("/").pop();
    if (record.content_schema !== `pubphys.content.${record.type}/${version}`) return failed(["content_schema does not match type"]);
    const contentSchema = version === "1" ? schemaFor("content." + record.type) : null;
    let status = "verified";
    const notes = [];
    if (!contentSchema) { status = "not_checked"; notes.push(`unknown content schema ${record.content_schema}`); }
    else if (content === null) { status = "not_checked"; notes.push("content withheld: content rules not checked"); }
    else {
      const e = validateSchema(content, contentSchema);
      if (e.length) return failed(e);
    }
    const checkedContent = contentSchema ? content : null;
    const order = [record, attested, checkedContent].flatMap(v => (v === null ? [] : arrayOrderProblems(v)));
    if (order.length) return failed(order);
    const rules = [...recordRuleProblems(record, checkedContent), ...attestationRuleProblems(record, attested), ...bundleRuleProblems(bundle)];
    if (rules.length) return failed(rules);
    if (bundle.attesting !== null) {
      const inner = checkStructure(bundle.attesting);
      if (inner.status === "failed") return failed(inner.notes.map(n => "attesting: " + n));
      if (inner.status === "not_checked") { status = "not_checked"; notes.push(...inner.notes.map(n => "attesting: " + n)); }
    }
    return { status, notes };
  } catch (e) {
    return failed([e.message]);
  }
}

// Trust is verifier configuration; anything malformed is treated as absent.
export function normalizeTrust(trust) {
  const t = trust && typeof trust === "object" && !Array.isArray(trust) ? trust : {};
  const list = v => (Array.isArray(v) ? v : []);
  const w = t.witness;
  return {
    platform_keys: list(t.platform_keys).filter(x => typeof x === "string"),
    recovery_keys: list(t.recovery_keys).filter(x => typeof x === "string"),
    orcid_keys: list(t.orcid_keys).filter(x => x && typeof x === "object" && !Array.isArray(x)),
    orcid_client_ids: list(t.orcid_client_ids).filter(x => typeof x === "string"),
    earliest_anchor: typeof t.earliest_anchor === "string" ? t.earliest_anchor : null,
    witness: w && typeof w === "object" && !Array.isArray(w) ? w : null,
  };
}

export async function verifyBundle(input, rawTrust) {
  const trust = normalizeTrust(rawTrust);
  const parts = { structure: "verified", content: "verified", identity: "not_applicable", platform: "verified", log: "verified", witness: "not_checked", time: "not_checked" };
  const notes = [];
  const fail = (part, why) => { parts[part] = "failed"; notes.push(`${part}: ${why}`); };

  let bundle, st;
  try {
    bundle = typeof input === "string" ? parseJsonStrict(input) : input;
    st = checkStructure(bundle);
  } catch (e) {
    st = { status: "failed", notes: [e.message] };
  }
  if (st.status === "failed") {
    for (const k of Object.keys(parts)) parts[k] = "not_checked";
    fail("structure", st.notes.join("; "));
    return { parts, notes };
  }
  parts.structure = st.status;
  for (const n of st.notes) notes.push("structure: " + n);

  const { record, attested, envelope, content } = bundle;

  // content: the hash chain first, then the content object and the files
  let recordHash, envelopeHash;
  try {
    recordHash = await hashObject(record);
    envelopeHash = await hashObject(envelope);
    if (attested.record_hash !== recordHash) fail("content", "attested.record_hash mismatch");
    if (envelope.attested_hash !== (await hashObject(attested))) fail("content", "envelope.attested_hash mismatch");
  } catch (e) {
    for (const k of Object.keys(parts)) parts[k] = "not_checked";
    fail("structure", e.message);
    return { parts, notes };
  }
  let withheld = content === null;
  try {
    if (!withheld && (await hashObject(content)) !== record.content_sha256) fail("content", "content_sha256 mismatch");
  } catch (e) {
    fail("content", e.message);
  }
  for (const f of record.files) {
    const data = bundle.files.find(x => x.id === f.id);
    if (data.data === null) { withheld = true; continue; }
    try {
      const bytes = fromB64url(data.data);
      if ((await sha256hex(bytes)) !== f.sha256 || String(bytes.length) !== f.size) fail("content", `file ${f.id} hash or size mismatch`);
    } catch (e) {
      fail("content", `file ${f.id}: ${e.message}`);
    }
  }
  if (withheld && parts.content !== "failed") parts.content = "withheld";

  // identity
  try {
    if (attested.attestation.kind === "orcid-oidc") {
      if (bundle.id_token === null) parts.identity = "withheld";
      else {
        const r = await checkOrcidAttestation({ record, recordHash, attested, idToken: bundle.id_token, trustedKeys: trust.orcid_keys, trustedClientIds: trust.orcid_client_ids, earliestAnchor: trust.earliest_anchor });
        parts.identity = r.status;
        if (r.reason) notes.push(`identity: ${r.reason}`);
      }
    } else if (record.type === "upload" && record.author.orcid !== null) {
      const at = bundle.attesting;
      if (at === null) {
        parts.identity = "not_checked";
        notes.push("identity: upload names an ORCID iD but carries no attesting bundle");
      } else {
        const inner = (await verifyBundle(at, { ...trust, earliest_anchor: null, witness: null })).parts;
        if (["content", "platform", "log"].some(k => inner[k] === "failed")) fail("identity", "attesting bundle does not verify");
        else if (inner.identity !== "verified") { parts.identity = inner.identity === "failed" ? "failed" : "not_checked"; notes.push("identity: attesting bundle identity is " + inner.identity); }
        else if (!at.record.parents.includes(recordHash)) fail("identity", "attesting record does not list this upload in parents");
        else if (record.author.orcid !== at.record.author.orcid) fail("identity", "attesting record has a different author");
        else parts.identity = "verified";
      }
    }
  } catch (e) {
    fail("identity", e.message);
  }

  // platform
  try {
    if (record.type === "platform-key" || record.type === "platform-key-revocation") {
      if (content === null || !record.content_schema.endsWith("/1")) parts.platform = "not_checked";
      else {
        const why = record.type === "platform-key" ? await rotationProblems(content, envelope, trust) : await revocationProblems(content, envelope, trust);
        if (why) fail("platform", why);
      }
    } else if (!(await verifyEnvelopeSignature(envelope, trust.platform_keys))) {
      fail("platform", "envelope signature does not verify with a trusted signing key");
    }
  } catch (e) {
    fail("platform", e.message);
  }

  // log
  let checkpoint = null;
  try {
    const note = await verifyNote(bundle.log.checkpoint, LOG_NAME, trust.platform_keys);
    if (!note) fail("log", "checkpoint signature invalid");
    else {
      checkpoint = parseCheckpoint(note);
      const index = Number(bundle.log.leaf_index);
      const leaf = await leafHash(envelopeHash, record.type);
      if (String(checkpoint.treeSize) !== bundle.log.tree_size) fail("log", "tree size mismatch");
      else if (!(await verifyInclusion(index, checkpoint.treeSize, leaf, bundle.log.proof.map(fromHex), checkpoint.root))) fail("log", "inclusion proof does not match the checkpoint");
      if (bundle.log.promise !== null) {
        const pnote = await verifyNote(bundle.log.promise, LOG_NAME, trust.platform_keys);
        if (!pnote) fail("log", "inclusion promise signature invalid");
        else {
          const promise = parsePromise(pnote);
          if (promise.leafHash !== hex(leaf) || promise.leafIndex !== index) fail("log", "inclusion promise is for another leaf");
        }
      }
    }
  } catch (e) {
    fail("log", e.message);
    checkpoint = null;
  }

  // witness: the witnessed checkpoint must be the same size or newer, and consistent
  try {
    const w = trust.witness;
    if (w && typeof w === "object" && checkpoint && parts.log === "verified") {
      const wnote = await verifyNote(w.checkpoint, LOG_NAME, trust.platform_keys);
      if (!wnote) fail("witness", "witnessed checkpoint signature invalid");
      else {
        const wc = parseCheckpoint(wnote);
        if (wc.treeSize < checkpoint.treeSize) notes.push("witness: witnessed checkpoint is older than the bundle's checkpoint");
        else if (await verifyConsistency(checkpoint.treeSize, wc.treeSize, (w.proof || []).map(fromHex), checkpoint.root, wc.root)) parts.witness = "verified";
        else fail("witness", "bundle checkpoint is not consistent with the witnessed checkpoint");
      }
    }
  } catch (e) {
    fail("witness", e.message);
  }

  return { parts, notes, recordHash, envelopeHash };
}
