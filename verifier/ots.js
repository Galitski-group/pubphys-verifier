// OpenTimestamps proofs for the verifier's time part (protocol/SPEC.md sections 10, 11 and 14;
// wiki/platform/phase-1b-plan.md section 11). Parses .ots files, walks every path from the initial
// digest to its attestations, and checks Bitcoin attestations against block headers supplied by the
// caller. Covers the operations OpenTimestamps uses: sha256, sha1, ripemd160 is not supported (no
// Web Crypto implementation) and makes a path unusable, never valid.

const MAGIC = new Uint8Array([0x00, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x73, 0x00, 0x00,
  0x50, 0x72, 0x6f, 0x6f, 0x66, 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
const BITCOIN = "0588960d73d71901";
const PENDING = "83dfe30d2ef90c8e";
const MAX_DEPTH = 256;
const MAX_BYTES = 65536;

const toHex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
const concat = (a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a); r.set(b, a.length); return r; };
const digest = async (alg, bytes) => new Uint8Array(await crypto.subtle.digest(alg, bytes));

export class OtsError extends Error {}

class Reader {
  constructor(bytes) { this.b = bytes; this.i = 0; }
  byte() { if (this.i >= this.b.length) throw new OtsError("truncated proof"); return this.b[this.i++]; }
  bytes(n) { if (this.i + n > this.b.length) throw new OtsError("truncated proof"); const r = this.b.slice(this.i, this.i + n); this.i += n; return r; }
  varuint() {
    let value = 0, shift = 0;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * 2 ** shift;
      if (!(b & 0x80)) return value;
      shift += 7;
      if (shift > 49) throw new OtsError("varuint too large");
    }
  }
  varbytes(max = 8192) { const n = this.varuint(); if (n > max) throw new OtsError("field too long"); return this.bytes(n); }
}

// Returns { fileDigest, tree } where tree is { attestations: [...], ops: [{ op, arg, child }] }.
export function parseOts(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_BYTES) throw new OtsError("proof missing or too large");
  const r = new Reader(bytes);
  if (toHex(r.bytes(MAGIC.length)) !== toHex(MAGIC)) throw new OtsError("not an .ots file");
  if (r.varuint() !== 1) throw new OtsError("unsupported .ots version");
  if (r.byte() !== 0x08) throw new OtsError("only sha256 file digests are supported");
  const fileDigest = r.bytes(32);
  const tree = readTimestamp(r, 0);
  if (r.i !== bytes.length) throw new OtsError("trailing bytes after the proof");
  return { fileDigest, tree };
}

function readTimestamp(r, depth) {
  if (depth > MAX_DEPTH) throw new OtsError("proof too deep");
  const node = { attestations: [], ops: [] };
  const item = tag => {
    if (tag === 0x00) {
      const kind = toHex(r.bytes(8));
      const payload = new Reader(r.varbytes());
      if (kind === BITCOIN) node.attestations.push({ kind: "bitcoin", height: payload.varuint() });
      else if (kind === PENDING) node.attestations.push({ kind: "pending", uri: new TextDecoder().decode(payload.varbytes()) });
      else node.attestations.push({ kind: "unknown", tag: kind });
      return;
    }
    let op, arg = null;
    if (tag === 0xf0) op = "append";
    else if (tag === 0xf1) op = "prepend";
    else if (tag === 0x08) op = "sha256";
    else if (tag === 0x02) op = "sha1";
    else if (tag === 0x03) op = "ripemd160";
    else if (tag === 0x67) op = "keccak256";
    else throw new OtsError(`unknown operation 0x${tag.toString(16)}`);
    if (op === "append" || op === "prepend") { arg = r.varbytes(4096); if (arg.length === 0) throw new OtsError("empty operand"); }
    node.ops.push({ op, arg, child: readTimestamp(r, depth + 1) });
  };
  let tag = r.byte();
  while (tag === 0xff) { item(r.byte()); tag = r.byte(); }
  item(tag);
  return node;
}

async function apply(op, arg, msg) {
  if (op === "append") return concat(msg, arg);
  if (op === "prepend") return concat(arg, msg);
  if (op === "sha256") return digest("SHA-256", msg);
  if (op === "sha1") return digest("SHA-1", msg);
  return null; // ripemd160 and keccak256: path not followed
}

// Every attestation reachable from the initial digest, with the message committed at it.
export async function attestations(tree, initial) {
  const out = [];
  const walk = async (node, msg) => {
    for (const a of node.attestations) out.push({ ...a, msg });
    for (const { op, arg, child } of node.ops) {
      if (msg.length > 4096) continue;
      const next = await apply(op, arg, msg);
      if (next) await walk(child, next);
    }
  };
  await walk(tree, initial);
  return out;
}

// Checks one .ots against an expected digest. getHeader(height) resolves to { merkleRoot (display hex),
// time (unix seconds) } or throws. Returns { status: "verified" | "pending" | "failed", height, time, notes }.
export async function verifyOts(bytes, expectedDigest, getHeader) {
  let parsed;
  try { parsed = parseOts(bytes); } catch (e) { return { status: "failed", notes: [e.message] }; }
  if (toHex(parsed.fileDigest) !== toHex(expectedDigest)) return { status: "failed", notes: ["proof is for another digest"] };
  const atts = await attestations(parsed.tree, parsed.fileDigest);
  let best = null;
  const notes = [];
  let pending = false;
  for (const a of atts) {
    if (a.kind === "pending") { pending = true; continue; }
    if (a.kind !== "bitcoin") continue;
    if (a.msg.length !== 32) { notes.push(`attestation at block ${a.height} commits to a non-digest`); continue; }
    let header;
    try { header = await getHeader(a.height); } catch (e) { notes.push(`block ${a.height}: header unavailable (${e.message})`); continue; }
    if (toHex(a.msg.slice().reverse()) !== header.merkleRoot) { notes.push(`block ${a.height}: merkle root does not match`); return { status: "failed", notes }; }
    if (!best || a.height < best.height) best = { height: a.height, time: header.time };
  }
  if (best) return { status: "verified", height: best.height, time: best.time, notes };
  return { status: pending || notes.length ? "pending" : "failed", notes: notes.length ? notes : [pending ? "waiting for Bitcoin" : "no attestation"] };
}

// Block headers from an Esplora-compatible explorer (trusting the explorer for the header; a
// Bitcoin node removes that trust).
export function esploraHeaders(base = "https://blockstream.info/api") {
  const cache = new Map();
  return async height => {
    if (cache.has(height)) return cache.get(height);
    const hash = (await (await fetch(`${base}/block-height/${height}`)).text()).trim();
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error("no block at that height");
    const block = await (await fetch(`${base}/block/${hash}`)).json();
    const header = { merkleRoot: block.merkle_root, time: block.timestamp };
    cache.set(height, header);
    return header;
  };
}
