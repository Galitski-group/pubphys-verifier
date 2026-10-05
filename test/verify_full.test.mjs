// The verifier-side policy of verify_full.js that does not need Bitcoin headers.
import { test } from "node:test";
import assert from "node:assert/strict";
import { judgeRevocation } from "../verifier/verify_full.js";

test("an envelope of a revoked key counts only if the envelope hash was anchored before the revocation", () => {
  assert.equal(judgeRevocation(100, 200).platform, "verified");
  assert.equal(judgeRevocation(200, 200).platform, "failed");
  assert.equal(judgeRevocation(300, 200).platform, "failed");
  // No envelope anchor (only the attested hash was stamped early, which needs no key): not checked.
  assert.equal(judgeRevocation(null, 200).platform, "not_checked");
  assert.equal(judgeRevocation(100, null).platform, "not_checked");
});

// Review F27: the JavaScript verifier agrees with the Ruby one on these inputs.
import { decodeJwt, verifyRs256 } from "../verifier/pubphys_protocol.js";
import { verifyFull } from "../verifier/verify_full.js";
const b64u = s => Buffer.from(s).toString("base64url");

test("a byte-order mark in a token is refused, as in Ruby (A12)", () => {
  assert.throws(() => decodeJwt(`${b64u("﻿{\"alg\":\"RS256\",\"kid\":\"k\"}")}.${b64u("{}")}.AA`));
});

test("an RSA modulus with a leading zero byte is counted as OpenSSL counts it (A15)", async () => {
  const n = Buffer.concat([Buffer.from([0x00, 0x7f]), Buffer.alloc(255, 0xff)]); // 2047 bits
  const jwt = `${b64u("{\"alg\":\"RS256\",\"kid\":\"k\",\"typ\":\"JWT\"}")}.${b64u("{}")}.AA`;
  await assert.rejects(verifyRs256(jwt, { kty: "RSA", n: n.toString("base64url"), e: "AQAB" }), /shorter than 2048/);
});

test("a malformed bundle never makes the time step throw (A17)", async () => {
  for (const ots of [{ attested: 5 }, { attested: [5] }, 7, null]) {
    const r = await verifyFull(JSON.stringify({ ots, attested: {}, envelope: {} }), {}, { getHeader: async () => null });
    assert.equal(r.parts.structure, "failed");
  }
});
