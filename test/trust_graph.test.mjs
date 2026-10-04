import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { computeTrust } from "../verifier/trust_graph.js";

const cases = JSON.parse(fs.readFileSync(new URL("./trust_graph_cases.json", import.meta.url), "utf8"));
for (const c of cases) {
  test(c.name, () => {
    const r = computeTrust(c);
    assert.deepEqual({ trusted: r.trusted, revoked: r.revoked }, { trusted: c.trusted, revoked: c.revoked });
    if (c.counted) assert.deepEqual(r.counted, c.counted);
  });
}
