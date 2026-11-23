import { test } from "node:test";
import assert from "node:assert/strict";
import { readinessScopes, productionAuthorized } from "../server/activation.mjs";

test("practice onboarding remains pending without blocking cloud portal readiness", () => {
  const gates = { database: true, mfa: true, monitoring: true, pilot: false, endpoint: false };
  const scopes = readinessScopes(gates);
  assert.equal(scopes.portalReady, true);
  assert.equal(scopes.practiceOnboarding.ready, false);
  assert.equal(gates.pilot, false);
  for (const gate of ["database", "mfa", "monitoring"]) {
    assert.equal(readinessScopes({ ...gates, [gate]: false }).portalReady, false);
  }
  assert.equal(productionAuthorized({}), false);
});
