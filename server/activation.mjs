export const approvalRequirements = [
  ["PROVIDER_BAA_CONFIRMED", "Storage provider"],
  ["HOSTING_APPROVED_FOR_PHI", "Application hosting"],
  ["CLERK_BAA_CONFIRMED", "Identity provider"],
  ["NEON_BAA_CONFIRMED", "Database provider"],
];
export function productionApprovals(env) {
  return approvalRequirements.map(([setting, label]) => ({
    setting,
    label,
    confirmed: env[setting] === "true",
  }));
}
export function productionAuthorized(env) {
  return productionApprovals(env).every((item) => item.confirmed);
}

// Practice endpoint onboarding is reviewed separately from the cloud portal.
export function readinessScopes(gates) {
  const onboardingKeys = new Set(["pilot", "endpoint"]);
  const portalGates = Object.fromEntries(
    Object.entries(gates).filter(([key]) => !onboardingKeys.has(key)),
  );
  return {
    portalReady: Object.values(portalGates).every(Boolean),
    portalGates,
    practiceOnboarding: {
      ready: gates.pilot === true && gates.endpoint === true,
      gates: { pilot: gates.pilot === true, endpoint: gates.endpoint === true },
    },
  };
}
