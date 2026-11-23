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
