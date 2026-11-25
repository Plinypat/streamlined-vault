export function recoveryRequestAllowed(path, method) {
  if (["GET", "HEAD"].includes(method)) {
    if (["/health", "/api/config", "/api/me", "/api/msp/security", "/internal/security-status"].includes(path)) return true;
    return !["/api/", "/internal/", "/auth/"].some(prefix => path.startsWith(prefix));
  }
  return method === "POST" && ["/auth/complete", "/api/logout"].includes(path);
}
export function uploadPrincipal(user) {
  return user.agent ? "token:" + user.tokenId : user.clerkId ? "clerk:" + user.clerkId : "email:" + user.email;
}
export function canManageUpload(user, access, file) {
  return access.role !== "uploader" || file.upload_actor === uploadPrincipal(user);
}
export function createRateLimiter({limit=1800, maxKeys=4096, windowMs=60000, clock=Date.now}={}) {
  const entries = new Map();
  let nextSweep = 0;
  return {
    allow(key) {
      const at = clock();
      if (at >= nextSweep) {
        for (const [ip, entry] of entries) if (entry.until <= at) entries.delete(ip);
        nextSweep = at + windowMs;
      }
      let entry = entries.get(key);
      if (!entry || entry.until <= at) {
        if (!entry && entries.size >= maxKeys) return false;
        entry = {n:0,until:at+windowMs}; entries.set(key,entry);
      }
      return ++entry.n <= limit;
    },
    size: () => entries.size,
  };
}
