# Clerk setup and acceptance

The existing Streamlined Vault development app is app_3MGh55n90qG6tgF2k8BHgQhoHzm. Do not create a replacement application.

The CLI stores local credentials in ignored .env.clerk; npm start loads .env followed by .env.clerk. Never commit either file. DEMO_MODE=true continues to use synthetic demo authentication and local storage. Merely linking Clerk does not enable live authentication in the hosted static preview.

Development policy: authenticator app and backup codes enabled; MFA required for sign-up and sign-in; inactivity timeout 15 minutes; maximum session 8 hours. The reproducible policy is clerk-development-policy.json. Production settings must be separately configured and verified.

The backend verifies Clerk signatures, issuer, authorized frontend origin, completed session status, recent second factor, online active session and verified primary email. Practice membership and MSP privileges remain server-owned. A Clerk account alone grants no practice access. Expired MFA requires verification again; test recovery and reauthentication UX before pilot rollout.

Synthetic SDK tests cover invalid signatures, wrong origin/issuer, missing or stale MFA, pending sessions, revoked sessions and unassigned identities. Browser enrollment, recovery, logout and cross-practice acceptance on the actual hosted backend remain outstanding. Do not describe these tests as a completed live login rollout.

Live mode requires HTTPS, Clerk keys, MSP administrator allowlist and object-storage settings. Before PHI, verify contractual and operational requirements, including Clerk's appropriate BAA and CLERK_BAA_CONFIRMED, hosting approval and storage-provider BAA. Development keys are rejected in NODE_ENV=production.

Neon: a verified TLS connection check succeeded. server/postgres.mjs is a connection utility; the application runtime remains SQLite. Do not assume DATABASE_URL alone migrates metadata or backups. Rotate the database password shared in chat before production use.
