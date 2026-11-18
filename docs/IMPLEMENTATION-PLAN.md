# Streamlined Vault delivery plan

## Agreed product

An MSP-managed, branded file portal with a 4 TB allowance per practice, backed by B2. Its automation feature is **Streamlined Vault Uploader**, which runs on a practice's existing Windows computer and sends new/changed files on a schedule. No NAS or owned server is required. The uploader is one-way, never deletes source files, and never propagates deletions to cloud storage. No cloud cron is required to initiate workstation uploads. The future virtual desktop remains out of scope.

## Delivery stages and acceptance criteria

1. **Foundation**: repository already connected. Business confirms domain ownership and DNS. Keep production secrets out of Git and use synthetic data in all previews.
2. **Uploader pilot (current implementation stage)**: one-time expiring enrollment; upload-only device credential; interval or selected-day local-time schedule; per-device pause/revoke; status and run history in dashboard; resumable transfer; no duplicate concurrent runs. The MSP installs an inspectable Windows Task Scheduler background agent on a synthetic-data test machine. Pass isolation, enrollment replay, revocation, retry and schedule tests. An executable installer with signing is a subsequent release task; a PowerShell pilot installer is not a signed commercial installer.
3. **Neon**: configure a project with the appropriate HIPAA settings and BAA before PHI. Migrate SQLite metadata, sessions, upload reservations, device policies and audit records into Postgres; add migrations, transactional quota checks, pooled connections, restricted roles, backups/restore tests and tenant isolation tests. Keep the local SQLite adapter for offline development. No live connection string is available yet.
4. **Clerk**: development application linked; mandatory authenticator MFA, backup codes and session limits configured. Backend token/session/MFA verification implemented with synthetic tests. Complete browser enrollment, recovery and revocation acceptance tests on the hosted backend before production.
5. **Live B2 and hosting**: configure least-privilege server secrets, private storage, approved production hosting, TLS and branded domain. Request white-label custom endpoint/partner access and the MSP/subcontractor BAA arrangement. Measure proxy bandwidth before choosing a transfer design. Do not send large upload requests through Vercel Functions unchanged. Validate transfer checksums, restart recovery, retention and metadata/object restoration using synthetic data.
6. **Pilot release**: one consenting practice, synthetic first; code-sign packaged agent and establish a signed-release/manual update process before broad rollout. Test device loss, token expiration, Windows reboot, locked files, DST, internet outages, quota exhaustion, database recovery and credential revocation. Define support ownership, failure alerts, audit archival, incident response and applicable BAAs before any patient files are accepted.

## Uploader design

- MSP creates a device for a specific practice and receives a random one-time enrollment credential valid 15 minutes.
- Installer exchanges that credential once over HTTPS and receives an upload-only device token. The server stores only token hashes. Enrollment is transactionally consumed to prevent replay.
- Windows stores the token using DPAPI machine encryption inside a SYSTEM/Administrators-only directory. The scheduled task runs as SYSTEM at startup. Pilot supports local absolute folders; network shares and mapped drives require a separately designed service identity.
- Folder selection is local and explicit. Dashboard policy can change interval/days/time/destination and pause state, but cannot make the agent browse a new local folder or execute remote commands.
- Agent polls for policy/heartbeat and begins uploads according to the **practice computer's local clock**. Manual Run on next contact is cooperative, not a remote shell. The dashboard acknowledges offline devices rather than promising immediate execution.
- Each source keeps a protected resume state. A single-instance OS lock prevents concurrent agent processes. Changed files are uploaded as new stored objects. Pause takes effect between chunks; revocation is enforced at the next API request.
- Report only bounded status, counts and error codes to the dashboard; never send source paths or file contents in heartbeat/run telemetry. Filenames in normal file metadata remain sensitive and are protected accordingly.
- Schedule changes are revisioned. Run commands have increasing sequence IDs to avoid repetition. Finished runs have idempotent UUIDs; failures remain visible. No automatic code download or execution.

## Hosting cost approach

Use a small rented cloud instance for a bounded pilot, a separate managed identity service and Neon metadata. File capacity remains in B2. Start with one instance only if its documented recovery/availability limitations are acceptable for the pilot; it is not a highly available production architecture. Confirm architecture and costs before provisioning paid resources. Major cost variable is large files flowing through a proxy: B2's egress allowance does not waive the hosting provider's outbound transfer fees. Prefer an approved branded direct-transfer path if feasible.

## External setup still needed

- Confirm domain registration/DNS access.
- Neon project and billing/HIPAA configuration; secure server-side connection string.
- AWS account, selected region and approved hosting budget; Clerk production application, verified sender and appropriate BAA.
- Restricted B2 key/bucket and contractual review; provider custom-domain eligibility.
- Code-signing certificate or signing service, release distribution endpoint and a designated pilot Windows machine.

Do not paste credentials into chat. Live activation is separate from local implementation and testing; completed source code is not evidence of HIPAA compliance.
