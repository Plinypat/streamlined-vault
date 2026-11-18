# Streamlined Vault

A branded MSP client portal for cloud file storage. Product name: Streamlined Vault. Intended domain: portal.streamlinedvault.com (not purchased or configured by this project).

## What is implemented

- Responsive sign-in, practice dashboard, searchable file browser and folder grouping.
- MSP-created practice workspaces with decimal 4 TB quotas, memberships and viewer/editor/uploader/admin roles.
- OIDC authorization-code sign-in with PKCE, nonce and state checks, verified email, required MFA assurance, server-side 15-minute sessions, same-origin CSRF protection and HttpOnly cookies.
- A real server-side Backblaze B2 S3-compatible adapter: multipart creation, upload, completion, abort, HEAD verification, range downloads and encrypted writes.
- SHA-256 checking of incoming upload parts, 16 MiB parts, per-part retries and browser-session pause/resume. Current maximum single file: 160,000 MiB (10,000 parts). Browser reselection after a page refresh is not implemented; the scheduled uploader supports restart/resume.
- Recoverable trash and restore. Trash continues to count toward quota. No permanent purge, remote wipes or retention destruction is implemented.
- Capacity alerts (in-app), object-size inventory checks and stale-upload cleanup on hourly/daily/weekly schedules. The backend must remain running. Inventory checks do not replace content integrity scans or recovery drills.
- Expiring, hashed, practice-scoped upload-only or read-only tokens with revocation. Token creation is admin only; upload tokens cannot list or download existing files.
- A branded Python uploader for scheduled local-folder uploads, no direct provider account or key required by the practice.
- Tenant-scoped audit events and export. A hash chain helps detect some alterations, but it is not immutable or independently anchored. Production audit archival is an outstanding deployment task.

This is an implementation candidate, not a HIPAA compliance certification or a production deployment. No live B2 credentials have been supplied or used. B2 integration and OIDC MFA must be acceptance-tested with the chosen live services before release. The hosted Sites version is a synthetic browser demo; it does not run this Node backend.

## Start locally with synthetic files

Node.js 24+ is required (uses built-in SQLite).

```powershell
npm ci
Copy-Item .env.example .env
npm start
```

Open http://127.0.0.1:4173. In local test mode, files are stored on the development machine and metadata in `data/portal.sqlite`. The app binds only to loopback. It refuses to start demo mode with NODE_ENV=production. Never use patient data in demo mode. `npm test` exercises the backend with isolated temporary local storage.

For a static browser-only preview, serve `dist/`. The app visibly enters preview mode and keeps selected synthetic files in browser memory only (100 MB per-file preview limit). Refresh removes these changes.

## Production setup

1. Register the domain in the business owner's registrar account, protect it with MFA, and confirm annual renewal pricing. The registry returned no record for streamlinedvault.com on November 17, 2026, but availability and final price remain subject to registrar checkout. Nothing has been purchased.
2. Establish the necessary business-associate agreements between the practice and MSP, and with storage, hosting, identity and any other applicable subprocessors. The user confirmed having a B2 account, not an executed BAA. Confirm eligibility for the MSP/subcontractor arrangement directly with the provider. White labeling does not remove contractual/subprocessor disclosure obligations.
3. Deploy the Node service in an approved hosting environment. An AWS EC2 Linux instance on encrypted EBS behind a TLS reverse proxy is one possible starting deployment; use an AWS BAA and review the whole architecture. No physical hardware needs to be bought by you or your practices. TLS terminates at the proxy. Keep the app port on loopback/private networking. Enforce request-size and connection limits at the proxy, no body buffering to unencrypted disk, and no file-name/query logging. The backend handles file content, so its hosting belongs in the PHI boundary. Plan for proxy bandwidth, upload duration, egress, monitoring and capacity.
4. Create a private B2 bucket in the intended region, confirm encryption for newly uploaded objects, and generate a non-master bucket-restricted application key with only necessary list/read/write capabilities. The portal uses opaque object IDs (`tenants/<workspace-id>/objects/<file-id>`), never patient names as storage object keys. Human-readable file and folder names are in the metadata database and can contain PHI; protect the database accordingly. The current adapter uses one restricted bucket and application-enforced tenant prefixes. Separate buckets/credentials per practice can be added for stronger provider-side isolation; do not describe the present implementation as separate provider accounts.
5. Put secrets in a protected server environment or secret manager. Fill in STORAGE_ENDPOINT, STORAGE_REGION, STORAGE_BUCKET, STORAGE_KEY_ID and STORAGE_APPLICATION_KEY from your own account. Never enter provider secrets into the client portal, JavaScript bundle, chat, source control, or a domain registrar.
6. Configure an OIDC identity provider with exact redirect `https://portal.streamlinedvault.com/auth/callback`, verified email and mandatory MFA. Provide OIDC_ISSUER, OIDC_CLIENT_ID and optional client secret. The current implementation requires the provider to supply a verified `amr` claim matching OIDC_MFA_AMR; acceptance-test this before release. Not all providers emit this claim identically. Do not bypass the check if sign-in fails; adapt the assurance check to documented IdP policy/claims and test it. Keep the issuer fixed to an administrator-controlled trusted provider. Authentication enrollments/password recovery are delegated to that provider, not recreated here.
7. Set MSP_ADMINS to verified administrator email addresses. Create practices, then assign members. Adding a member grants an existing verified identity access; it does not send an email or provision an IdP account. Configure IdP invitations/enrollment separately. MSP admins can access all practices; ordinary members are checked for current membership on every request. Arrange explicit MSP support-access policy and access reviews.
8. Set APP_ORIGIN to the HTTPS origin, NODE_ENV=production and DEMO_MODE=false. Set PROVIDER_BAA_CONFIRMED and HOSTING_APPROVED_FOR_PHI only after the reviews they represent are complete. These are operator activation switches, not automated compliance assessments.
9. Store the SQLite database, WAL and metadata on encrypted persistent disk with strict OS permissions. Back them up consistently; the database holds the mapping from opaque cloud objects to practice ownership and filenames. Test restoring both metadata and objects. Do not run multiple portal replicas against a shared SQLite file. A managed database and a durable queue/worker are needed for horizontal scaling; the present scheduler is a single-process implementation.
10. Complete security and live acceptance testing described below before admitting PHI. Disable/suppress PHI in analytics, crash reporting, logs and email. Define retention, incident response, token rotation, user termination and availability/recovery targets. No browser analytics or third-party fonts are included.

## White-label boundary

Clients see only Streamlined Vault product text and your portal origin for API calls, uploads and downloads. Long-lived provider secrets, storage bucket names, upstream upload URLs and raw provider errors remain on the server. Downloads stream as attachments and are not rendered as diagnostic images. No medical image viewer is included.

Traffic is proxied through your backend to avoid exposing provider endpoints in browser network requests. This is not a promise that a vendor can never be inferred through network analysis or server incidents. Required legal, contractual and subprocessor disclosures must remain accurate. Do not use a direct-to-provider signed upload URL if hiding its hostname is a requirement.

## Automations without provider branding

The portal offers scheduled capacity checks, size inventories and abandoned multipart cleanup. They run every 30 seconds when due; alerts stay in the in-app notification center. Email, webhooks, calendar integrations, file mirroring and arbitrary scripts are not implemented.

For upload automation, create an upload-only token in Automations. On a practice computer, place the token in a protected file outside the source folder and protect the uploader state directory. The tool has no provider branding, endpoints or application keys. Use Python 3.10+:

```powershell
python tools/vault-uploader.py --portal https://portal.streamlinedvault.com --workspace YOUR_WORKSPACE_ID --source "D:\Imaging Exports" --token-file "C:\ProgramData\StreamlinedVault\token.txt" --state "C:\ProgramData\StreamlinedVault\state.json" --folder Imaging
```

Use Windows Task Scheduler to run that exact command every 15 minutes under a dedicated least-privileged service identity. Set **Do not start a new instance** if already running. Restrict token and state permissions to that identity and administrators, including backups. The agent skips files modified within the last two minutes, detects changes during transfer, resumes uploaded parts using its state file, does not follow symlinks outside the source, and never deletes local or cloud files. Changed files become separate stored objects; they consume additional quota. It is one-way upload, not a bidirectional sync or a database-consistent backup agent. The client computer must be online; no NAS or owned server hardware is required. Tokens expire within 90 days, so arrange rotation and failure monitoring.

## Important operating limits

- Browser pause/resume works within the current page session. Agent resume persists across runs using the protected state file. Background transfers cannot continue after the browser closes.
- Completion interrupted after the provider accepted the file may require administrator reconciliation if metadata is left in `finishing`. Do not simply discard the reservation; verify the object and its size/version and record the reconciliation. Production reconciliation tooling is a remaining task.
- Multipart reservations and trash count toward the logical 4 TB quota. The meter does not represent the entire provider bill. Orphaned objects, provider versions, delayed cleanup, logs and metadata need separate billing reconciliation. Do not make unbounded retention promises from this meter.
- Existing files uploaded outside the portal are not automatically imported. Use a reviewed import/migration job to assign ownership and metadata; never expose a global bucket listing to clients.
- Object Lock, legal holds, automatic permanent purge, external sharing links, provider account creation and provider credential rotation UI are deliberately outside this release. They need policy and provider-integration work before exposure. This is a client file portal, not a clone of every provider administration API.
- Rate limits are per application instance. Set an additional edge/IP limit at production ingress. A single in-memory scheduler and SQLite process are suitable for a bounded pilot, not multi-region HA.

## Acceptance checklist and evidence

Automated local tests cover: unauthenticated denial; CSRF/origin checks; practice boundaries; MSP-only provisioning; part checksum and size validation; byte-identical downloads and range requests; trash recovery; quota reservations and release; upload-token scope and revocation; and automation results. These use the local adapter, not live B2.

Before live release, test with synthetic files in the real private bucket: login/MFA and denied memberships; 1-byte, multipart, interrupted and representative very large files; resume/retry behavior; maximum file limits; end-to-end checksums on downloaded files; no upstream hostname/secrets in browser responses; storage quota concurrency; expired/revoked users and tokens; recovery of database and cloud objects; alert monitoring; and restart/failed completion reconciliation. Conduct an independent security assessment and address findings. Configure off-host immutable audit export/retention and monitor scheduler failures before launch. Complete customer agreements, support/runbooks and documented risk analysis. The virtual-desktop idea remains excluded.

## Primary references checked November 17, 2026

- https://www.backblaze.com/apidocs/introduction-to-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-s3-compatible-app-keys
- https://www.backblaze.com/docs/cloud-storage-application-keys
- https://www.backblaze.com/cloud-storage/compliance
- https://help.backblaze.com/hc/en-us/articles/217667238-Backblaze-and-HIPAA
- https://www.backblaze.com/docs/cloud-storage-object-lock
- https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html

No provider references or credentials are included in the client-facing `dist/` assets. Technical provider references here are for the MSP operator's setup and accurate disclosures.
