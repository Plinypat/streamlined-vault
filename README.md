# Streamlined Vault

A branded MSP portal for practice file storage, plus a scheduled Windows uploader. Files live in cloud object storage; practices use existing computers, with no additional NAS or owned server required.

## Current delivery: uploader pilot (v0.3)

- Portal: practice workspaces, 4 TB logical quotas, roles, file browsing, multipart uploads/downloads, trash/restore and activity history.
- **Uploaders**, replacing the earlier cloud-automation UI: one-time 15-minute enrollment, upload-only device identity, pause, revoke, schedule editing, run-on-next-contact and run history.
- Scheduled agent: every 15 minutes, hourly, every four hours, or selected days at a local time. The practice computer's clock controls the schedule. It must be awake and online.
- One-way upload of new/changed files, retry/resume, unchanged-file skipping and single-instance locking. No source or cloud deletion. Changed files consume additional storage as separate objects.
- Locally selected sources; cloud settings cannot choose new workstation folders or execute commands. Telemetry carries counts/status, not source paths.
- Windows pilot installer uses Task Scheduler, a protected SYSTEM task and machine-encrypted DPAPI credentials. It requires PowerShell 7 and Python 3.10+ installed machine-wide under Program Files. It is an inspectable script, **not a signed executable installer**.
- Backblaze B2 adapter stays server-side; provider credentials and raw provider URLs are not sent to client code. Live credentials have not been configured or tested.

The implementation plan and remaining production gates are in [docs/IMPLEMENTATION-PLAN.md](docs/IMPLEMENTATION-PLAN.md). This repository is not evidence of HIPAA compliance. The hosted Sites publication is a synthetic frontend preview, not the live Node backend.

## Local synthetic-data development

Node.js 24+, Python 3.10+ and PowerShell 7 for installer parsing on Windows:

```powershell
npm ci
Copy-Item .env.example .env
npm start
```

Visit http://127.0.0.1:4173. Local test mode binds to loopback and stores synthetic files in `data/`; it refuses production mode. Static hosting of `dist/` instead gives an in-memory browser demo (100 MB per synthetic file, resets on refresh). Never enter patient data or real credentials into preview mode.

```powershell
npm run check
npm test
python -m unittest discover -s agent/tests -v
```

Tests cover access/tenant isolation, CSRF, quotas, multipart integrity, downloads, trash recovery, device enrollment/replay/renewal, revocation/pause, schedules, OS locking and Windows DPAPI. The synthetic end-to-end test enrolls an agent, uploads real bytes through the local API, reports results, and skips the unchanged file on a subsequent run. Live B2, full Clerk browser enrollment/recovery, actual installation under SYSTEM, signed distribution and live large-file performance have not been acceptance-tested.

## Pilot uploader installation

Use a separate synthetic-data pilot machine. First deploy the backend on an approved HTTPS origin, enroll a practice in the portal, then create an uploader with the desired schedule. The portal displays a one-use credential valid for 15 minutes.

From an elevated **PowerShell 7** terminal in this source package:

```powershell
./agent/Install-Uploader.ps1 -Portal https://portal.streamlinedvault.com -Source 'D:\Imaging Exports' -PythonPath 'C:\Program Files\Python312\python.exe'
```

The installer prompts for the enrollment credential; it is never placed in command-line arguments. It locks program/state folders to SYSTEM and Administrators, encrypts the returned device token using Windows DPAPI, and registers `Streamlined Vault Uploader` to start with Windows. It does not download Python or other software. Verify the official machine-wide Python installation and folder permissions before running. Source folders must be local absolute paths readable by SYSTEM; mapped drives and network shares need a separately designed service account. Do not select a parent folder containing uploader program files or its configuration.

Verify the device's first contact, upload counts and downloaded file integrity in the portal. Pause takes effect between file parts; revocation is checked on API calls. The dashboard's Run on next contact command is not immediate execution on an offline computer. The token expires after 90 days; plan re-enrollment before expiry. A revoked credential cannot be restored; create a new device enrollment.

The agent and metadata live under Program Files/ProgramData with restricted ACLs. Do not relocate credentials into source folders. Source folders are changed locally under administrator control. Do not run two enrolled agents with the same state directory. Don't edit metadata or delete resume state to force retries: investigate failed/finishing uploads first.

To stop the pilot, stop and unregister its scheduled task and revoke the device in the portal. Keep any needed state for incident/recovery analysis. This does not delete locally stored or cloud files. Replacement/update procedures must preserve the machine's encrypted secret and local resume state. Automatic executable updates are not implemented; production rollout needs code signing, verified releases, rollback and a tested installer/update process.

## Production services and boundaries

- **Neon Postgres** is required in live mode through DATABASE_URL, with verified TLS and pooled transactional connections. Versioned migrations run once under a database lock; existing local SQLite records are never silently imported. See docs/NEON-MIGRATION.md for import, backup and rollout requirements. Neon requires the appropriate plan, BAA and HIPAA project settings before PHI.
- **Clerk** is the identity provider. The existing development application is linked, with mandatory authenticator MFA and backup codes. Server verification checks signed tokens, recent MFA, active sessions, verified email and application-owned membership. See docs/CLERK-SETUP.md for boundaries and remaining acceptance checks.
- **B2** stores file objects, and private server credentials are configured only through protected environment variables/secret management. No API key should be pasted into chat or stored in Git. Validate MSP/subcontractor BAA terms directly with the provider.
- **Hosting** is still undecided pending cost/transfer design review. AWS can host the pilot without physical hardware. A proxy handles file bytes, so its hosting falls inside the PHI boundary and its outbound transfer charges matter. Approved provider-branded endpoints may reduce proxy costs but are not configured here.
- Domain registration/DNS ownership has not been verified by this application. Intended domain: portal.streamlinedvault.com.
- New workspaces support dedicated private buckets with encrypted, bucket-restricted credentials. MSP setup can create a bucket or connect an existing one. Existing workspaces/files keep their shared-bucket location. See docs/DEDICATED-STORAGE.md. Dedicated provisioning on Vercel is enabled only with migrated Postgres metadata and configured encryption/provisioning secrets; this is not a separate provider account per client.
- The metadata database contains sensitive filenames and account records. Protect it on encrypted persistent storage with backups. SQLite remains a local synthetic-data adapter. Postgres backs live metadata; restoring it and the separate credential-encryption key must be tested together.
- Trash and pending reservations count toward logical quota. Provider versions/orphans may add billable usage outside that meter. Full billing reconciliation and provider/metadata restore drills are required.
- Current hash-chained audit records are not immutable or independently anchored. Off-host audit retention/monitoring and tested incident procedures remain production tasks.
- Default multipart part size is 16 MiB, with a maximum of 10,000 parts per file (160,000 MiB). Browser pause/resume lasts for the page session; the uploader persists resume state. Upload completion interrupted after provider acceptance can require administrator reconciliation; don't release quota or discard objects blindly.
- No cloud cron task reads local practice folders. Old cloud capacity/inventory automation routes are removed. A background cleanup timer expires local sessions only. Legacy scoped token endpoints remain for the standalone command-line uploader.
- Legal holds, destructive retention policies, external sharing, database-consistent backups, diagnostic image viewing and practice-software desktops are outside this pilot.

## Operational setup before patient data

Execute applicable BAAs with the practice and all relevant providers, complete risk analysis/access reviews, configure production TLS and secrets, MFA/recovery, database/object backups and restoration, failure/expiry monitoring, immutable audit archival, privacy-safe logging, code signing, support ownership and breach/incident procedures. Test production data isolation and lost/expired devices before go-live. UI branding does not remove required contractual/subprocessor disclosures.

## References

- https://www.backblaze.com/apidocs/introduction-to-the-s3-compatible-api
- https://www.backblaze.com/docs/cloud-storage-application-keys
- https://www.backblaze.com/cloud-storage/compliance
- https://www.backblaze.com/docs/cloud-storage-present-a-branded-s3-endpoint
- https://neon.com/docs/security/hipaa
- https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html
- https://www.hhs.gov/hipaa/for-professionals/special-topics/health-information-technology/cloud-computing/index.html

These operator-only notes identify providers accurately; client-facing `dist/` assets contain no provider references or long-lived secrets.
