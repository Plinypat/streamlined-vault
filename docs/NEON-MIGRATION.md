# Neon metadata rollout

Live mode requires DATABASE_URL and uses Postgres for all portal metadata. It never falls back to local SQLite. Local DEMO_MODE=true continues to use SQLite unless the isolated test harness explicitly selects Postgres. Neon Auth is not used; Clerk remains the identity provider.

## Schema and startup

The application uses the dedicated streamlined_vault schema. server/migrations/001-metadata.sql defines practices, memberships, Clerk identity bindings, sessions, file/upload metadata, parts, tokens, devices, enrollment, run summaries, audit records, notices, dedicated bucket assignments and setup requests. Migration 002 adds private MSP workspace ownership, draft/published service plans, portal transfer events and resumable provider inventory. Existing workspaces default to client workspaces and keep their bucket bindings. Migration versions are recorded in schema_migrations. Startup reads the version; a missing version triggers one transactional migration under an advisory lock. Concurrent cold starts do not run conflicting DDL. A failed migration rolls back and the server does not start. Health returns metadata: postgres only after a live database query succeeds.

DATABASE_URL should use Neon's pooled endpoint. The pg driver enforces certificate verification, channel binding, bounded pools and idle/connection timeouts. Production connection-string flags cannot turn off TLS verification. Plaintext connections are permitted only by the synthetic test harness against loopback. Never put DATABASE_URL in browser variables, source control, build artifacts or logs.

A migration-role connection may be supplied as DATABASE_MIGRATION_URL when running npm run db:migrate separately. Deploy a runtime role restricted to the application's schema after applying migrations with an owner/migration role; normal startup skips DDL once the version exists. Keep the migration credential outside the deployed runtime when using separate roles. No database role or paid Neon plan is created/upgraded by this code.

## Existing SQLite records

No existing records are silently copied, merged or deleted. For a new pilot, the schema starts empty and the MSP signs in again. Existing transient Vercel SQLite state cannot be recovered merely by configuring DATABASE_URL. If there were real workspaces, pause writes and export/recover their consistent SQLite backup before cutover. Preserve the original shared object-store configuration and the exact STORAGE_CREDENTIAL_ENCRYPTION_KEY separately. File objects are not moved by a metadata import.

An explicit import tool is available:

    node --env-file=.env tools/import-sqlite-metadata.mjs --source <consistent-backup.sqlite> --confirm-empty-target

Use a protected local environment or migration runner containing the target DATABASE_URL or DATABASE_MIGRATION_URL. The source is opened read-only. The tool requires an empty target, copies whitelisted tables in foreign-key order in one transaction, preserves credential ciphertext and audit order, and rejects a repeat/merge import. Human sessions are not imported; everyone signs in again. Verify practice IDs, bucket assignments, counts, quotas, file downloads, tokens, devices and the audit chain before enabling writes. Do not import demo/local file metadata into a real cloud workspace. Existing object keys are unchanged and must actually exist in the original storage account.

## Transaction boundaries

All queries in a transaction retain one checked-out Postgres connection using AsyncLocalStorage. Quota reservations and storage assignment changes serialize per workspace. Each file records its immutable storage assignment at initialization. Multipart writes serialize per file; completion claims commit before the provider call so interrupted completion remains visible for reconciliation. Cancellation continues counting toward quota until confirmed. Provider completion/abort failures are never treated as verified storage deletion or successful completion.

One-time enrollment and device changes serialize per device. Identity binding, provisioning request IDs and the global audit chain have separate transaction locks. Native bucket provisioning uses a durable five-minute ownership lease instead of a process-local lock. A stale worker cannot overwrite a newer setup attempt. Bucket/key operations remain external side effects: interrupted provisioning may leave an unused key or empty bucket requiring manual reconciliation.

## Validation performed

The security/uploader API suite runs against local SQLite and real local Postgres. Postgres tests start a second server against the same database, retain sessions and bucket bindings through a server restart, race 32 large quota reservations without exceeding 4 TB, race enrollment claims, preserve device commands, validate the audit chain, verify rollback, test a cross-instance provisioning lease and decrypt persisted bucket credentials after adapter recreation. The offline importer was tested with a synthetic backup and a non-empty target rejection. No patient files or real provider buckets are used in these tests.

GitHub CI has an isolated Postgres service using only synthetic test credentials. To run locally, provide TEST_POSTGRES_URL for a loopback-only database named sv_test, then npm run test:postgres. That test database's streamlined_vault schema is reset; production URLs are explicitly rejected by the test harness.

## Before patient data

NEON_BAA_CONFIRMED is an operator review flag, not a purchased agreement or a substitute for compliance configuration. Storage remains gated unless Neon, storage, identity and hosting review flags are all satisfied. Confirm the applicable provider plans/agreements, least-privilege roles, retention, encryption and access controls independently. Set up database point-in-time recovery/backups and protected off-provider exports as appropriate; no backup policy is provisioned automatically.

Before go-live, restore a backup into an isolated Neon project/branch, supply the separately backed-up encryption key, verify practice/bucket bindings and synthetic downloads, and test device revocation and audit history. Do not restore production secrets or PHI into ordinary public previews. Production monitoring, provider round-trip tests, large-file hosting acceptance, disaster recovery and contractual review remain separate rollout requirements.
