# Dedicated workspace storage

New workspace setup supports creating a private encrypted bucket or connecting an existing private bucket. Each workspace has one immutable storage binding. Browsers and Windows uploaders continue using the same branded API; the server chooses the bucket and credential from its workspace/file record. Client-supplied bucket, endpoint and storage-location overrides are never used for file transfers.

## Deployment prerequisite

Live mode now requires migrated Postgres metadata through DATABASE_URL. SQLite is retained only for local synthetic testing. Dedicated provisioning on Vercel is available when Postgres metadata and the server secrets are configured; no temporary filesystem is used for live records. The metadata migration is versioned and guarded by a database lock. Existing SQLite backups require explicit offline import; see NEON-MIGRATION.md. Live B2 provisioning and actual provider round trips still require synthetic acceptance testing before practice rollout.

## Server configuration

- STORAGE_CREDENTIAL_ENCRYPTION_KEY: 32 random bytes encoded as base64. Generate in a trusted terminal/secret manager, not chat. Store as a Production Secret. Retain the same value across restarts/deployments and back it up separately from metadata. Losing it loses access to encrypted bucket credentials; rotation requires a designed re-encryption procedure.
- STORAGE_PROVISIONING_KEY_ID and STORAGE_PROVISIONING_APPLICATION_KEY: optional server-only account-level application credential for automatic bucket/key creation. Do not use the account master key. Required capabilities: listBuckets, readBuckets, writeBuckets, writeBucketEncryption, readBucketEncryption, writeKeys, listFiles, readFiles, writeFiles, deleteFiles. It must not have bucket or file-prefix restrictions, because newly created buckets do not exist yet. Do not grant deleteBuckets, deleteKeys, bypassGovernance or retention-management capabilities. File transfers never use this credential.
- Existing STORAGE_* variables remain solely for original shared-bucket files/workspaces. Keep them until a separately verified migration is completed.

Connecting a manually created bucket needs only the encryption key on a supported persistent host. Enter that bucket's application key in the MSP-only HTTPS form. The key must be restricted to exactly one bucket, with no file-prefix restriction; include listBuckets, readBuckets, readBucketEncryption, listFiles, readFiles, writeFiles and deleteFiles. The server verifies account endpoint, restriction, permissions, bucket privacy and default SSE-B2/AES256 encryption before activation. The credential is AES-256-GCM encrypted with workspace-bound authenticated data. Key ID and secret are not returned after setup and are not written to the audit trail.

## Behavior and recovery

Creation uses an opaque sv-<workspace UUID> bucket name and an opaque ownership marker, never a practice/patient name. Automatic creation issues a new single-bucket file credential. Creating a workspace is idempotent with its setup request ID. Partial failures leave a visible storage-error state, block transfers and provide Resume storage setup for the same bucket. A bucket cannot be assigned to two workspaces or reused from the original shared configuration. Dedicated bindings cannot be replaced, and a workspace with any indexed files cannot switch buckets. No file migration is performed implicitly.

If provider acceptance succeeds but the network/database fails, an empty bucket or unused key may remain. Retrying reuses the owned bucket, but can create a replacement file key. Reconcile unused credentials manually through the provider; no automatic bucket/key deletion is performed. Provider failures and database loss must be investigated rather than blindly retried with different buckets.

Original files have a null storage binding and continue using the original shared bucket/key. New files store their workspace storage binding when initialized; upload parts, completion, verification, cancellation, download and restore do not change that location. Trash restore changes metadata only. Connecting an existing bucket does not import arbitrary files already in it.

The 4 TB allowance remains a portal logical quota, including trash and unfinished reservations; it is not a provider capacity reservation or billing reconciliation. Per-bucket version/orphan costs and provider account bucket limits require operational monitoring. BAAs, durable metadata, secret backups, restoration testing and the other production readiness controls remain required before patient data.

## Validation

Automated checks cover native API request shape, private/encrypted bucket verification, restrictive credentials, encrypted credential persistence, wrong-workspace decryption denial, endpoint validation, duplicate bucket assignment, failure/retry handling, legacy routing, API permissions, idempotent creation, and synthetic uploader byte integrity. Provider tests use injected HTTP responses; no real provider buckets or credentials are created by the test suite.

References:
- https://www.backblaze.com/apidocs/b2-authorize-account
- https://www.backblaze.com/apidocs/b2-create-bucket
- https://www.backblaze.com/apidocs/b2-create-key
- https://www.backblaze.com/apidocs/b2-list-buckets
