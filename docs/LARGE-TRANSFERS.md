# Large-file transfers

The default browser and scheduled-uploader file limit is **50 GiB (53,687,091,200 bytes)**. Each practice keeps its existing 4 decimal TB quota. The server reserves the full declared size before starting a multipart upload; quota checks remain transactional. Cloud transfers use 16 MiB parts, with a smaller final part. Local demo files remain local and use the proxy for synthetic testing.

## Transfer flow

1. An authorized member or enrolled uploader initializes a transfer. The server chooses the workspace's immutable bucket binding, opaque object key and multipart ID. The caller cannot supply a bucket, key, host or multipart ID.
2. The client computes a part's MD5 transfer checksum and requests a five-minute signed PUT link. The signature binds the specific part, upload ID, checksum and content length. A grant cannot be changed to different content. MD5 here detects accidental transfer errors; it is not a password or authenticity mechanism. HTTPS and signed authorization protect transport.
3. The client uploads directly without portal cookies or its bearer token, then acknowledges the part. The server lists the provider's stored part and verifies its number and size. Repeated acknowledgment does not double-count usage.
4. Completion compares all provider part numbers, sizes and ETags with acknowledged metadata, then completes the multipart upload and verifies the stored object's size. An interrupted completion retains the reservation for reconciliation. Cancellation aborts the upload before releasing quota.

Downloads are authorized by the portal and use a signed GET link valid for 60 seconds, so file bodies bypass Vercel's response-size limit. The full file counts against the monthly allowance when the link is issued, even if unused. Links can be reused until expiry, and a transfer started before expiry may continue. Hard limits govern new link issuance; this is not exact egress enforcement or billing. Actual storage traffic must be reconciled with the provider. Upload links remain usable for up to five minutes after membership/device revocation; download links for up to one minute. Aborting a multipart upload invalidates its outstanding part links.

## Browser origin and branding

Browser initialization configures one CORS rule for the exact APP_ORIGIN using the existing provisioning credential. An MSP can also use Workspace settings → Configure browser transfers. Existing unrelated CORS rules are retained; the bucket stays private and default encryption is checked. No wildcard origin, public ACL or account credential is sent to a client. The provisioning key must have its existing documented bucket-management permissions. If authorization or origin configuration fails, browser setup fails with an actionable error rather than silently using an oversized Vercel request.

The dashboard remains branded. Signed URLs necessarily reveal the storage hostname and scoped signing key ID to network tools. They are temporary bearer capabilities, not long-lived application secrets. Never log, email or persist them. URLs are not saved in uploader state. Fully concealing the provider hostname requires a separate branded transfer gateway with its own hosting and transfer costs; this release does not provision one.

## Existing uploader installations

New installations copy the updated tools/vault-uploader.py. Existing installed agents must update their installed vault_transfer.py to this release under MSP control; the old uploader sends oversized parts through the proxy. Stop the scheduled task, back up its protected configuration/state, replace only the transfer module from the verified release, retain ACLs and machine-protected credentials, then restart and validate a synthetic transfer. Do not rerun enrollment or discard resume state to update code. There is no silent updater or signed executable release yet.

## Acceptance and deployment

No new environment secrets are required. Migration 003 adds upload_part_grants and preserves existing files/bindings. A failed migration prevents startup. Existing encryption keys must stay unchanged.

Automated coverage uses a synthetic HTTP S3 fixture to transfer and download 33 MiB with actual signed URLs, validates checksum rejection, authoritative part acknowledgment, immutable grants, duplicate acknowledgments, changed-part rejection, size verification and download authorization limits. This is not a real Backblaze acceptance test. Existing API tests continue to cover identity, tenant isolation, quotas and scheduled uploads.

Before patient files, verify the real production origin/CORS and credentials with a synthetic file over 4 MiB, then representative imaging files and a file near the configured cap. Test pause/resume, expired links, interrupted network/completion, revoked devices, quota exhaustion, range/restore behavior and provider/metadata reconciliation. The configured 50 GiB ceiling does not establish tested throughput or completion duration on a practice connection. BAA/review, backup/restore and other readiness gates remain unchanged.

References: [Vercel payload limits](https://vercel.com/docs/functions/limitations), [upload part](https://www.backblaze.com/apidocs/s3-upload-part), [list parts](https://www.backblaze.com/apidocs/s3-list-parts), [CORS](https://www.backblaze.com/docs/cloud-storage-enable-cors-with-the-s3-compatible-api).
