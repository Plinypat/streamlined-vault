# Streamlined Vault security review — November 24, 2026

## Result and scope

Reviewed application authentication/session handling, practice roles and object authorization, upload/download routes, invitations, browser rendering and headers, SQL usage, credential scoping, encrypted backups and restore isolation, scheduled security maintenance, CI configuration, and Windows uploader/installer code. This is a source review with targeted regression tests and limited authorized live checks, not an independent penetration test or a guarantee against compromise. No patient files were used or downloaded during the review.

## Findings fixed

| Finding | Impact and fix |
|---|---|
| Upload-only transfer ownership was not enforced | A practice uploader knowing another transfer ID could inspect its metadata, cancel it, or alter its in-progress contents. New transfers now bind to their initiating Clerk identity or automation token. Upload-only users may manage only that principal's transfers; editors/admins retain practice management permissions. Regression tests cover metadata, cancellation, signing, completion and idempotent upload initialization. |
| Restore isolation did not cover every operational route | Existing guards covered new uploads and downloads but did not uniformly block upload continuation, provisioning, canaries, invitations or scheduled writes. A recovery quarantine now permits only public static/config/health, sign-in/sign-out, and read-only account/security diagnostics. Other operations return 503. Storage canaries also check quarantine directly. |
| Installer relied on environment paths and executable lookup | The packaged installer now obtains protected folders from Windows APIs and uses absolute Windows system-tool paths. The legacy PowerShell installer refuses pre-existing installation/state folders and obtains protected paths from Windows rather than process environment variables. This reduces folder pre-placement and executable-search hijacking exposure during elevated installation. The package was rebuilt without installing it. |
| Unbounded per-process rate-limit state | Peer-address entries are now capped and expired. This does not provide distributed or tenant-wide DDoS protection; the hosting firewall remains a separate control. |
| Malformed JSON produced server errors | JSON endpoints now require object payloads and the appropriate media type for nonempty requests. Invalid shapes receive client errors rather than uncontrolled exceptions and high-severity server-error alerts. |
| Unnecessary session fields in account responses | Responses no longer include internal session hashes or Clerk session/subject binding fields. Automation tokens cannot use human account or logout endpoints. |
| Mutable CI action tags | Checkout, Node and Python actions are pinned to commit hashes resolved from their official repositories. CI now also runs a production dependency advisory check. |

## Verification

- Application suite: 73 passing, one PostgreSQL-only test skipped in that run.
- Separate PostgreSQL integration suite: all 23 passing, including migration from the original schema, ownership boundaries and recovery quarantine.
- Python agent/installer suite: all 11 passing; PowerShell installer parsed successfully.
- npm audit: zero known advisories in the current dependency tree at review time. This is an advisory snapshot, not proof that dependencies are defect-free.
- Known-secret scan: no matches for the four checked current secrets in the 85 tracked files present at the time of scanning. This was not a scan of every historical or third-party credential.
- Live storage scope review: three ready workspaces had private, encrypted, dedicated buckets and restricted credentials. Archive and recovery writers were single-bucket credentials without delete, key-administration or retention-bypass capabilities.
- A pre-migration off-site metadata backup completed. Migration 007 adds upload_actor; the restricted runtime role can access the column. There were no legacy in-progress uploads requiring owner reconciliation at migration time.
- Scheduled maintenance recovered after the earlier transient incident; the observed 06:45 UTC run on November 25 completed with no recorded maintenance failure and passing log integrity.

## Compatibility and remaining limits

Existing completed files retain normal viewer/editor/admin access. Legacy ownerless in-progress uploads cannot be resumed by upload-only users; an administrator must reconcile those rather than guessing their owner. Revoking a membership/device blocks new portal authorizations, but already issued storage URLs can remain usable until their existing expiry (60 seconds for downloads, five minutes for upload parts).

The pilot installer remains unsigned and Sorski's real endpoint/two-night pilot is still deferred. Use the rebuilt installer archive rather than an earlier downloaded copy. Its SHA-256 is 834b718ee82710e192f85d46de578c9558cc3f6dca21da91fc4384cbcd1990b5.

Vercel's firewall configuration could not be inspected: the connector denied access and no authenticated local CLI was available. No firewall rules were changed or claimed verified. OS/container image vulnerability scanning, a full external penetration test, endpoint compromise, provider-account administrative controls, and malware scanning of uploaded content were not established by these checks. Provider/MFA completion records remain administrator attestations, as previously requested.

Future dependency advisories, code changes, provider changes and newly discovered attacks require ongoing review. No security approval or evidence expiry was bypassed to complete this audit.
