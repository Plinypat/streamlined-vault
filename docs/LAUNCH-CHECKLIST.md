# Completion evidence - November 23, 2026

Completed automatically or verified in this session:
- Reproduced the provider inventory failure: file-version listing rejected an unexpected accountId parameter with HTTP 400. Removing only that parameter returned HTTP 200. Added a regression test preserving account parameters on account-level operations.
- Ran a full inventory using the corrected application service and the production database, through the locally authorized provider account. Completed four buckets with aggregate sizes only; no object names were printed.
- Added explicit provider/technical launch states and clearer administrator/client activation messages. Existing file-operation approval guards remain enforced.
- High-severity alert acknowledgment no longer bypasses readiness. Explicit resolution requires a fix-and-test reference; recurrence reopens the incident.
- Prepared an x64 Windows pilot installer with a SHA-256-verified Python 3.14.10 runtime from python.org, one-time enrollment over stdin, Windows-protected credentials, a SYSTEM startup task and synthetic-file checksums. The installer build is a pilot artifact without an Authenticode publisher signature. It is not installed or enrolled on the development computer.

Remaining operator/practice evidence:
- Key custody passed: the actual Bitwarden export decrypted an off-site backup and recovered storage credentials. Operator confirmed MFA and a secured offline copy. Key-custody evidence is recorded; private keys remain outside the runtime.
- Independent monitoring connection passed through a GitHub workflow rerun. Actual missed-heartbeat, explicit failure and both recovery emails reached the business inbox using a disposable check, which was then paused. Maintenance monitoring is 15 minutes plus 15 minutes grace; backups are 60 plus 15. A new unattended GitHub scheduled run remains to be observed before recording full monitoring acceptance.
- Run live Clerk MFA enrollment, recovery and revocation with patrickdenatale@gmail.com; preserve the primary MSP administrator. Test all practice roles and membership removal with synthetic data.
- Confirm the practice computer's encryption, updates, local time and approved export source. Run the installer on Sorski's computer, then validate two actual nightly runs at 21:00 local time plus restore/restart/resume tests.
- Review the user-reported completed provider agreements/account approvals against their actual documents or dashboards. Record each confirmed flag only after that review. Source locations have not yet been supplied.
- Credential review passed: the previously shared database-owner password was rotated and the new owner connection verified. Workspace storage is private, encrypted and restricted to its bucket. Audit and recovery writers cannot delete files, administer keys or bypass retention. Required server secrets are protected Production variables. A scan of 79 tracked files found none of the checked current credentials. This is a scoped review, not proof that every historical third-party secret was scanned.
- Record portal activation only after cloud technical checks and provider approvals pass. Practice endpoint review and the actual pilot are separate onboarding evidence and do not block portal approval. Review evidence expires after 30 days.

See SORSKI-PILOT.md for the on-site workflow. Record real results, not intended results. A completed package build is not a live practice pilot.

The GitHub Actions monitor secret is now working, verified by a successful rerun. Connected Drive searches located client agreement drafts but no matching completed storage/hosting/identity/database provider approval records; those activation flags remain unchanged pending evidence.

After deploying the inventory fix, the inventory fault and historical database-hardening/maintenance alerts were resolved with fix/test references and fresh live restricted-role, certificate-verified transport, scheduled-maintenance and protected-archive evidence. No unresolved high-severity alerts remained at that verification.


## Portal and practice onboarding separation

At the operator's request, practice endpoint review and the two-night Sorski pilot are tracked separately from cloud-portal technical readiness. Their evidence is still pending; no pilot success is implied. Cloud MFA recovery, independent monitoring, provider approvals and an explicit portal review remain required for portal approval. Existing backend provider guards on production file transfers are unchanged.

The persistent yellow activation banner has been replaced with a compact header status. Security & logs retains provider approval details, cloud readiness and the independent practice-onboarding status. Removing a banner does not approve PHI processing.

November 23 verification: 57 application tests passed (one PostgreSQL-only case skipped in that run), then all 18 PostgreSQL integration tests passed. The role matrix exercised viewer, uploader, editor and practice-administrator behavior, cross-practice list/download/upload/administration denial, and immediate denial after membership removal. Clerk tests cover invalid signatures/origins, pending sessions, absent/stale second factors, revoked sessions, unverified/banned users and application-owned membership. These automated tests supplement the operator-confirmed live sign-in and access assignment; live recovery-code and session-revocation acceptance remain unverified.


## Administrator completion confirmation

On November 23, the Streamlined Consulting administrator confirmed completion of MFA recovery/session revocation, unattended monitoring, and all four provider approvals. This is recorded as administrator attestation, not an independent document review or a newly observed scheduled workflow. MFA and monitoring evidence are current, and all cloud technical gates passed at the subsequent live check. Sorski endpoint and pilot evidence remain deferred separately.

The provider confirmation is stored in the protected operational database. Applying the four existing production approval environment flags was rejected by Vercel with HTTP 403; no authenticated local CLI was available. Production authorization therefore remains false until those flags are saved and redeployed. Final portal activation review must follow that deployment. The administrator need not resubmit agreement proof to repeat this confirmation.
