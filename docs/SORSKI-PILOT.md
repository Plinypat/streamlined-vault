# Sorski pilot visit

1. On the practice computer, sign into Streamlined Vault, select the practice, then Uploaders > Add uploader. Download the current Windows ZIP from step 1 and extract the entire folder. Keep the executable and its _internal folder together. This is an unsigned MSP pilot package, not a signed mass-deployment release. Use the ZIP SHA-256 shown under Verify your download to verify the download under your normal software-approval process.
2. Use a supported Windows x64 computer. Confirm disk encryption, current updates, correct local clock/time zone, internet access and an awake/online window for the nightly test.
3. Create a NEW empty local folder, for example C:\StreamlinedVaultPilot. The pilot must contain no patient files. Network folders and existing populated folders are refused.
4. After the download finishes, choose Continue to enrollment in the portal. Name it Sorski pilot. Set daily 21:00, all days, and destination Pilot test files. A one-time enrollment code expires after 15 minutes; create or renew it at the practice, not before traveling.
5. Run Streamlined-Vault-Pilot-Setup.exe with administrator approval. Choose the empty test folder, paste the one-time code (not your password or a storage key), then select Install and enroll.
6. Confirm the device appears online in Uploaders. The package installs the branded agent and runtime under Program Files, protects credentials under ProgramData using Windows DPAPI, and creates a startup task running as SYSTEM. The agent follows the schedule selected in the portal.
7. Run the uploader once from the portal. Let the two synthetic files settle for two minutes first. Confirm both arrive, download them, and compare SHA-256 values with C:\ProgramData\StreamlinedVault\pilot-checksums.json. An offline preview or a successful enrollment is not a successful transfer.
8. Observe two actual scheduled nights at 9 p.m. while the computer is awake and online. Confirm run summaries and successful downloads. Also test a changed synthetic file, interrupted/resumed transfer, restart, quota rejection in a disposable test workspace, and device revoke/re-enrollment. Never alter a real practice quota to test rejection.
9. Record pilot evidence only after those tests pass. Add real imaging exports only after their manufacturer-approved source method and exclusions are confirmed and production approval is complete.

If installation stops after enrollment, do not copy tokens or remove safeguards. Review the existing installation, revoke the device in the portal, and use the MSP re-enrollment procedure. This package does not silently overwrite an enrolled computer or delete source/cloud files.

Clerk test identity: patrickdenatale@gmail.com. Use this dedicated identity for MFA, recovery, role and removal tests. Preserve the primary administrator account. Do not grant it MSP administrator status merely to test practice access.

The Windows pilot has to be observed on the actual practice computer. It cannot be marked complete by running installer unit tests on the development machine.

The portal also offers Download current installer without creating another device. Releases are centrally published; a release update changes the next download, not software already installed on a practice computer. Automatic in-place updates and signing are not part of this pilot.
