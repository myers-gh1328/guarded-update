# Progress: isolated inventory reporter integration

Goal: connect the generation-bound reader to the existing inventory coordinator without false coherence or cleanup claims.
Updated: 2026-10-29

## Decisions
- Keep request execution inactive until the native lifecycle, provisioning and measured resource gates pass.
- Parent owns durable journal authority; private publication ports are bounded I/O only.
- Keep the admitted environment clock alive through terminal prepared evidence, then close everything before successful exit. Prepared evidence alone never grants completion.

## Steps
- [x] Fixed reader/environment, durable journal gates, selected-generation normalization and bounded codec/pipe libraries.
- [x] Fixed publication owner, reviewed and tested.
- [x] Scan phases with a shared capped native clock, exact start ACK before hashing, frozen end and own-receipt prepared evidence.
- [x] Managed bounded dialogue, exact nested scan ACK and prepared-only terminal output with all-owner cleanup.
- [ ] Fixed source bootstrap, Rust Tools/coordinator bridge and native end-to-end proof. <- next
- [ ] Concrete process-set cleanup witness, owned cache retirement, measured fit, disabled provisioning and rollout verification.

## Last check
569 helper tests passed11.375s, including15 real-pipe dialogue tests; both independent source reviews and diff checks clear. Scan phase ef65de0 passed all14 hosted jobs in CI40820627723. No production activation.

## Next action
Verify and commit the dialogue, then implement the fixed reporter source bootstrap and native managed roundtrip. Keep this draft integration PR open; remove this temporary progress file before merge.

## Waiting on
Nothing for current implementation; no owner clarification is needed.
