# Active executor correction

Goal: accept independently verified APT cache copies of approved archives and
report a gate-rejected claimed attempt without replaying installation.

Owner authorization: continue the selected remote pilot rollout; keep exact human
approval, signature, freshness, archive and journal gates. No automatic reboot or
reuse of a consumed attempt. No credentials or private deployment data here.

Completed: reproduced both adapter failures before changes; actual-path evidence
uses the existing protected-file inspection and exact approved identity/hash.
Claim correlation is recorded separately from execution start and cannot establish
success. Added cache substitution and claimed-only success regressions.

Verification: 16 synthetic Python tests pass. Existing Rust gate is unchanged.
Next: full Rust profile checks, public CI including isolated relocated upgrade,
review, then merge only when all checks pass. Pilot recovery reports the preserved
terminal interruption without any APT replay. A future install needs new approval.
