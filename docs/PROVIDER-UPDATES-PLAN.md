# Provider update implementation

Change class: cross-repository preparation contract and device/provider UI. No
package operation is authorized by enrollment or a preparation request alone.

1. Introduce versioned provider-specific selected/all-eligible preparation intents.
   Preserve APT v1; advertise v2 support from the root dispatcher before delivery.
2. Resolve APT roots after metadata refresh from installed upgrade candidates,
   restricted to local allowlist and holds. Freeze the complete dependency closure
   using the existing signed exact-manifest execution gate.
3. Group dashboard updates by device and native install method. Capabilities must
   distinguish discovery, preparation and execution, and identify user context.
4. Reuse Homebrew discovery and native dependency planning. Add WinGet discovery
   through structured native output; never infer coverage from service context.
   Neither provider gains exact remote execution until its artifact freeze and
   claim gate is implemented and verified on that platform.
5. Verify synthetic contracts, signature separation, legacy profiles and hosted
   native CI. Activation requires the exact verified artifact and enrollment.

Invariants: no arbitrary command, shell or path input; no silent batching; held or
excluded packages remain visible; no automatic removal, privilege escalation or
reboot; OS updates remain separate; no real endpoint changes during tests.

Tradeoff: a compact all-eligible intent avoids browser-sized package lists and
12 KiB signature limits, but fresh local resolution may discover a different set
than saved inventory. Exact manifest review exposes that set before installation.
Missing provider/context support is unavailable, never simulated success.

Rollout/rollback: deploy compatible server first; capability negotiation withholds
v2 from old root agents. Disable preparation enrollment to stop new work while
retaining status/result reconciliation. Existing manifests and one-use claims
remain unchanged. No package install enables a service automatically.
