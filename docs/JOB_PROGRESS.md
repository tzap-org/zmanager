# Job progress contract

`zmanager-core::jobs::JobEvent` distinguishes whole-job lifecycle events from
phase-native progress.

TZAP create jobs emit these phases in order when they use the multi-pass
writer:

1. `PlanningPayload`
2. `PlanningMetadata`
3. `EmittingPayload`
4. `EmittingMetadata`
5. `CommittingOutput`

Single-pass and ordered-parallel TZAP writers begin at `EmittingPayload`.

`PhaseStarted` announces the active phase and its source-byte total when that
phase consumes source bytes. `PhaseBytesProcessed` is cumulative only within
the named phase. Consumers must not combine phase byte totals as though they
were unique file content: a multi-pass writer intentionally reads the same
logical source bytes during planning and emission.

`BytesProcessed` remains the generic logical-file counter used across archive
backends. For TZAP create, it advances during `EmittingPayload`, when the final
payload is actually being produced. It must not be interpreted as complete
until the job emits `Completed`.

`CommittingOutput` is owned by ZManager because TZAP finishes writing into an
application-provided sink before ZManager atomically publishes the temporary
output files.

