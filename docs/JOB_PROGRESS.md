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
Automatic volume sizing may repeat the `PlanningPayload` and
`PlanningMetadata` pair before emission. Every `PhaseStarted` begins a new
phase occurrence and resets that occurrence's cumulative counter.

`PhaseStarted` announces the active phase and its source-byte total when that
phase consumes source bytes. `PhaseBytesProcessed` is cumulative only within
the named phase. Consumers must not combine phase byte totals as though they
were unique file content: a multi-pass writer intentionally reads the same
logical source bytes during planning and emission.

Create and extract jobs coalesce source-byte progress using one format-neutral
policy. The first activity is emitted immediately. Later progress is emitted
after one second or after `max(4 MiB, 1% of the known job or phase total)`
bytes, whichever condition is reached first. Unknown-size jobs use the 4 MiB
byte threshold. Pending progress is flushed before terminal lifecycle events;
phase progress is also flushed at phase boundaries.

Each aggregate includes the most recently active archive member as an activity
hint. Its byte count may include earlier members in the same batch, so
consumers must not attribute all aggregate bytes to that path. It also includes
up to 10 distinct recently active paths, ordered oldest to newest, for
responsive activity displays. The list resets after every emitted aggregate.
Use cumulative counters rather than relying on callback frequency.

`BytesProcessed` remains the generic logical-file counter used across archive
backends. For TZAP create, it advances during `EmittingPayload`, when the final
payload is actually being produced. It must not be interpreted as complete
until the job emits `Completed`.

`CommittingOutput` is owned by ZManager because TZAP finishes writing into an
application-provided sink before ZManager atomically publishes the temporary
output files.
