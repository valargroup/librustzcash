# Orchard Sync Architecture

This document sketches a new Orchard-only sync architecture for this fork. The
goal is to separate sync concepts that are coupled in the current
`zcash_client_backend` and `zcash_client_sqlite` design.

The initial scope is Orchard. Sapling and transparent state remain owned by the
legacy wallet database until later migration work.

## Goals

- Separate external note discovery from witness maintenance.
- Treat full transaction discovery as its own task.
- Store Orchard note history in a new database model.
- Make witness updates note-centric.
- Support block-based sync and PIR-based sync without pretending that every
  method provides the same completeness guarantees.
- Keep compact block fetching and compact block pruning explicit.
- Preserve the ability to use block sync as a backup witness update method.
- Add short-range rollback support for recently accepted chain state.
- Defer merged wallet-wide history until the Orchard history model is stable.

## Non-Goals

- Replace legacy Sapling sync in the first version.
- Replace legacy transparent tracking in the first version.
- Require a separate header sync protocol in the first version.
- Treat PIR discovery attempts as complete historical scans unless the PIR
  method provides that guarantee.
- Redesign transaction creation or fee calculation in the first version.

## Current Model Issues

The current sync path uses block scanning as the central operation. A call to
`scan_cached_blocks` does note discovery, spend detection, commitment ingestion,
tree updates, wallet persistence, scan queue mutation, and witness stabilization.

The current SQLite transaction history is also assembled from several tables:

- `transactions`
- `sapling_received_notes`
- `orchard_received_notes`
- `transparent_received_outputs`
- `sent_notes`
- shielded and transparent spend-link tables
- summary views such as `v_transactions`

That model works for the current wallet, but it makes it hard for a new Orchard
engine to own Orchard notes without either duplicating writes into legacy tables
or letting the old views define the new model.

The new design therefore starts with a separate Orchard history database. A
merged history view is a later integration step.

## Conceptual Roles

### External Note Discovery

External note discovery answers:

> Did an external Orchard receiver controlled by this wallet receive a note?

Supported methods:

- Trial decrypt over compact blocks.
- PIR discovery for a specific action.

Trial decrypt over a complete block range may provide a completeness guarantee
for that range. PIR discovery for a specific action does not imply that any
historical range has been fully searched.

### Full Transaction Discovery

Full transaction discovery answers:

> Given a compact action or spend that appears relevant, what full transaction
> created or spent it?

A full transaction task fetches the transaction bytes and ingests every input
and output relevant to the wallet. Memo availability should be modeled as a
result of full transaction ingestion, not as an implicit property of compact
block scanning.

### Internal Note Discovery

Internal note discovery answers:

> Did this wallet create a change or internal note?

The primary trigger is observing consumption of a known nullifier. Once a spend
is detected, the engine fetches the full transaction, checks every output, and
records any wallet-internal notes.

If the spend transaction references inputs that the wallet does not yet know,
the engine may query for note commitment data through PIR to classify history
and maintain consistency.

Trial decrypt with internal keys remains a possible fallback for out-of-range
or recovery flows, but it should not be the default conceptual path.

### Witness Updates

Witness maintenance answers:

> Can a known Orchard note be spent from a selected chain state?

Witness updates are note-centric. Each known note tracks its own witness state:

- current witness height
- witness block hash
- serialized witness value
- created-at block
- spent-at block, if known

The preferred historical witness method is PIR. Block-based witness updates are
a backup method and the normal recent-chain append method.

### Compact Block Fetching

Compact block fetching answers:

> Which source should provide the compact block data needed by discovery or
> witness update tasks?

Fetching should be separable from sync policy. The fetch layer should support
multiple sources and collect source metrics such as bytes downloaded, latency,
failure rate, and useful-block yield.

Historical compact blocks should be pruned after all required discovery,
transaction-fetch triggers, nullifier checks, and witness-update work has been
completed for the relevant range.

## Core Data Types

These names are provisional.

```rust
enum ShieldedPool {
    Orchard,
}

struct BlockRef {
    height: BlockHeight,
    hash: BlockHash,
}

struct BlockRange {
    start_height: BlockHeight,
    end_height: BlockHeight,
}

enum DiscoveryMethod {
    TrialDecrypt,
    PirAction,
}

enum DiscoveryGuarantee {
    CompleteForRange,
    Opportunistic,
    NoHistoricalGuarantee,
}

enum WitnessUpdateMethod {
    PirShardFetch,
    BlockBackupRange,
    RecentBlockAppend,
}

enum FullTxReason {
    ExternalNoteFound,
    KnownNullifierSpent,
    PirSpendDetected,
    HistoryCompletion,
}
```

## Caller API Surface

The first caller API should be oriented around explicit wallet actions, not
around the old `scan_queue` model. The API should be usable by a wallet that
owns orchestration and wants to call individual routines.

The `sample-sync/legacy` crate in this workspace contains a pure-Rust
executable model of the current Vizor-style sync boundary. The
`sample-sync/new` crate contains the proposed Orchard API shape. Neither is
production code; they exist so that the current caller/library split can be
compared directly against the proposed replacement.

Existing `vizor-wallet` usage falls into these groups:

- full sync orchestration: `run_sync_inner`
- chain-tip and scan range management: `update_chain_tip`, `suggest_scan_ranges`
- compact block ingestion: `scan_blocks`
- subtree root ingestion: `put_orchard_subtree_roots`
- transaction enhancement: `get_transaction_data_requests`,
  `decrypt_and_store_transaction`, `set_transaction_status`
- balance and history queries: `get_wallet_balance`, `get_transaction_history`,
  `get_transaction_detail`
- rollback: `rewind_to_height`
- spending: `propose_send`, `execute_proposal`, PCZT helpers, transparent
  shielding helpers

The new Orchard API should replace these in stages.

### Store Lifecycle

```rust
struct OrchardSyncStore;

impl OrchardSyncStore {
    fn open(path: &Path, network: Network) -> Result<Self, Error>;
    fn initialize(&mut self) -> Result<(), Error>;
    fn hydrate_from_legacy(&mut self, legacy_path: &Path) -> Result<HydrationSummary, Error>;
}
```

The new store is separate from the legacy wallet database. Hydration is
idempotent and conservative.

### Chain State

```rust
impl OrchardSyncStore {
    fn update_chain_tip(&mut self, tip: BlockRef) -> Result<(), Error>;
    fn get_sync_status(&self, account: AccountId) -> Result<OrchardSyncStatus, Error>;
    fn rollback_to(&mut self, ancestor: BlockRef) -> Result<RollbackSummary, Error>;
}
```

This replaces the Orchard portion of today's `update_chain_tip`,
`get_sync_progress`, and `rewind_to_height` behavior.

Rollback takes a `(height, hash)` pair, not only a height.

### Compact Block Fetch Planning

```rust
impl OrchardSyncStore {
    fn next_compact_block_requests(
        &self,
        limits: FetchLimits,
    ) -> Result<Vec<CompactBlockRequest>, Error>;

    fn ingest_compact_blocks(
        &mut self,
        source: BlockSourceId,
        blocks: &[CompactBlock],
    ) -> Result<CompactBlockIngestSummary, Error>;

    fn prune_compact_blocks(&mut self) -> Result<PruneSummary, Error>;
}
```

This separates compact block fetching from note discovery. A caller may satisfy
requests using lightwalletd, another compact block source, or a future peer
selection layer.

`ingest_compact_blocks` should record block metadata and make the blocks
available to discovery and witness tasks. It should not imply that discovery or
witness updates have completed.

### External Note Discovery

```rust
impl OrchardSyncStore {
    fn next_external_discovery_tasks(
        &self,
        limits: TaskLimits,
    ) -> Result<Vec<ExternalDiscoveryTask>, Error>;

    fn trial_decrypt_discover_notes(
        &mut self,
        task: ExternalDiscoveryTask,
        keys: &[OrchardViewingKey],
    ) -> Result<DiscoverySummary, Error>;

    fn ingest_pir_action_discovery(
        &mut self,
        result: PirActionDiscoveryResult,
    ) -> Result<DiscoverySummary, Error>;
}
```

This replaces the external-note-discovery portion of today's `scan_blocks`.

Trial decrypt over a compact block range may produce a
`DiscoveryGuarantee::CompleteForRange`. PIR action discovery should not produce
a range-completeness guarantee unless the PIR method actually provides one.

### Full Transaction Discovery

```rust
impl OrchardSyncStore {
    fn next_full_tx_requests(
        &self,
        limits: TaskLimits,
    ) -> Result<Vec<FullTxRequest>, Error>;

    fn ingest_full_transaction(
        &mut self,
        tx: &Transaction,
        mined: Option<BlockRef>,
    ) -> Result<FullTxIngestSummary, Error>;

    fn set_full_tx_status(
        &mut self,
        txid: TxId,
        status: FullTxStatus,
    ) -> Result<(), Error>;
}
```

This replaces the Orchard part of today's transaction enhancement flow:
`get_transaction_data_requests`, `decrypt_and_store_transaction`, and
`set_transaction_status`.

Full transaction ingestion should inspect every Orchard action and spend in the
transaction. It is the place where internal notes, memo data, and spentness are
recorded.

### Internal Note Discovery

```rust
impl OrchardSyncStore {
    fn next_internal_discovery_tasks(
        &self,
        limits: TaskLimits,
    ) -> Result<Vec<InternalDiscoveryTask>, Error>;

    fn ingest_nullifier_search_result(
        &mut self,
        result: NullifierSearchResult,
    ) -> Result<InternalDiscoverySummary, Error>;
}
```

Internal discovery is primarily nullifier-driven. When a known nullifier is
observed as spent, the engine should enqueue a high-priority full transaction
request for the spending transaction.

### Witness Maintenance

```rust
impl OrchardSyncStore {
    fn next_witness_tasks(
        &self,
        limits: TaskLimits,
    ) -> Result<Vec<WitnessTask>, Error>;

    fn ingest_pir_witness(
        &mut self,
        result: PirWitnessResult,
    ) -> Result<WitnessUpdateSummary, Error>;

    fn update_witnesses_from_blocks(
        &mut self,
        range: BlockRange,
    ) -> Result<WitnessUpdateSummary, Error>;

    fn get_raw_notes(
        &self,
        query: NoteQuery,
    ) -> Result<Vec<RawOrchardNoteInfo>, Error>;
}
```

This replaces the witness-maintenance portion of today's `scan_blocks` and
`put_orchard_subtree_roots` behavior.

The store should maintain:

- data for the latest Orchard shard
- data for any shard containing a wallet note
- per-note witness state

PIR witness updates are preferred. Block-based witness updates remain available
for recent append and backup range updates.

### Balances and History

```rust
impl OrchardSyncStore {
    fn get_orchard_balance(
        &self,
        account: AccountId,
        policy: SpendabilityPolicy,
    ) -> Result<OrchardBalance, Error>;

    fn get_orchard_history(
        &self,
        account: AccountId,
        query: HistoryQuery,
    ) -> Result<Vec<OrchardHistoryRow>, Error>;

    fn get_orchard_transaction_detail(
        &self,
        account: AccountId,
        txid: TxId,
    ) -> Result<OrchardTransactionDetail, Error>;
}
```

This is the new Orchard-only counterpart to today's `get_wallet_balance`,
`get_transaction_history`, and `get_transaction_detail`.

Merged wallet-wide history is intentionally later. Until then, callers can show
legacy Sapling/transparent history and Orchard history through a temporary
composition layer.

### Spending

```rust
impl OrchardSyncStore {
    fn get_spendable_orchard_notes(
        &self,
        account: AccountId,
        target_height: BlockRef,
        policy: SpendabilityPolicy,
    ) -> Result<Vec<SpendableOrchardNote>, Error>;

    fn reserve_notes_for_spend(
        &mut self,
        request: SpendReservationRequest,
    ) -> Result<SpendReservation, Error>;

    fn mark_transaction_created(
        &mut self,
        tx: &Transaction,
        reservation: SpendReservationId,
    ) -> Result<(), Error>;
}
```

The first implementation may keep transaction construction on the legacy
librustzcash path. This API defines what the new Orchard DB must eventually
provide to a spending engine: spendable notes with witnesses, reservation to
avoid double selection, and created-transaction tracking.

Open spending question:

- whether Orchard notes selected by the new DB should be fed into the existing
  proposal engine, or whether Orchard-only spending gets a new proposal path.

## Orchard History Database

The new Orchard database owns Orchard note history and Orchard transaction
ingestion state. Sapling and transparent history remain in the legacy database.

### Blocks

```sql
CREATE TABLE orchard_chain_blocks (
    height INTEGER PRIMARY KEY,
    block_hash BLOB NOT NULL UNIQUE,
    prev_block_hash BLOB,
    time INTEGER,
    orchard_tree_size INTEGER
);

CREATE INDEX orchard_chain_blocks_hash_idx
ON orchard_chain_blocks(block_hash);
```

### Transactions

```sql
CREATE TABLE orchard_transactions (
    txid BLOB PRIMARY KEY,
    mined_height INTEGER,
    mined_block_hash BLOB,
    tx_index INTEGER,
    raw BLOB,
    first_observed_height INTEGER,
    full_tx_fetched_at_height INTEGER,

    CHECK ((mined_height IS NULL) = (mined_block_hash IS NULL))
);

CREATE INDEX orchard_transactions_mined_idx
ON orchard_transactions(mined_height, mined_block_hash);
```

This table is Orchard history state. It may contain transactions that also
appear in the legacy database. Cross-database merging is deferred.

### Notes

```sql
CREATE TABLE orchard_notes (
    note_id BLOB PRIMARY KEY,
    account_id BLOB NOT NULL,

    txid BLOB NOT NULL,
    action_index INTEGER NOT NULL,

    value_zat INTEGER NOT NULL,
    diversifier BLOB,
    rho BLOB,
    rseed BLOB,
    nullifier BLOB,
    recipient_scope INTEGER,
    is_change INTEGER NOT NULL DEFAULT 0,

    commitment_tree_position INTEGER,

    created_at_height INTEGER,
    created_in_block_hash BLOB,

    spent_at_height INTEGER,
    spent_in_block_hash BLOB,

    witness_height INTEGER,
    witness_block_hash BLOB,
    witness_value BLOB,

    status INTEGER NOT NULL,

    CHECK ((created_at_height IS NULL) = (created_in_block_hash IS NULL)),
    CHECK ((spent_at_height IS NULL) = (spent_in_block_hash IS NULL)),
    CHECK ((witness_height IS NULL) = (witness_block_hash IS NULL)),
    CHECK ((witness_value IS NULL) = (witness_height IS NULL))
);

CREATE UNIQUE INDEX orchard_notes_tx_action_idx
ON orchard_notes(txid, action_index);

CREATE UNIQUE INDEX orchard_notes_nullifier_idx
ON orchard_notes(nullifier)
WHERE nullifier IS NOT NULL;

CREATE INDEX orchard_notes_created_idx
ON orchard_notes(created_at_height, created_in_block_hash);

CREATE INDEX orchard_notes_spent_idx
ON orchard_notes(spent_at_height, spent_in_block_hash);

CREATE INDEX orchard_notes_witness_idx
ON orchard_notes(witness_height, witness_block_hash);

CREATE INDEX orchard_notes_position_idx
ON orchard_notes(commitment_tree_position);
```

### Discovery Attempts

```sql
CREATE TABLE orchard_discovery_attempts (
    id INTEGER PRIMARY KEY,
    method INTEGER NOT NULL,
    guarantee INTEGER NOT NULL,
    start_height INTEGER,
    end_height INTEGER,
    action_txid BLOB,
    action_index INTEGER,
    completed_at_height INTEGER,
    completed_at_block_hash BLOB
);

CREATE INDEX orchard_discovery_attempts_range_idx
ON orchard_discovery_attempts(start_height, end_height);
```

This table records work that was attempted. It must not be used to infer that a
range is complete unless `guarantee` explicitly says so.

### Full Transaction Tasks

```sql
CREATE TABLE orchard_full_tx_tasks (
    txid BLOB PRIMARY KEY,
    reason INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    status INTEGER NOT NULL,
    discovered_at_height INTEGER,
    discovered_at_block_hash BLOB
);

CREATE INDEX orchard_full_tx_tasks_order_idx
ON orchard_full_tx_tasks(status, priority DESC);
```

### Witness Tasks

```sql
CREATE TABLE orchard_witness_tasks (
    note_id BLOB NOT NULL,
    target_height INTEGER NOT NULL,
    target_block_hash BLOB,
    method INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    status INTEGER NOT NULL,

    PRIMARY KEY (note_id, target_height, method)
);

CREATE INDEX orchard_witness_tasks_order_idx
ON orchard_witness_tasks(status, priority DESC, target_height DESC);
```

## Witness Policy

The engine maintains:

- data for the latest Orchard shard
- data for shards containing wallet notes
- per-note witness state

PIR witness updates are preferred. Block-based witness updates are used for:

- recent block append
- backup updates when PIR is unavailable
- recovery from incomplete PIR results

When a note is found by trial decrypt over a block range, the scanner may have
enough commitment data to establish an initial witness. The resulting witness
still belongs to the note, not to the scan range.

When a note is found by PIR, the engine creates the note first and then creates a
PIR witness task. That task may target a recent block height instead of the
note's creation height.

After receiving a note, the engine should enqueue spend detection work. Once PIR
spend detection is available, spend detection should be attempted immediately.
If the note is already spent, the spending transaction should be prioritized for
full transaction ingestion.

## Rollback Policy

Rollback means invalidating state derived from blocks that are no longer in the
selected chain.

The new DB stores block hash alongside every height-derived note fact. This lets
the engine distinguish "same height, different block" from "same chain".

On short-range rollback to a common ancestor:

- remove or mark orphaned `orchard_chain_blocks`
- clear `created_at_*` for notes created after the ancestor
- clear `spent_at_*` for spends observed after the ancestor
- clear `witness_*` for witnesses above the ancestor
- requeue recent witness update work
- requeue external discovery for affected block ranges when the previous
  discovery method had a complete-range guarantee

Rollback support is initially bounded to recent chain state.

## Trial Decrypt Optimization

Future lightwalletd support may pass both `tk` and `tk_helper = tk^{2^64}` for
each action.

Until that exists, trial decrypt ingestion should be architected so that when:

- multiple view keys are active, and
- the helper is not provided by the source,

the engine can compute `tk_helper` and a reusable scalar multiplication window
before trial decrypt. This should be cached so that trial decrypt work for
inactive accounts can reuse prior computation.

Initial implementation should include TODOs and capability boundaries, not the
full optimization.

The scheduler should be able to prioritize trial decrypt for an active wallet or
account while preserving helper/window cache entries for future work.

## Implementation Plan

### Phase 1: Model Crate

Create a new model crate for Orchard sync domain types:

- block references and ranges
- discovery methods and guarantees
- full transaction task reasons
- witness update methods
- note lifecycle status
- rollback events

This crate should not depend on SQLite.

### Phase 2: Orchard History DB

Create a new SQLite-backed Orchard history crate.

Implement:

- schema creation
- typed inserts and updates
- idempotent upserts
- query helpers for pending tasks
- rollback helpers for height and block-hash indexed facts

Do not write into legacy `orchard_received_notes` in this phase.

### Phase 3: Legacy Hydration

Hydrate Orchard state from the legacy wallet database:

- accounts needed by Orchard sync
- known Orchard notes
- known Orchard nullifiers
- known Orchard note positions
- known Orchard mined/spent heights where available
- existing full transaction bytes where available

Hydration should be conservative and restartable.

### Phase 4: Block Trial Decrypt Discovery

Implement Orchard external note discovery over compact block ranges.

Outputs:

- discovered Orchard notes
- discovery attempt records with explicit guarantees
- full transaction tasks for relevant compact actions
- optional initial witness state if the range scan produced it

### Phase 5: Full Transaction Ingestion

Implement full transaction fetch and ingestion for Orchard-relevant
transactions.

On ingest:

- inspect every Orchard action
- record external and internal Orchard notes
- inspect spends
- update spent status for known notes
- enqueue PIR note commitment lookup for unknown relevant inputs when needed
- record memo data from full transaction outputs

### Phase 6: Note-Centric Witness Updates

Implement witness tasks.

Preferred method:

- PIR shard fetch for the note's position and target height

Backup methods:

- block range witness update for note shards
- recent block append for current tip updates

### Phase 7: Compact Block Fetch Layer

Extract compact block fetching behind a source-selection interface.

Track:

- source id
- bytes downloaded
- latency
- failures
- useful block yield

Prune historic compact block data once all dependent tasks are complete.

### Phase 8: Merged History View

Add a merged history layer after Orchard history is stable.

Inputs:

- legacy Sapling history
- legacy transparent history
- new Orchard history

This layer should merge by `txid`, not by legacy `transactions.id_tx`.

Open design questions:

- whether merged history is a SQL view, a Rust query layer, or a materialized
  projection
- how to represent transactions involving both new Orchard and legacy Sapling
- whether full transaction bytes are shared or duplicated
- how to compute wallet-wide fee and memo summaries across both systems

This phase is intentionally later. The first milestone is correct Orchard sync
state, not wallet-wide history replacement.

## Open Questions

- Should new Orchard transactions reference legacy `transactions` rows when
  present, or remain fully independent and merge only by `txid`?
- Should full transaction bytes be stored in both databases during transition?
- What is the first PIR witness target: current tip, stable height, or a
  recent checkpoint height?
- Which compact block sources are supported in the first implementation?
- What recent rollback depth should the new engine guarantee?
