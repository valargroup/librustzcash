use async_trait::async_trait;
use core::time::Duration;

use zcash_client_backend::proto::compact_formats::CompactBlock;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockRef {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockRange {
    pub start: BlockHeight,
    pub end: BlockHeight,
}

/// Scheduling class for sync work.
///
/// Recent work is latency-sensitive state near the chain tip: current note
/// discovery, current spend detection, and witness updates needed to make
/// known notes spendable. Historic work is recovery/backfill state where
/// throughput matters more than immediate user-visible freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncWorkClass {
    Recent,
    Historic,
}

/// Budget for one class of sync work.
///
/// Both fields are optional because callers may want to express a block budget,
/// a wall-clock budget, or both. A managed sync loop should yield out of the
/// current work class when either configured budget is exhausted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorkBudget {
    pub max_blocks: Option<u32>,
    pub max_duration: Option<Duration>,
}

/// Scheduling policy for alternating between recent and historic work.
///
/// This replaces the legacy tendency to overload a single batch size with
/// several unrelated concerns. The wallet can ask the managed loop to spend a
/// bounded amount of work on recent chain-tip freshness before making progress
/// on historic recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncSchedulingPolicy {
    pub recent: WorkBudget,
    pub historic: WorkBudget,
    pub prefer_recent_until_caught_up: bool,
}

impl Default for SyncSchedulingPolicy {
    fn default() -> Self {
        Self {
            recent: WorkBudget {
                max_blocks: Some(100),
                max_duration: Some(Duration::from_secs(2)),
            },
            historic: WorkBudget {
                max_blocks: Some(1_000),
                max_duration: Some(Duration::from_secs(10)),
            },
            prefer_recent_until_caught_up: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiscoveryGuarantee {
    CompleteForRange,
    Opportunistic,
    NoHistoricalGuarantee,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExternalDiscoveryMethod {
    TrialDecrypt,
    PirAction,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessUpdateMethod {
    PirShardFetch,
    BlockBackupRange,
    RecentBlockAppend,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FullTxReason {
    ExternalNoteFound,
    KnownNullifierSpent,
    PirSpendDetected,
    HistoryCompletion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExternalDiscoveryTask {
    pub method: ExternalDiscoveryMethod,
    pub range: Option<BlockRange>,
    pub guarantee: DiscoveryGuarantee,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullTxRequest {
    pub txid: TxId,
    pub reason: FullTxReason,
    pub priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessTask {
    pub note_id: OrchardNoteId,
    pub target: BlockRef,
    pub method: WitnessUpdateMethod,
    pub priority: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrchardNoteId {
    pub txid: TxId,
    pub action_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawOrchardNoteInfo {
    pub note_id: OrchardNoteId,
    pub account_id: Vec<u8>,
    pub value: Zatoshis,
    pub created_at: Option<BlockRef>,
    pub spent_at: Option<BlockRef>,
    pub witness_at: Option<BlockRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceBreakdown {
    pub finalized_available: Zatoshis,
    pub pending_confirmation: Zatoshis,
    pub pending_sync: Zatoshis,
    pub spendable: Zatoshis,
}

impl Default for BalanceBreakdown {
    fn default() -> Self {
        Self {
            finalized_available: Zatoshis::ZERO,
            pending_confirmation: Zatoshis::ZERO,
            pending_sync: Zatoshis::ZERO,
            spendable: Zatoshis::ZERO,
        }
    }
}

pub trait OrchardSyncStore {
    type Error;

    fn update_chain_tip(&mut self, tip: BlockRef) -> Result<(), Self::Error>;
    // Notification boundary:
    // The caller should notify after this commits if chain-tip-dependent UI
    // state changed. This should not be treated as wallet activity by itself.

    fn rollback_to(&mut self, ancestor: BlockRef) -> Result<(), Self::Error>;
    // Notification boundary:
    // Rollback can invalidate note lifecycle facts, witnesses, balances, and
    // history. Callers should refresh all visible Orchard state after commit.

    fn ingest_compact_blocks(
        &mut self,
        source_id: &str,
        blocks: &[CompactBlock],
    ) -> Result<(), Self::Error>;
    // Notification boundary:
    // Compact block ingestion records source/block availability. It should not
    // notify as discovery or witness completion until those specific tasks run.

    fn next_external_discovery_tasks(
        &self,
        limit: usize,
    ) -> Result<Vec<ExternalDiscoveryTask>, Self::Error>;

    fn trial_decrypt_discover_notes(
        &mut self,
        task: ExternalDiscoveryTask,
        viewing_keys: &[UnifiedFullViewingKey],
    ) -> Result<(), Self::Error>;
    // Notification boundary:
    // Notify after commit when new notes or spend-detection work were created.
    // The summary type should eventually say whether caller-visible history,
    // balance, or only background work changed.

    fn next_full_tx_requests(&self, limit: usize) -> Result<Vec<FullTxRequest>, Self::Error>;

    fn ingest_full_transaction(
        &mut self,
        tx: &Transaction,
        mined: Option<BlockRef>,
    ) -> Result<(), Self::Error>;
    // Notification boundary:
    // Full transaction ingestion may add memos, internal notes, spentness, and
    // history detail. This is a transaction-history refresh point.

    fn next_witness_tasks(&self, limit: usize) -> Result<Vec<WitnessTask>, Self::Error>;

    fn update_witnesses_from_blocks(&mut self, range: BlockRange) -> Result<(), Self::Error>;
    // Notification boundary:
    // Witness updates can move funds from pending-sync to finalized/spendable.
    // Notify balance/spendability observers after commit.

    fn get_raw_orchard_notes(&self) -> Result<Vec<RawOrchardNoteInfo>, Self::Error>;

    fn get_orchard_balance(&self, account_id: &[u8]) -> Result<BalanceBreakdown, Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedSyncPhase {
    UpdateChainTip,
    FetchCompactBlocks,
    ExternalDiscovery,
    FetchFullTransaction,
    InternalDiscovery,
    WitnessUpdate,
    PruneCompactBlocks,
    Rollback,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManagedSyncEvent {
    PhaseStarted { phase: ManagedSyncPhase },
    PhaseCompleted { phase: ManagedSyncPhase },
    ChainTipUpdated { tip: BlockRef },
    NotesDiscovered { count: usize },
    FullTransactionIngested { txid: TxId },
    WitnessesUpdated { count: usize },
    Rollback { ancestor: BlockRef },
    BalanceChanged,
    HistoryChanged,
    SpendabilityChanged,
}

pub trait OrchardSyncNotifier {
    type Error;

    fn notify(&mut self, event: ManagedSyncEvent) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedSyncLimits {
    pub scheduling: SyncSchedulingPolicy,
    pub external_discovery_tasks: usize,
    pub full_tx_requests: usize,
    pub witness_tasks: usize,
}

impl Default for ManagedSyncLimits {
    fn default() -> Self {
        Self {
            scheduling: SyncSchedulingPolicy::default(),
            external_discovery_tasks: 16,
            full_tx_requests: 16,
            witness_tasks: 16,
        }
    }
}

#[async_trait]
pub trait OrchardSyncDataSource {
    type Error;

    async fn latest_chain_tip(&mut self) -> Result<BlockRef, Self::Error>;

    async fn compact_blocks(&mut self, range: BlockRange)
    -> Result<Vec<CompactBlock>, Self::Error>;

    async fn full_transaction(
        &mut self,
        request: FullTxRequest,
    ) -> Result<Transaction, Self::Error>;

    async fn pir_action_discovery(
        &mut self,
        task: ExternalDiscoveryTask,
    ) -> Result<(), Self::Error>;

    async fn pir_witness(&mut self, task: WitnessTask) -> Result<(), Self::Error>;
}

pub trait ManagedOrchardSync {
    type Error;

    fn run_once<S, D, N>(
        store: &mut S,
        data_source: &mut D,
        notifier: &mut N,
        viewing_keys: &[UnifiedFullViewingKey],
        limits: ManagedSyncLimits,
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>
    where
        S: OrchardSyncStore,
        D: OrchardSyncDataSource,
        N: OrchardSyncNotifier;
}
