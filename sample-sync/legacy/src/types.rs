use async_trait::async_trait;

use zcash_client_backend::{
    data_api::{
        TransactionDataRequest, TransactionStatus,
        chain::{ChainState, ScanSummary},
        scanning::ScanRange,
    },
    proto::compact_formats::CompactBlock,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::{block::BlockHash, transaction::Transaction};
use zcash_protocol::{consensus::BlockHeight, value::Zatoshis};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainTip {
    pub height: BlockHeight,
    pub hash: BlockHash,
}

#[derive(Clone, Debug, PartialEq)]
pub struct RawTransaction {
    pub mined_height: Option<BlockHeight>,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyBalance {
    pub transparent: Zatoshis,
    pub sapling: Zatoshis,
    pub orchard: Zatoshis,
    pub transparent_pending: Zatoshis,
    pub sapling_pending: Zatoshis,
    pub orchard_pending: Zatoshis,
}

impl Default for LegacyBalance {
    fn default() -> Self {
        Self {
            transparent: Zatoshis::ZERO,
            sapling: Zatoshis::ZERO,
            orchard: Zatoshis::ZERO,
            transparent_pending: Zatoshis::ZERO,
            sapling_pending: Zatoshis::ZERO,
            orchard_pending: Zatoshis::ZERO,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncError {
    Network(String),
    Db(String),
    Parse(String),
    Continuity {
        at_height: BlockHeight,
        detail: String,
    },
    Other(String),
}

impl SyncError {
    pub fn continuity(at_height: BlockHeight, detail: impl Into<String>) -> Self {
        Self::Continuity {
            at_height,
            detail: detail.into(),
        }
    }

    pub fn recovery_strategy(&self, rewind_distance: u32) -> RecoveryStrategy {
        match self {
            SyncError::Continuity { at_height, .. } => RecoveryStrategy::Rewind {
                to_height: at_height.saturating_sub(rewind_distance),
            },
            SyncError::Network(_) | SyncError::Other(_) => RecoveryStrategy::Retry,
            SyncError::Db(_) | SyncError::Parse(_) => RecoveryStrategy::Fatal,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStrategy {
    Rewind { to_height: BlockHeight },
    Retry,
    Fatal,
}

/// Chain-tip continuity result before new scan work begins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainTipStatus {
    /// The new tip is compatible with the wallet's currently accepted chain.
    Continue,

    /// The wallet must first roll back facts above `to_height`.
    Rewind { to_height: BlockHeight },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncOptions {
    /// Maximum number of blocks to process in one compact-block scan batch.
    ///
    /// Vizor currently chooses this outside `librustzcash`:
    ///
    /// - foreground desktop sync uses a larger base batch;
    /// - mobile and background sync use smaller batches;
    /// - debug builds may clamp the batch size with an e2e-test environment
    ///   override;
    /// - historical ranges overlapping the mainnet sandblasting attack window
    ///   use a much smaller batch to avoid memory pressure and timeouts.
    ///
    /// This sample stores only the final effective batch size because the
    /// current caller, not `librustzcash`, owns those policy decisions.
    pub batch_size: u32,
    pub rewind_distance: u32,
    pub max_rewinds_per_run: u32,
    pub max_enhancement_rounds: usize,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            batch_size: 1_000,
            rewind_distance: 10,
            max_rewinds_per_run: 3,
            max_enhancement_rounds: 3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgressEvent {
    pub scanned_height: BlockHeight,
    pub chain_tip_height: BlockHeight,
    pub phase: SyncPhase,
    pub has_new_wallet_activity: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncPhase {
    Rollback,
    Download,
    Scan,
    Enhance,
    Complete,
}

#[async_trait]
pub trait LightwalletdLike {
    async fn get_latest_block(&mut self) -> Result<ChainTip, SyncError>;

    async fn download_subtree_roots(&mut self) -> Result<SubtreeRootBatch, SyncError>;

    async fn download_compact_blocks(
        &mut self,
        range: &ScanRange,
    ) -> Result<Vec<CompactBlock>, SyncError>;

    async fn get_tree_state(&mut self, height: BlockHeight) -> Result<ChainState, SyncError>;

    async fn get_transaction(
        &mut self,
        request: &TransactionDataRequest,
    ) -> Result<Option<RawTransaction>, SyncError>;

    async fn transactions_involving_address(
        &mut self,
        request: &TransactionDataRequest,
    ) -> Result<Vec<RawTransaction>, SyncError>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubtreeRootBatch {
    pub sapling_roots: Vec<SubtreeRoot>,
    pub orchard_roots: Vec<SubtreeRoot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubtreeRoot {
    pub completing_height: BlockHeight,
    pub root_hash: [u8; 32],
}

/// The legacy wallet database operations used by the current Vizor-style sync.
///
/// In the real code, these are provided by `zcash_client_sqlite::WalletDb`
/// through `WalletRead`, `WalletWrite`, and `WalletCommitmentTrees`.
pub trait LegacyWalletDb {
    fn chain_tip_status(&self, tip: &ChainTip) -> Result<ChainTipStatus, SyncError>;

    fn update_chain_tip(&mut self, tip: &ChainTip) -> Result<(), SyncError>;

    fn put_subtree_roots(&mut self, roots: SubtreeRootBatch) -> Result<(), SyncError>;

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, SyncError>;

    /// Model of the current scan call.
    ///
    /// Today's librustzcash obtains UFVKs through the database. This sample
    /// accepts them explicitly so we can reason about a caller-owned key path
    /// before designing the new Orchard API.
    fn scan_cached_blocks(
        &mut self,
        blocks: &[CompactBlock],
        from_state: &ChainState,
        viewing_keys: &[UnifiedFullViewingKey],
        limit: usize,
    ) -> Result<ScanSummary, SyncError>;

    fn truncate_to_height(&mut self, height: BlockHeight) -> Result<BlockHeight, SyncError>;

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, SyncError>;

    fn decrypt_and_store_transaction(&mut self, tx: RawTransaction) -> Result<(), SyncError>;

    fn set_transaction_status(
        &mut self,
        request: &TransactionDataRequest,
        status: TransactionStatus,
    ) -> Result<(), SyncError>;

    fn get_legacy_balance(&self, account_id: &[u8]) -> Result<LegacyBalance, SyncError>;
}

pub trait ProgressSink {
    fn emit(&mut self, event: ProgressEvent);
}
