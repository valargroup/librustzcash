//! A small executable model of the current Vizor-style wallet sync shape.
//!
//! This crate is intentionally not a production sync engine. It captures the
//! responsibilities that currently sit in the wallet application around
//! `librustzcash`: network fetching, retry policy, batching, progress, full
//! transaction enhancement, rollback decisions, and passing viewing keys into
//! wallet-owned scan routines.
//!
//! The point is to make the current caller/library boundary explicit before
//! designing a replacement Orchard sync API.

mod types;

pub use types::*;

use zcash_client_backend::data_api::{
    TransactionDataRequest, TransactionStatus,
    chain::ScanSummary,
    scanning::{ScanPriority, ScanRange},
};
use zcash_keys::keys::UnifiedFullViewingKey;

/// Runs the current Vizor-style sync shape against abstract client and DB
/// interfaces.
///
/// This function shows the current caller/library boundary:
///
/// - the caller owns network fetches, batching, retry, progress, and rollback
///   decisions;
/// - the legacy database owns scan range scheduling;
/// - `scan_cached_blocks` performs both note discovery and witness/tree updates;
/// - transaction enhancement is a separate queue-draining pass.
pub async fn run_current_vizor_style_sync<C, D, P>(
    client: &mut C,
    db: &mut D,
    viewing_keys: &[UnifiedFullViewingKey],
    progress: &mut P,
    options: SyncOptions,
) -> Result<(), SyncError>
where
    C: LightwalletdLike + Send,
    D: LegacyWalletDb + Send,
    P: ProgressSink,
{
    let tip = client.get_latest_block().await?;
    // NOTE: The current legacy sync path does not quite work like this. Today,
    // `update_chain_tip` is mostly height-oriented, and rollback is commonly
    // discovered later when scanning detects block continuity failure. The new
    // architecture should make this chain-tip continuity check explicit here,
    // before compact block fetch and scan work proceed.
    match db.chain_tip_status(&tip)? {
        ChainTipStatus::Continue => {}
        ChainTipStatus::Rewind { to_height } => {
            progress.emit(ProgressEvent {
                scanned_height: to_height,
                chain_tip_height: tip.height,
                phase: SyncPhase::Rollback,
                has_new_wallet_activity: false,
            });
            db.truncate_to_height(to_height)?;
            // Wallet/UI notification boundary:
            // A chain-tip conflict can invalidate state before normal scan
            // work begins. Balances, mined transaction status, and witnesses
            // should be treated as stale after this rollback commits.
        }
    }

    db.update_chain_tip(&tip)?;
    // Wallet/UI notification boundary:
    // The wallet can emit "known chain tip changed" after this DB write
    // commits. In the current Vizor shape this is usually reflected via
    // progress events or balance/history reads, not as a distinct DB event.

    let roots = client.download_subtree_roots().await?;
    db.put_subtree_roots(roots)?;
    // Wallet/UI notification boundary:
    // Subtree root ingestion changes witness/spendability possibilities but
    // does not itself mean new wallet activity was found. Prefer exposing this
    // as sync-state/progress data rather than a "new transaction" notification.

    run_legacy_sync_core_loop(client, db, viewing_keys, progress, &tip, options).await
}

/// Runs the current legacy scan loop after setup has completed.
///
/// This models the core loop currently owned by the wallet:
///
/// 1. Ask the DB for scan ranges via [`LegacyWalletDb::suggest_scan_ranges`].
/// 2. Pick the first range that is not ignored and not already scanned.
/// 3. Split that range to the configured batch size.
/// 4. Fetch compact blocks and the tree state for the block before the batch.
/// 5. Call [`LegacyWalletDb::scan_cached_blocks`].
/// 6. Drain the full-transaction enhancement queue.
///
/// The important architectural issue is that step 5 mixes note discovery,
/// nullifier/spend discovery, note commitment tree advancement, witness
/// updates, and scan queue mutation.
pub async fn run_legacy_sync_core_loop<C, D, P>(
    client: &mut C,
    db: &mut D,
    viewing_keys: &[UnifiedFullViewingKey],
    progress: &mut P,
    tip: &ChainTip,
    options: SyncOptions,
) -> Result<(), SyncError>
where
    C: LightwalletdLike + Send,
    D: LegacyWalletDb + Send,
    P: ProgressSink,
{
    let mut rewinds_this_run = 0;

    loop {
        let Some(scan_range) = next_scan_range(db)? else {
            progress.emit(ProgressEvent {
                scanned_height: tip.height,
                chain_tip_height: tip.height,
                phase: SyncPhase::Complete,
                has_new_wallet_activity: false,
            });
            return Ok(());
        };

        let batch = first_batch(&scan_range, options.batch_size);
        if batch.is_empty() {
            return Err(SyncError::Other("empty scan batch".into()));
        }

        progress.emit(ProgressEvent {
            scanned_height: batch.block_range().start,
            chain_tip_height: tip.height,
            phase: SyncPhase::Download,
            has_new_wallet_activity: false,
        });

        let blocks = client.download_compact_blocks(&batch).await?;
        let from_state = client.get_tree_state(batch.block_range().start - 1).await?;

        progress.emit(ProgressEvent {
            scanned_height: batch.block_range().start,
            chain_tip_height: tip.height,
            phase: SyncPhase::Scan,
            has_new_wallet_activity: false,
        });

        let scan_summary = match db.scan_cached_blocks(
            &blocks,
            &from_state,
            viewing_keys,
            options.batch_size as usize,
        ) {
            Ok(summary) => summary,
            Err(err) => match err.recovery_strategy(options.rewind_distance) {
                RecoveryStrategy::Rewind { to_height } => {
                    if rewinds_this_run >= options.max_rewinds_per_run {
                        return Err(err);
                    }

                    rewinds_this_run += 1;
                    db.truncate_to_height(to_height)?;
                    // Wallet/UI notification boundary:
                    // A rewind can invalidate balances, transaction mined
                    // status, and witnesses. The caller should notify the
                    // wallet that visible state may have moved backwards and
                    // that cached balance/history views should be refreshed.
                    continue;
                }
                RecoveryStrategy::Retry | RecoveryStrategy::Fatal => return Err(err),
            },
        };
        // Wallet/UI notification boundary:
        // `scan_cached_blocks` is the main legacy state transition. Once it
        // commits, newly discovered notes, spends, witness updates, scan queue
        // changes, and balance changes may all be visible. This is where the
        // caller should emit progress and "new wallet activity" notifications.

        progress.emit(ProgressEvent {
            scanned_height: batch.block_range().end,
            chain_tip_height: tip.height,
            phase: SyncPhase::Enhance,
            has_new_wallet_activity: has_new_wallet_activity(&scan_summary),
        });

        run_legacy_enhancement(client, db, options.max_enhancement_rounds).await?;
        // Wallet/UI notification boundary:
        // Enhancement can add memos, raw transaction bytes, transparent
        // details, fee information, and additional received/spent outputs.
        // The caller should refresh transaction detail/history after this
        // phase, even if the scan summary did not count new compact activity.
    }
}

fn next_scan_range<D: LegacyWalletDb>(db: &D) -> Result<Option<ScanRange>, SyncError> {
    Ok(db
        .suggest_scan_ranges()?
        .into_iter()
        .find(|range| needs_work(range.priority())))
}

fn first_batch(range: &ScanRange, batch_size: u32) -> ScanRange {
    if let Some((cur, _next)) = range.split_at(range.block_range().start + batch_size) {
        cur
    } else {
        range.clone()
    }
}

fn needs_work(priority: ScanPriority) -> bool {
    !matches!(priority, ScanPriority::Ignored | ScanPriority::Scanned)
}

fn has_new_wallet_activity(summary: &ScanSummary) -> bool {
    summary.received_sapling_note_count() > 0
        || summary.spent_sapling_note_count() > 0
        || summary.received_orchard_note_count() > 0
        || summary.spent_orchard_note_count() > 0
}

/// Drains the legacy full-transaction enhancement queue.
///
/// This is the current pattern:
///
/// 1. Read DB-generated requests.
/// 2. Fetch data from lightwalletd.
/// 3. Feed raw data back into the DB.
/// 4. Repeat because storing one full transaction may enqueue more work.
pub async fn run_legacy_enhancement<C, D>(
    client: &mut C,
    db: &mut D,
    max_rounds: usize,
) -> Result<(), SyncError>
where
    C: LightwalletdLike + Send,
    D: LegacyWalletDb + Send,
{
    for _ in 0..max_rounds {
        let requests = db.transaction_data_requests()?;
        if requests.is_empty() {
            break;
        }

        let actionable = requests.iter().any(is_actionable_request);
        if !actionable {
            break;
        }

        for request in requests {
            match &request {
                TransactionDataRequest::GetStatus(_) => {
                    match client.get_transaction(&request).await {
                        Ok(Some(tx)) => db.set_transaction_status(
                            &request,
                            tx.mined_height
                                .map(TransactionStatus::Mined)
                                .unwrap_or(TransactionStatus::NotInMainChain),
                        )?,
                        Ok(None) => {
                            db.set_transaction_status(&request, TransactionStatus::NotInMainChain)?
                        }
                        Err(SyncError::Network(message)) if message.contains("not found") => db
                            .set_transaction_status(
                                &request,
                                TransactionStatus::TxidNotRecognized,
                            )?,
                        Err(err) => return Err(err),
                    }
                }

                TransactionDataRequest::Enhancement(_) => {
                    match client.get_transaction(&request).await {
                        Ok(Some(tx)) => db.decrypt_and_store_transaction(tx)?,
                        Ok(None) => {
                            db.set_transaction_status(&request, TransactionStatus::NotInMainChain)?
                        }
                        Err(SyncError::Network(message)) if message.contains("not found") => db
                            .set_transaction_status(
                                &request,
                                TransactionStatus::TxidNotRecognized,
                            )?,
                        Err(err) => return Err(err),
                    }
                }

                TransactionDataRequest::TransactionsInvolvingAddress(_) => {
                    for tx in client.transactions_involving_address(&request).await? {
                        db.decrypt_and_store_transaction(tx)?;
                    }
                }
            }
        }
    }

    // Wallet/UI notification boundary:
    // This function intentionally does not emit notifications itself. It is a
    // queue-draining helper; the orchestration layer should notify once after
    // the enhancement round so the UI does not refresh for every individual
    // transaction write.
    Ok(())
}

fn is_actionable_request(request: &TransactionDataRequest) -> bool {
    match request {
        TransactionDataRequest::GetStatus(_) | TransactionDataRequest::Enhancement(_) => true,
        TransactionDataRequest::TransactionsInvolvingAddress(req) => {
            req.block_range_end().is_some()
        }
    }
}

/// Shows the current legacy balance call shape.
///
/// The DB computes these values from its wallet summary. The caller is only
/// reading the latest committed snapshot; if sync is in progress, this may lag
/// behind downloaded-but-unscanned blocks.
pub fn get_current_legacy_balance<D: LegacyWalletDb>(
    db: &D,
    account_id: &[u8],
) -> Result<LegacyBalance, SyncError> {
    db.get_legacy_balance(account_id)
}
