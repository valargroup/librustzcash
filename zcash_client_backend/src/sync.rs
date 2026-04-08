//! Implementation of the synchronization flow described in the crate root.
//!
//! This is currently a simple implementation that does not yet implement a few features:
//!
//! - Block batches are not downloaded in parallel with scanning.
//! - There is no mechanism for notifying the caller of progress updates.
//! - There is no mechanism for interrupting the synchronization flow, other than ending
//!   the process.
//!
//! This helper now also services queued transaction-data requests so that compact scanning,
//! transaction enhancement, and transparent history discovery can converge to a complete wallet
//! history during recovery.

use std::fmt;

#[cfg(feature = "transparent-inputs")]
use std::collections::BTreeSet;

use futures_util::TryStreamExt;
use shardtree::error::ShardTreeError;
use subtle::ConditionallySelectable;
use tonic::{
    body::Body as TonicBody,
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use tracing::{debug, info};

use zcash_primitives::{
    merkle_tree::HashSer,
    transaction::{Transaction, TransactionData, TxId},
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};

use crate::{
    data_api::{
        TransactionDataRequest, TransactionStatus, WalletCommitmentTrees, WalletRead, WalletWrite,
        chain::{
            BlockCache, ChainState, CommitmentTreeRoot, error::Error as ChainError,
            scan_cached_blocks,
        },
        ll::wallet::PRUNING_DEPTH,
        scanning::{ScanPriority, ScanRange},
    },
    decrypt::{
        TxBundlePositions, collect_wallet_note_positions, compute_enriched_outputs,
        decrypt_transaction,
    },
    proto::service::{
        self, BlockId, TxFilter, compact_tx_streamer_client::CompactTxStreamerClient,
    },
    scanning::ScanError,
};

#[cfg(feature = "transparent-inputs")]
use crate::{
    data_api::{OutputStatusFilter, TransactionStatusFilter},
    proto::service::TransparentAddressBlockFilter,
};

#[cfg(feature = "orchard")]
use orchard::tree::MerkleHashOrchard;

#[cfg(feature = "transparent-inputs")]
use {
    crate::wallet::WalletTransparentOutput,
    ::transparent::{
        address::Script,
        bundle::{OutPoint, TxOut},
    },
    zcash_keys::encoding::AddressCodec as _,
    zcash_protocol::value::Zatoshis,
    zcash_script::script,
};

/// Scans the chain until the wallet is up-to-date.
pub async fn run<P, ChT, CaT, DbT>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
) -> Result<(), Error<CaT::Error, <DbT as WalletRead>::Error, <DbT as WalletCommitmentTrees>::Error>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite + WalletCommitmentTrees,
    DbT::AccountId: ConditionallySelectable + Copy + Default + Send + 'static,
    <DbT as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    // 1) Download note commitment tree data from lightwalletd
    // 2) Pass the commitment tree data to the database.
    update_subtree_roots(client, db_data).await?;

    loop {
        while running(client, params, db_cache, db_data, batch_size).await? {}

        let outcome = service_transaction_data_requests(client, params, db_data).await?;

        // Only prune the tracked-nullifier map if the request queue fully
        // drained. The contract on `WalletWrite::prune_tracked_nullifiers`
        // requires the request queue to be drained first, because pruning
        // would otherwise cascade-delete locators that an unresolved
        // enhancement retry will need. If the queue stabilized with
        // unresolved entries, skip pruning entirely — the next sync session
        // will retry once the underlying issue (typically lightwalletd not
        // recognizing a queued txid) clears, and the map size is bounded by
        // the work done during the running() call so growth is finite.
        //
        // This is the only `prune_tracked_nullifiers` call site in the sync
        // module: the per-chunk drain inside `running()` is preserved for
        // its cascade-discovery side effects, but pruning is intentionally
        // hoisted out of `running()` so we can gate it on this drain
        // outcome.
        if matches!(outcome, ServiceOutcome::Drained) {
            db_data
                .prune_tracked_nullifiers(PRUNING_DEPTH)
                .map_err(Error::Wallet)?;
        }

        let scan_done = db_data
            .suggest_scan_ranges()
            .map_err(Error::Wallet)?
            .into_iter()
            .all(|range| range.is_empty());

        if scan_done {
            // No more scan work to do. Break regardless of whether the queue
            // drained or stabilized: any still-pending requests cannot be
            // unblocked by further scanning on this pass, so we have converged
            // as far as this sync run can. A subsequent `run()` call (triggered
            // by new chain-tip data, UI action, etc.) can retry the stabilized
            // requests with fresh state.
            if matches!(outcome, ServiceOutcome::Stabilized) {
                debug!(
                    "sync::run converged with a non-empty but stabilized \
                     transaction-data request queue; deferring to next run"
                );
            }
            break;
        }
        // scan_done == false → loop again. New scanning work may unblock
        // stabilized requests, at which point `service_transaction_data_requests`
        // will progress normally on the next iteration (its `last_requests`
        // local is freshly None on each call).
    }

    Ok(())
}

/// Outcome of a single call to [`service_transaction_data_requests`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceOutcome {
    /// The transaction-data request queue was fully drained.
    Drained,
    /// Two consecutive queue reads returned the same non-empty set of requests
    /// without any successful drain. This typically means lightwalletd does
    /// not recognize the queued txid(s), or the backend is re-surfacing a
    /// request that we just serviced without state advancing. Further progress
    /// requires new input from elsewhere (scanning a new chunk, chain tip
    /// advancing, etc.).
    Stabilized,
}

async fn running<P, ChT, CaT, DbT, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    batch_size: u32,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Copy + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    // 3) Download chain tip metadata from lightwalletd
    // 4) Notify the wallet of the updated chain tip.
    update_chain_tip(client, db_data).await?;

    // Refresh UTXOs for the accounts in the wallet. We do this before we perform
    // any shielded scanning, to ensure that we discover any UTXOs between the old
    // fully-scanned height and the current chain tip.
    #[cfg(feature = "transparent-inputs")]
    for account_id in db_data.get_account_ids().map_err(Error::Wallet)? {
        let start_height = db_data
            .utxo_query_height(account_id)
            .map_err(Error::Wallet)?;
        info!(
            "Refreshing UTXOs for {:?} from height {}",
            account_id, start_height,
        );
        refresh_utxos(params, client, db_data, account_id, start_height).await?;
    }

    // 5) Get the suggested scan ranges from the wallet database
    let mut scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

    // Store the handles to cached block deletions (which we spawn into separate
    // tasks to allow us to continue downloading and scanning other ranges).
    let mut block_deletions = vec![];

    // 6) Run the following loop until the wallet's view of the chain tip as of
    //    the previous wallet session is valid.
    loop {
        // If there is a range of blocks that needs to be verified, it will always
        // be returned as the first element of the vector of suggested ranges.
        match scan_ranges.first() {
            Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                // Download the blocks in `scan_range` into the block source,
                // overwriting any existing blocks in this range.
                download_blocks(client, db_cache, scan_range).await?;

                let chain_state =
                    download_chain_state(client, scan_range.block_range().start - 1).await?;

                // Scan the downloaded blocks and check for scanning errors that
                // indicate the wallet's chain tip is out of sync with blockchain
                // history.
                let scan_ranges_updated =
                    scan_blocks(params, db_cache, db_data, &chain_state, scan_range).await?;

                // Delete the now-scanned blocks, because keeping the entire chain
                // in CompactBlock files on disk is horrendous for the filesystem.
                block_deletions.push(db_cache.delete(scan_range.clone()));

                // Pruning is intentionally NOT performed here. The verify
                // branch has no local visibility into whether the
                // transaction-data request queue is drained, and pruning
                // without that signal violates the contract on
                // `WalletWrite::prune_tracked_nullifiers`. Instead, the outer
                // `run()` loop calls `service_transaction_data_requests`
                // after `running()` returns and prunes only if the outcome is
                // `ServiceOutcome::Drained`. Verify scans are tip-adjacent
                // and infrequent, so deferring their prune by one stack frame
                // has no observable cost.

                if scan_ranges_updated {
                    // The suggested scan ranges have been updated, so we re-request.
                    scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
                } else {
                    // At this point, the cache and scanned data are locally
                    // consistent (though not necessarily consistent with the
                    // latest chain tip - this would be discovered the next time
                    // this codepath is executed after new blocks are received) so
                    // we can break out of the loop.
                    break;
                }
            }
            _ => {
                // Nothing to verify; break out of the loop
                break;
            }
        }
    }

    // 7) Loop over the remaining suggested scan ranges, retrieving the requested data
    //    and calling `scan_cached_blocks` on each range.
    let scan_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
    debug!("Suggested ranges: {:?}", scan_ranges);
    for scan_range in scan_ranges.into_iter().flat_map(|r| {
        // Limit the number of blocks we download and scan at any one time.
        (0..).scan(r, |acc, _| {
            if acc.is_empty() {
                None
            } else if let Some((cur, next)) = acc.split_at(acc.block_range().start + batch_size) {
                *acc = next;
                Some(cur)
            } else {
                let cur = acc.clone();
                let end = acc.block_range().end;
                *acc = ScanRange::from_parts(end..end, acc.priority());
                Some(cur)
            }
        })
    }) {
        // Capture the chunk's priority before `scan_range` is moved into
        // `db_cache.delete` below; we need it for the post-enhancement
        // priority re-check.
        let chunk_priority = scan_range.priority();

        // Download the blocks in `scan_range` into the block source.
        download_blocks(client, db_cache, &scan_range).await?;

        let chain_state = download_chain_state(client, scan_range.block_range().start - 1).await?;

        // Scan the downloaded blocks.
        let scan_ranges_updated =
            scan_blocks(params, db_cache, db_data, &chain_state, &scan_range).await?;

        // Delete the now-scanned blocks.
        block_deletions.push(db_cache.delete(scan_range));

        // Drain enhancement requests generated by this chunk.
        //
        // This is what makes the External-only batch scanning optimization
        // correct under chunked sync: change notes (Internal-IVK) are
        // discovered here via `decrypt_transaction` on the full transaction
        // bytes, and `detect_*_spend` consults the nullifier map (still
        // intact because `put_blocks` no longer prunes, and pruning is
        // gated on a Drained outcome in the outer `run()` loop) to link
        // those change notes to their spending transactions. Change notes
        // written to `received_notes` here will also be picked up
        // automatically by the next chunk's `scan_cached_blocks`, whose
        // in-memory `Nullifiers` set is rebuilt from the database at the
        // top of each call — this handles the cross-chunk forward cascade
        // without needing the nullifier map.
        //
        // The return value is intentionally ignored at this site: the
        // intra-chunk drain runs purely for its cascade-discovery side
        // effects. The decision of whether it is safe to prune the
        // nullifier map lives in `run()`, gated on the outcome of the
        // post-`running()` drain — if THAT one stabilizes, pruning is
        // skipped, regardless of any per-chunk drain outcomes here.
        service_transaction_data_requests(client, params, db_data).await?;

        if scan_ranges_updated {
            // The suggested scan ranges have been updated (either due to a continuity
            // error or because a higher priority range has been added).
            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await.map_err(Error::Cache)?;
            }
            return Ok(true);
        }

        // Enhancement may have extended scan ranges via
        // `notify_wallet_note_positions` → `scan_complete` → `extend_range`,
        // creating new `FoundNote`-priority ranges for blocks adjacent to
        // newly-discovered change-note positions. If any such range now
        // outranks the current chunk's priority, bail out to the outer loop
        // so the higher-priority ranges get processed first. Without this
        // re-check, we would only notice the new ranges on the next outer
        // pass, which could leave chunks of a single logical scan range
        // processing in mixed priority order.
        let latest_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;
        if latest_ranges
            .first()
            .is_some_and(|next| next.priority() > chunk_priority)
        {
            info!("Waiting for cached blocks to be deleted...");
            for deletion in block_deletions {
                deletion.await.map_err(Error::Cache)?;
            }
            return Ok(true);
        }
    }

    info!("Waiting for cached blocks to be deleted...");
    for deletion in block_deletions {
        deletion.await.map_err(Error::Cache)?;
    }
    Ok(false)
}

/// Drains the wallet's [`TransactionDataRequest`] queue until no more requests remain or
/// progress has stalled.
///
/// This is the post-scan phase that recovers information which compact-block scanning could
/// not surface directly: change notes (via the enhancement path, which decrypts full
/// transactions under all key scopes), mempool/unmined transaction statuses, and transparent
/// address history.
///
/// Returns [`ServiceOutcome::Drained`] when the queue empties, or
/// [`ServiceOutcome::Stabilized`] when two consecutive queue reads return the same
/// non-empty set without progress. The caller (`run`) uses the outcome to decide whether
/// to break out of the outer sync loop.
async fn service_transaction_data_requests<P, ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_data: &mut DbT,
) -> Result<ServiceOutcome, Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::AccountId: Copy + ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    // Drain the transaction-data request queue, re-requesting each iteration because
    // servicing a request may itself queue new requests (e.g. enhancement of tx A
    // discovering a spend whose cascade queues tx B). We terminate either when the
    // queue is empty (Drained) or when two consecutive iterations return the same
    // non-empty set of requests (Stabilized). The latter prevents us from looping
    // forever when a backend repeatedly surfaces the same request without it being
    // successfully serviced (for example, when the upstream lightwalletd does not
    // have the tx).
    let mut last_requests: Option<Vec<TransactionDataRequest>> = None;

    loop {
        let requests = db_data.transaction_data_requests().map_err(Error::Wallet)?;
        if requests.is_empty() {
            return Ok(ServiceOutcome::Drained);
        }

        if last_requests.as_ref() == Some(&requests) {
            debug!(
                "Transaction-data requests stabilized without draining; deferring remaining work"
            );
            return Ok(ServiceOutcome::Stabilized);
        }
        last_requests = Some(requests.clone());

        for request in requests {
            service_transaction_data_request(client, params, db_data, request).await?;
        }
    }
}

/// Services a single [`TransactionDataRequest`], fetching any needed data from the
/// lightwalletd server and committing it to the wallet.
async fn service_transaction_data_request<P, ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_data: &mut DbT,
    request: TransactionDataRequest,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::AccountId: Copy + ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    match request {
        TransactionDataRequest::GetStatus(txid) => {
            let status = match fetch_raw_transaction(client, txid).await? {
                Some(raw) => raw_transaction_status(&raw)?,
                None => TransactionStatus::TxidNotRecognized,
            };
            db_data
                .set_transaction_status(txid, status)
                .map_err(Error::Wallet)?;
        }
        TransactionDataRequest::Enhancement(txid) => {
            match fetch_raw_transaction(client, txid).await? {
                Some(raw) => {
                    let status = raw_transaction_status(&raw)?;
                    store_raw_transaction(client, params, db_data, &raw).await?;
                    if !matches!(status, TransactionStatus::Mined(_)) {
                        db_data
                            .set_transaction_status(txid, status)
                            .map_err(Error::Wallet)?;
                    }
                }
                None => db_data
                    .set_transaction_status(txid, TransactionStatus::TxidNotRecognized)
                    .map_err(Error::Wallet)?,
            }
        }
        #[cfg(feature = "transparent-inputs")]
        TransactionDataRequest::TransactionsInvolvingAddress(req) => {
            service_transactions_involving_address(client, params, db_data, req.clone()).await?;
            // Always advance the address-checked cursor after a successful
            // server query, regardless of whether transactions were returned.
            // The semantics of `notify_address_checked` are "we have queried
            // the server over this range," not "we have found something
            // relevant." If the target UTXO was spent in one of the returned
            // transactions, `mark_transparent_utxo_spent` (called from
            // `store_raw_transaction`) has already removed it from the
            // `transparent_spend_search_queue`, so this call is a no-op for
            // that entry. Without this unconditional advancement, an address
            // range that returned only unrelated activity would re-surface
            // forever in `transaction_data_requests()`.
            let checked_height = req.block_range_end().map(|end| end - 1).unwrap_or(
                db_data
                    .chain_height()
                    .map_err(Error::Wallet)?
                    .ok_or(Error::MisbehavingServer)?,
            );
            db_data
                .notify_address_checked(req, checked_height)
                .map_err(Error::Wallet)?;
        }
    }

    Ok(())
}

/// Fetches a single raw transaction by txid from the lightwalletd server.
///
/// Returns `Ok(None)` if the server does not recognize the txid (`tonic::Code::NotFound`).
async fn fetch_raw_transaction<ChT, CaErr, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    txid: TxId,
) -> Result<Option<service::RawTransaction>, Error<CaErr, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    match client
        .get_transaction(TxFilter {
            block: None,
            index: 0,
            hash: txid.as_ref().to_vec(),
        })
        .await
    {
        Ok(response) => Ok(Some(response.into_inner())),
        Err(status) if status.code() == tonic::Code::NotFound => Ok(None),
        Err(status) => Err(Error::Server(status)),
    }
}

/// Classifies a [`service::RawTransaction`] as [`TransactionStatus::Mined`] or
/// [`TransactionStatus::NotInMainChain`] based on its `height` field.
///
/// lightwalletd uses `0` or `u64::MAX` to indicate "not mined"; any other value is the
/// block height at which the transaction was mined.
fn raw_transaction_status<CaErr, DbErr, TrErr>(
    raw: &service::RawTransaction,
) -> Result<TransactionStatus, Error<CaErr, DbErr, TrErr>> {
    if raw.height == 0 || raw.height == u64::MAX {
        Ok(TransactionStatus::NotInMainChain)
    } else {
        BlockHeight::try_from(raw.height)
            .map(TransactionStatus::Mined)
            .map_err(|_| Error::MisbehavingServer)
    }
}

/// Parses a [`service::RawTransaction`] into a [`Transaction`] tagged with its mined height
/// (if any), choosing the correct consensus branch ID.
///
/// For mined transactions the branch ID is derived from the mined height. For unmined
/// transactions the expiry height is used as a proxy (after a two-step parse/re-freeze
/// because `Transaction::read` needs a branch ID up front but pre-v5 transactions don't
/// commit to one). Returns `Ok(None)` if the server reported the txid as unknown, or if
/// an unmined transaction has a zero expiry height and no other way to determine the
/// correct branch ID.
#[allow(clippy::type_complexity)]
fn parse_raw_transaction<P, CaErr, DbErr, TrErr>(
    params: &P,
    raw: &service::RawTransaction,
) -> Result<Option<(Option<BlockHeight>, Transaction)>, Error<CaErr, DbErr, TrErr>>
where
    P: Parameters,
{
    let mined_height = match raw_transaction_status(raw)? {
        TransactionStatus::Mined(height) => Some(height),
        TransactionStatus::NotInMainChain => None,
        TransactionStatus::TxidNotRecognized => return Ok(None),
    };

    let tx = if let Some(height) = mined_height {
        Transaction::read(&raw.data[..], BranchId::for_height(params, height))
            .map_err(|_| Error::MisbehavingServer)?
    } else {
        let tx_data = Transaction::read(&raw.data[..], BranchId::Sprout)
            .map_err(|_| Error::MisbehavingServer)?
            .into_data();
        let expiry_height = tx_data.expiry_height();
        if expiry_height == BlockHeight::from(0) {
            return Ok(None);
        }

        TransactionData::from_parts(
            tx_data.version(),
            BranchId::for_height(params, expiry_height),
            tx_data.lock_time(),
            expiry_height,
            #[cfg(all(
                any(zcash_unstable = "nu7", zcash_unstable = "zfuture"),
                feature = "zip-233"
            ))]
            tx_data.zip233_amount(),
            tx_data.transparent_bundle().cloned(),
            tx_data.sprout_bundle().cloned(),
            tx_data.sapling_bundle().cloned(),
            tx_data.orchard_bundle().cloned(),
        )
        .freeze()
        .map_err(|_| Error::MisbehavingServer)?
    };

    Ok(Some((mined_height, tx)))
}

/// Decrypts a raw transaction, enriches its outputs with nullifier and commitment-tree
/// position metadata, stores the result in the wallet, and notifies the wallet of any
/// newly-discovered note positions so that witnesses can be maintained.
///
/// This is the core of the enhancement path: scanning only uses External-scope keys, so
/// change notes are only recovered here (via `decrypt_transaction`, which tries all key
/// scopes) and need their commitment-tree positions and nullifiers populated before being
/// handed to `store_decrypted_tx`.
async fn store_raw_transaction<P, ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_data: &mut DbT,
    raw: &service::RawTransaction,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::AccountId: Copy + ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let Some((mined_height, tx)) = parse_raw_transaction(params, raw)? else {
        return Ok(());
    };

    let ufvks = db_data
        .get_unified_full_viewing_keys()
        .map_err(Error::Wallet)?;
    let chain_tip_height = db_data.chain_height().map_err(Error::Wallet)?;
    let d_tx = decrypt_transaction(params, mined_height, chain_tip_height, &tx, &ufvks);
    let d_tx = enrich_decrypted_transaction(client, params, db_data, &tx, d_tx, &ufvks).await?;
    let wallet_note_positions = collect_wallet_note_positions(&d_tx);
    db_data.store_decrypted_tx(d_tx).map_err(Error::Wallet)?;
    if let Some(height) = mined_height {
        if !wallet_note_positions.is_empty() {
            db_data
                .notify_wallet_note_positions(height..height + 1, &wallet_note_positions)
                .map_err(Error::Wallet)?;
        }
    }
    Ok(())
}

/// Enriches a [`crate::data_api::DecryptedTransaction`] with nullifier metadata and
/// commitment-tree positions by fetching the transaction's bundle base positions from
/// lightwalletd.
///
/// For mined transactions that have a shielded bundle, this calls
/// [`fetch_tx_bundle_positions`] to derive the starting position of the tx's bundle
/// within the global note commitment tree, then delegates to [`compute_enriched_outputs`]
/// which uses those bases to populate per-output positions and nullifiers. For unmined
/// transactions (or pure-transparent txs with no shielded bundle) the position lookup is
/// skipped; Sapling outputs remain without nullifiers, but Orchard outputs still get
/// nullifiers because Orchard nullifier computation does not depend on tree position.
async fn enrich_decrypted_transaction<'a, P, ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    _params: &P,
    db_data: &DbT,
    tx: &'a Transaction,
    d_tx: crate::data_api::DecryptedTransaction<'a, Transaction, DbT::AccountId>,
    ufvks: &std::collections::HashMap<DbT::AccountId, zcash_keys::keys::UnifiedFullViewingKey>,
) -> Result<
    crate::data_api::DecryptedTransaction<'a, Transaction, DbT::AccountId>,
    Error<CaErr, DbT::Error, TrErr>,
>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletRead,
    DbT::AccountId: Copy + ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let txid = tx.txid();
    let positions = match d_tx.mined_height() {
        Some(height)
            if d_tx.tx().sapling_bundle().is_some() || {
                #[cfg(feature = "orchard")]
                {
                    d_tx.tx().orchard_bundle().is_some()
                }
                #[cfg(not(feature = "orchard"))]
                {
                    false
                }
            } =>
        {
            Some(fetch_tx_bundle_positions(client, db_data, height, txid).await?)
        }
        _ => None,
    };

    Ok(compute_enriched_outputs(
        tx,
        &d_tx,
        positions.as_ref(),
        ufvks,
    ))
}

/// Fetches the compact block containing `txid` at `height` and computes the starting
/// position of that transaction's Sapling (and Orchard, if enabled) bundle within each
/// global note commitment tree.
///
/// For the height-minus-one tree sizes we prefer `block_metadata` from the wallet (the
/// fast path under normal sync), falling back to `download_chain_state` from lightwalletd
/// when the metadata isn't available (e.g. enhancement of a tx in a block the wallet
/// hasn't yet scanned contiguously up to).
async fn fetch_tx_bundle_positions<ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &DbT,
    height: BlockHeight,
    txid: TxId,
) -> Result<TxBundlePositions, Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletRead,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let mut stream = client
        .get_block_range(service::BlockRange {
            start: Some(BlockId {
                height: u32::from(height).into(),
                hash: vec![],
            }),
            end: Some(BlockId {
                height: u32::from(height).into(),
                hash: vec![],
            }),
            pool_types: vec![],
        })
        .await?
        .into_inner();
    let block = stream
        .try_next()
        .await
        .map_err(Error::Server)?
        .ok_or(Error::MisbehavingServer)?;

    let tx_index = block
        .vtx
        .iter()
        .position(|tx| tx.txid() == txid)
        .ok_or(Error::MisbehavingServer)?;

    let prior_sapling_tree_size = if height == BlockHeight::from(0) {
        0
    } else if let Some(meta) = db_data.block_metadata(height - 1).map_err(Error::Wallet)? {
        meta.sapling_tree_size().map(u64::from).unwrap_or(0)
    } else {
        download_chain_state(client, height - 1)
            .await?
            .final_sapling_tree()
            .tree_size()
    };

    #[cfg(feature = "orchard")]
    let prior_orchard_tree_size = if height == BlockHeight::from(0) {
        0
    } else if let Some(meta) = db_data.block_metadata(height - 1).map_err(Error::Wallet)? {
        meta.orchard_tree_size().map(u64::from).unwrap_or(0)
    } else {
        download_chain_state(client, height - 1)
            .await?
            .final_orchard_tree()
            .tree_size()
    };

    Ok(TxBundlePositions {
        sapling_base: Some(
            prior_sapling_tree_size
                + block.vtx[..tx_index]
                    .iter()
                    .map(|tx| tx.outputs.len() as u64)
                    .sum::<u64>(),
        ),
        #[cfg(feature = "orchard")]
        orchard_base: Some(
            prior_orchard_tree_size
                + block.vtx[..tx_index]
                    .iter()
                    .map(|tx| tx.actions.len() as u64)
                    .sum::<u64>(),
        ),
    })
}

/// Services a [`TransactionDataRequest::TransactionsInvolvingAddress`] request by
/// querying lightwalletd for transactions touching the requested address in the requested
/// block range, and storing each result via [`store_raw_transaction`].
///
/// The two output-status filters use different gRPC endpoints:
/// `OutputStatusFilter::All` uses `get_taddress_transactions` (streams all transactions
/// touching the address); `OutputStatusFilter::Unspent` uses `get_address_utxos_stream`
/// plus per-txid lookups (as the UTXO endpoint does not return full transactions).
///
/// The caller is responsible for invoking `notify_address_checked` after this function
/// returns successfully, regardless of whether any transactions were found, so that the
/// per-output `max_observed_unspent_height` cursor advances and the request stops
/// re-surfacing.
#[cfg(feature = "transparent-inputs")]
async fn service_transactions_involving_address<P, ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    params: &P,
    db_data: &mut DbT,
    request: crate::data_api::TransactionsInvolvingAddress,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::AccountId: Copy + ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let chain_tip = db_data
        .chain_height()
        .map_err(Error::Wallet)?
        .ok_or(Error::MisbehavingServer)?;
    let end_height_exclusive = request.block_range_end().unwrap_or(chain_tip + 1);
    if end_height_exclusive <= request.block_range_start() {
        return Ok(());
    }

    match request.output_status_filter() {
        OutputStatusFilter::All => {
            if matches!(request.tx_status_filter(), TransactionStatusFilter::Mempool) {
                return Ok(());
            }

            let mut stream = client
                .get_taddress_transactions(TransparentAddressBlockFilter {
                    address: request.address().encode(params),
                    range: Some(service::BlockRange {
                        start: Some(BlockId {
                            height: u32::from(request.block_range_start()).into(),
                            hash: vec![],
                        }),
                        end: Some(BlockId {
                            height: u32::from(end_height_exclusive - 1).into(),
                            hash: vec![],
                        }),
                        pool_types: vec![],
                    }),
                })
                .await?
                .into_inner();
            while let Some(raw) = stream.try_next().await.map_err(Error::Server)? {
                store_raw_transaction(client, params, db_data, &raw).await?;
            }
        }
        OutputStatusFilter::Unspent => {
            let mut stream = client
                .get_address_utxos_stream(service::GetAddressUtxosArg {
                    addresses: vec![request.address().encode(params)],
                    start_height: request.block_range_start().into(),
                    max_entries: 0,
                })
                .await?
                .into_inner();
            let mut txids = BTreeSet::new();
            while let Some(reply) = stream.try_next().await.map_err(Error::Server)? {
                let height =
                    BlockHeight::try_from(reply.height).map_err(|_| Error::MisbehavingServer)?;
                if height < end_height_exclusive {
                    txids.insert(
                        reply.txid[..]
                            .try_into()
                            .map(TxId::from_bytes)
                            .map_err(|_| Error::MisbehavingServer)?,
                    );
                }
            }

            for txid in &txids {
                if let Some(raw) = fetch_raw_transaction(client, *txid).await? {
                    store_raw_transaction(client, params, db_data, &raw).await?;
                }
            }
        }
    }

    Ok(())
}

async fn update_subtree_roots<ChT, DbT, CaErr, DbErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, DbErr, <DbT as WalletCommitmentTrees>::Error>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletCommitmentTrees,
    <DbT as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
{
    let mut request = service::GetSubtreeRootsArg::default();
    request.set_shielded_protocol(service::ShieldedProtocol::Sapling);

    let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
        .get_subtree_roots(request)
        .await?
        .into_inner()
        .and_then(|root| async move {
            let root_hash = sapling::Node::read(&root.root_hash[..])?;
            Ok(CommitmentTreeRoot::from_parts(
                BlockHeight::from_u32(root.completing_block_height as u32),
                root_hash,
            ))
        })
        .try_collect()
        .await?;

    info!("Sapling tree has {} subtrees", sapling_roots.len());
    db_data
        .put_sapling_subtree_roots(0, &sapling_roots)
        .map_err(Error::WalletTrees)?;

    #[cfg(feature = "orchard")]
    {
        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(service::ShieldedProtocol::Orchard);

        let orchard_roots: Vec<CommitmentTreeRoot<MerkleHashOrchard>> = client
            .get_subtree_roots(request)
            .await?
            .into_inner()
            .and_then(|root| async move {
                let root_hash = MerkleHashOrchard::read(&root.root_hash[..])?;
                Ok(CommitmentTreeRoot::from_parts(
                    BlockHeight::from_u32(root.completing_block_height as u32),
                    root_hash,
                ))
            })
            .try_collect()
            .await?;

        info!("Orchard tree has {} subtrees", orchard_roots.len());
        db_data
            .put_orchard_subtree_roots(0, &orchard_roots)
            .map_err(Error::WalletTrees)?;
    }

    Ok(())
}

async fn update_chain_tip<ChT, DbT, CaErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let tip_height: BlockHeight = client
        .get_latest_block(service::ChainSpec::default())
        .await?
        .get_ref()
        .height
        .try_into()
        .map_err(|_| Error::MisbehavingServer)?;

    info!("Latest block height is {}", tip_height);
    db_data
        .update_chain_tip(tip_height)
        .map_err(Error::Wallet)?;

    Ok(())
}

async fn download_blocks<ChT, CaT, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    db_cache: &CaT,
    scan_range: &ScanRange,
) -> Result<(), Error<CaT::Error, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Fetching {}", scan_range);
    let mut start = service::BlockId::default();
    start.height = scan_range.block_range().start.into();
    let mut end = service::BlockId::default();
    end.height = (scan_range.block_range().end - 1).into();
    let range = service::BlockRange {
        start: Some(start),
        end: Some(end),
        pool_types: vec![],
    };
    let compact_blocks = client
        .get_block_range(range)
        .await?
        .into_inner()
        .try_collect::<Vec<_>>()
        .await?;

    db_cache
        .insert(compact_blocks)
        .await
        .map_err(Error::Cache)?;

    Ok(())
}

async fn download_chain_state<ChT, CaErr, DbErr, TrErr>(
    client: &mut CompactTxStreamerClient<ChT>,
    block_height: BlockHeight,
) -> Result<ChainState, Error<CaErr, DbErr, TrErr>>
where
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
{
    let tree_state = client
        .get_tree_state(BlockId {
            height: block_height.into(),
            hash: vec![],
        })
        .await?;

    tree_state
        .into_inner()
        .to_chain_state()
        .map_err(|_| Error::MisbehavingServer)
}

/// Scans the given block range and checks for scanning errors that indicate the wallet's
/// chain tip is out of sync with blockchain history.
///
/// Returns `true` if scanning these blocks materially changed the suggested scan ranges.
async fn scan_blocks<P, CaT, DbT, TrErr>(
    params: &P,
    db_cache: &CaT,
    db_data: &mut DbT,
    initial_chain_state: &ChainState,
    scan_range: &ScanRange,
) -> Result<bool, Error<CaT::Error, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    CaT: BlockCache,
    CaT::Error: std::error::Error + Send + Sync + 'static,
    DbT: WalletWrite,
    DbT::AccountId: ConditionallySelectable + Default + Send + 'static,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    info!("Scanning {}", scan_range);
    let scan_result = scan_cached_blocks(
        params,
        db_cache,
        db_data,
        scan_range.block_range().start,
        initial_chain_state,
        scan_range.len(),
    );

    match scan_result {
        Err(ChainError::Scan(err)) if err.is_continuity_error() => {
            // Pick a height to rewind to, which must be at least one block before the
            // height at which the error occurred, but may be an earlier height determined
            // based on heuristics such as the platform, available bandwidth, size of
            // recent CompactBlocks, etc.
            let rewind_height = err.at_height().saturating_sub(10);
            info!(
                "Chain reorg detected at {}, rewinding to {}",
                err.at_height(),
                rewind_height,
            );

            // Rewind to the chosen height.
            db_data
                .truncate_to_height(rewind_height)
                .map_err(Error::Wallet)?;

            // Delete cached blocks from rewind_height onwards.
            //
            // This does imply that assumed-valid blocks will be re-downloaded, but it is
            // also possible that in the intervening time, a chain reorg has occurred that
            // orphaned some of those blocks.
            db_cache
                .truncate(rewind_height)
                .await
                .map_err(Error::Cache)?;

            // The database was truncated, invalidating prior suggested ranges.
            Ok(true)
        }
        Ok(_) => {
            // If scanning these blocks caused a suggested range to be added that has a
            // higher priority than the current range, invalidate the current ranges.
            let latest_ranges = db_data.suggest_scan_ranges().map_err(Error::Wallet)?;

            Ok(if let Some(range) = latest_ranges.first() {
                range.priority() > scan_range.priority()
            } else {
                false
            })
        }
        Err(e) => Err(e.into()),
    }
}

/// Refreshes the given account's view of UTXOs that exist starting at the given height.
///
/// ## Note about UTXO tracking
///
/// (Extracted from [a comment in the Android SDK].)
///
/// We no longer clear UTXOs here, as `WalletDb::put_received_transparent_utxo` now uses
/// an upsert instead of an insert. This means that now-spent UTXOs would previously have
/// been deleted, but now are left in the database (like shielded notes).
///
/// Due to the fact that the `lightwalletd` query only returns _current_ UTXOs, we don't
/// learn about recently-spent UTXOs here, so the transparent balance does not get updated
/// here.
///
/// Instead, when a received shielded note is "enhanced" by downloading the full
/// transaction, we mark any UTXOs spent in that transaction as spent in the database.
/// This relies on two current properties:
/// - UTXOs are only ever spent in shielding transactions.
/// - At least one shielded note from each shielding transaction is always enhanced.
///
/// However, for greater reliability, we may want to alter the Data Access API to support
/// "inferring spentness" from what is _not_ returned as a UTXO, or alternatively fetch
/// TXOs from `lightwalletd` instead of just UTXOs.
///
/// [a comment in the Android SDK]: https://github.com/Electric-Coin-Company/zcash-android-wallet-sdk/blob/855204fc8ae4057fdac939f98df4aa38c8e662f1/sdk-lib/src/main/java/cash/z/ecc/android/sdk/block/processor/CompactBlockProcessor.kt#L979-L991
#[cfg(feature = "transparent-inputs")]
async fn refresh_utxos<P, ChT, DbT, CaErr, TrErr>(
    params: &P,
    client: &mut CompactTxStreamerClient<ChT>,
    db_data: &mut DbT,
    account_id: DbT::AccountId,
    start_height: BlockHeight,
) -> Result<(), Error<CaErr, <DbT as WalletRead>::Error, TrErr>>
where
    P: Parameters + Send + 'static,
    ChT: GrpcService<TonicBody>,
    ChT::Error: Into<StdError>,
    ChT::ResponseBody: Body<Data = Bytes> + Send + 'static,
    <ChT::ResponseBody as Body>::Error: Into<StdError> + Send,
    DbT: WalletWrite,
    DbT::Error: std::error::Error + Send + Sync + 'static,
{
    let request = service::GetAddressUtxosArg {
        addresses: db_data
            .get_transparent_receivers(account_id, true, true)
            .map_err(Error::Wallet)?
            .into_keys()
            .map(|addr| addr.encode(params))
            .collect(),
        start_height: start_height.into(),
        max_entries: 0,
    };

    if request.addresses.is_empty() {
        info!("{:?} has no transparent receivers", account_id);
    } else {
        client
            .get_address_utxos_stream(request)
            .await?
            .into_inner()
            .map_err(Error::Server)
            .and_then(|reply| async move {
                WalletTransparentOutput::from_parts(
                    OutPoint::new(
                        reply.txid[..]
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                        reply
                            .index
                            .try_into()
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                    TxOut::new(
                        Zatoshis::from_nonnegative_i64(reply.value_zat)
                            .map_err(|_| Error::MisbehavingServer)?,
                        Script(script::Code(reply.script)),
                    ),
                    Some(
                        BlockHeight::try_from(reply.height)
                            .map_err(|_| Error::MisbehavingServer)?,
                    ),
                )
                .ok_or(Error::MisbehavingServer)
            })
            .try_for_each(|output| {
                let res = db_data.put_received_transparent_utxo(&output).map(|_| ());
                async move { res.map_err(Error::Wallet) }
            })
            .await?;
    }

    Ok(())
}

/// Errors that can occur while syncing.
#[derive(Debug)]
pub enum Error<CaErr, DbErr, TrErr> {
    /// An error while interacting with a [`BlockCache`].
    Cache(CaErr),
    /// The lightwalletd server returned invalid information, and is misbehaving.
    MisbehavingServer,
    /// An error while scanning blocks.
    Scan(ScanError),
    /// An error while communicating with the lightwalletd server.
    Server(tonic::Status),
    /// An error while interacting with a wallet database via [`WalletRead`] or
    /// [`WalletWrite`].
    Wallet(DbErr),
    /// An error while interacting with a wallet database via [`WalletCommitmentTrees`].
    WalletTrees(ShardTreeError<TrErr>),
}

impl<CaErr, DbErr, TrErr> fmt::Display for Error<CaErr, DbErr, TrErr>
where
    CaErr: fmt::Display,
    DbErr: fmt::Display,
    TrErr: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Cache(e) => write!(f, "Error while interacting with block cache: {e}"),
            Error::MisbehavingServer => write!(f, "lightwalletd server is misbehaving"),
            Error::Scan(e) => write!(f, "Error while scanning blocks: {e}"),
            Error::Server(e) => {
                write!(f, "Error while communicating with lightwalletd server: {e}")
            }
            Error::Wallet(e) => write!(f, "Error while interacting with wallet database: {e}"),
            Error::WalletTrees(e) => write!(
                f,
                "Error while interacting with wallet commitment trees: {e}"
            ),
        }
    }
}

impl<CaErr, DbErr, TrErr> std::error::Error for Error<CaErr, DbErr, TrErr>
where
    CaErr: std::error::Error,
    DbErr: std::error::Error,
    TrErr: std::error::Error,
{
}

impl<CaErr, DbErr, TrErr> From<ChainError<DbErr, CaErr>> for Error<CaErr, DbErr, TrErr> {
    fn from(e: ChainError<DbErr, CaErr>) -> Self {
        match e {
            ChainError::Wallet(e) => Error::Wallet(e),
            ChainError::BlockSource(e) => Error::Cache(e),
            ChainError::Scan(e) => Error::Scan(e),
        }
    }
}

impl<CaErr, DbErr, TrErr> From<tonic::Status> for Error<CaErr, DbErr, TrErr> {
    fn from(status: tonic::Status) -> Self {
        Error::Server(status)
    }
}
