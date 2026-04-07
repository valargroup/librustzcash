use std::{collections::HashSet, rc::Rc};

use incrementalmerkletree::Position;
use orchard::{
    keys::Diversifier,
    note::{Note, Nullifier, RandomSeed, Rho},
};
use rusqlite::{Connection, Row, named_params, types::Value};

use zcash_client_backend::{
    DecryptedOutput, TransferType,
    data_api::{
        Account as _, NullifierQuery, TargetValue,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{ReceivedNote, WalletOrchardOutput},
};
use zcash_keys::keys::{UnifiedAddressRequest, UnifiedFullViewingKey};
use zcash_primitives::transaction::TxId;
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
};
use zip32::Scope;

use crate::{AccountRef, AccountUuid, AddressRef, ReceivedNoteId, TxRef, error::SqliteClientError};

use super::{
    KeyScope, common::UnspentNoteMeta, get_account, get_account_ref, memo_repr, upsert_address,
};

/// This trait provides a generalization over shielded output representations.
pub(crate) trait ReceivedOrchardOutput {
    type AccountId;

    fn index(&self) -> usize;
    fn account_id(&self) -> Self::AccountId;
    fn note(&self) -> &Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl<AccountId: Copy> ReceivedOrchardOutput for WalletOrchardOutput<AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *WalletOrchardOutput::account_id(self)
    }
    fn note(&self) -> &Note {
        WalletOrchardOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        WalletOrchardOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(WalletOrchardOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        self.recipient_key_scope()
    }
}

impl<AccountId: Copy> ReceivedOrchardOutput for DecryptedOutput<Note, AccountId> {
    type AccountId = AccountId;

    fn index(&self) -> usize {
        self.index()
    }
    fn account_id(&self) -> Self::AccountId {
        *self.account()
    }
    fn note(&self) -> &orchard::note::Note {
        self.note()
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}

pub(crate) fn to_received_note<P: consensus::Parameters>(
    params: &P,
    row: &Row,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    let note_id = ReceivedNoteId(ShieldedProtocol::Orchard, row.get("id")?);
    let txid = row.get::<_, [u8; 32]>("txid").map(TxId::from_bytes)?;
    let action_index = row.get("action_index")?;
    let diversifier = {
        let d: Vec<_> = row.get("diversifier")?;
        if d.len() != 11 {
            return Err(SqliteClientError::CorruptedData(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0; 11];
        tmp.copy_from_slice(&d);
        Diversifier::from_bytes(tmp)
    };

    let note_value: u64 = row.get::<_, i64>("value")?.try_into().map_err(|_e| {
        SqliteClientError::CorruptedData("Note values must be nonnegative".to_string())
    })?;

    let rho = {
        let rho_bytes: [u8; 32] = row.get("rho")?;
        Option::from(Rho::from_bytes(&rho_bytes))
            .ok_or_else(|| SqliteClientError::CorruptedData("Invalid rho.".to_string()))
    }?;

    let rseed = {
        let rseed_bytes: [u8; 32] = row.get("rseed")?;
        Option::from(RandomSeed::from_bytes(rseed_bytes, &rho)).ok_or_else(|| {
            SqliteClientError::CorruptedData("Invalid Orchard random seed.".to_string())
        })
    }?;

    let note_commitment_tree_position = Position::from(
        u64::try_from(row.get::<_, i64>("commitment_tree_position")?).map_err(|_| {
            SqliteClientError::CorruptedData("Note commitment tree position invalid.".to_string())
        })?,
    );

    let ufvk_str: Option<String> = row.get("ufvk")?;
    let scope_code: Option<i64> = row.get("recipient_key_scope")?;
    let mined_height = row
        .get::<_, Option<u32>>("mined_height")?
        .map(BlockHeight::from);
    let max_shielding_input_height = row
        .get::<_, Option<u32>>("max_shielding_input_height")?
        .map(BlockHeight::from);

    // If we don't have information about the recipient key scope or the ufvk we can't determine
    // which spending key to use. This may be because the received note was associated with an
    // imported viewing key, so we treat such notes as not spendable. Although this method is
    // presently only called using the results of queries where both the ufvk and
    // recipient_key_scope columns are checked to be non-null, this is method is written
    // defensively to account for the fact that both of these are nullable columns in case it
    // is used elsewhere in the future.
    ufvk_str
        .zip(scope_code)
        .map(|(ufvk_str, scope_code)| {
            let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
                .map_err(SqliteClientError::CorruptedData)?;

            let spending_key_scope = zip32::Scope::try_from(KeyScope::decode(scope_code)?)
                .map_err(|_| {
                    SqliteClientError::CorruptedData(format!("Invalid key scope code {scope_code}"))
                })?;

            let recipient = ufvk
                .orchard()
                .map(|fvk| fvk.to_ivk(spending_key_scope).address(diversifier))
                .ok_or_else(|| {
                    SqliteClientError::CorruptedData("Diversifier invalid.".to_owned())
                })?;

            let note = Option::from(Note::from_parts(
                recipient,
                orchard::value::NoteValue::from_raw(note_value),
                rho,
                rseed,
            ))
            .ok_or_else(|| SqliteClientError::CorruptedData("Invalid Orchard note.".to_string()))?;

            Ok(ReceivedNote::from_parts(
                note_id,
                txid,
                action_index,
                note,
                spending_key_scope,
                note_commitment_tree_position,
                mined_height,
                max_shielding_input_height,
            ))
        })
        .transpose()
}

pub(crate) fn get_spendable_orchard_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    txid: &TxId,
    index: u32,
    target_height: TargetHeight,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::get_spendable_note(
        conn,
        params,
        txid,
        index,
        ShieldedProtocol::Orchard,
        target_height,
        to_received_note,
    )
}

pub(crate) fn select_spendable_orchard_notes<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    account: AccountUuid,
    target_value: TargetValue,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqliteClientError> {
    super::common::select_spendable_notes(
        conn,
        params,
        account,
        target_value,
        target_height,
        confirmations_policy,
        exclude,
        ShieldedProtocol::Orchard,
        to_received_note,
    )
}

pub(crate) fn ensure_address<
    T: ReceivedOrchardOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
>(
    conn: &rusqlite::Transaction,
    params: &P,
    output: &T,
    exposure_height: Option<BlockHeight>,
) -> Result<Option<AddressRef>, SqliteClientError> {
    if output.recipient_key_scope() != Some(Scope::Internal) {
        let account = get_account(conn, params, output.account_id())?
            .ok_or(SqliteClientError::AccountUnknown)?;

        let uivk = account.uivk();
        let ivk = uivk
            .orchard()
            .as_ref()
            .expect("uivk decrypted this output.");
        let to = output.note().recipient();
        let diversifier_index = ivk
            .diversifier_index(&to)
            .expect("address corresponds to account");

        let ua = account
            .uivk()
            .address(diversifier_index, UnifiedAddressRequest::ALLOW_ALL)?;
        upsert_address(
            conn,
            params,
            account.internal_id(),
            diversifier_index,
            &ua,
            exposure_height,
            false,
        )
        .map(Some)
    } else {
        Ok(None)
    }
}

pub(crate) fn select_unspent_note_meta(
    conn: &Connection,
    wallet_birthday: BlockHeight,
    anchor_height: BlockHeight,
) -> Result<Vec<UnspentNoteMeta>, SqliteClientError> {
    super::common::select_unspent_note_meta(
        conn,
        ShieldedProtocol::Orchard,
        wallet_birthday,
        anchor_height,
    )
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
///
/// Returns the internal account identifier of the account that received the output.
pub(crate) fn put_received_note<
    T: ReceivedOrchardOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
>(
    conn: &rusqlite::Transaction,
    params: &P,
    output: &T,
    tx_ref: TxRef,
    target_or_mined_height: Option<BlockHeight>,
    spent_in: Option<TxRef>,
) -> Result<AccountRef, SqliteClientError> {
    let account_id = get_account_ref(conn, output.account_id())?;
    let address_id = ensure_address(conn, params, output, target_or_mined_height)?;
    let mut stmt_upsert_received_note = conn.prepare_cached(
        "INSERT INTO orchard_received_notes (
            transaction_id, action_index, account_id, address_id,
            diversifier, value, rho, rseed, memo, nf,
            is_change, commitment_tree_position,
            recipient_key_scope
        )
        VALUES (
            :transaction_id, :action_index, :account_id, :address_id,
            :diversifier, :value, :rho, :rseed, :memo, :nf,
            :is_change, :commitment_tree_position,
            :recipient_key_scope
        )
        ON CONFLICT (transaction_id, action_index) DO UPDATE
        SET account_id = :account_id,
            address_id = :address_id,
            diversifier = :diversifier,
            value = :value,
            rho = :rho,
            rseed = :rseed,
            nf = IFNULL(:nf, nf),
            memo = IFNULL(:memo, memo),
            is_change = MAX(:is_change, is_change),
            commitment_tree_position = IFNULL(:commitment_tree_position, commitment_tree_position),
            recipient_key_scope = :recipient_key_scope
        RETURNING orchard_received_notes.id",
    )?;

    let rseed = output.note().rseed();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    let sql_args = named_params![
        ":transaction_id": tx_ref.0,
        ":action_index": i64::try_from(output.index()).expect("output indices are representable as i64"),
        ":account_id": account_id.0,
        ":address_id": address_id.map(|a| a.0),
        ":diversifier": diversifier.as_array(),
        ":value": output.note().value().inner(),
        ":rho": output.note().rho().to_bytes(),
        ":rseed": &rseed.as_bytes(),
        ":nf": output.nullifier().map(|nf| nf.to_bytes()),
        ":memo": memo_repr(output.memo()),
        ":is_change": output.is_change(),
        ":commitment_tree_position": output.note_commitment_tree_position().map(u64::from),
        ":recipient_key_scope": output.recipient_key_scope().map(|s| KeyScope::from(s).encode()),
    ];

    let received_note_id = stmt_upsert_received_note
        .query_row(sql_args, |row| row.get::<_, i64>(0))
        .map_err(SqliteClientError::from)?;

    // Reconcile: if a provisional PIR note exists at the same tree position,
    // set canonical_note_id and mark it as scanner-discovered so its descendants
    // remain valid. The is_spent flag on the same row is picked up by
    // spent_notes_clause via canonical_note_id.
    #[cfg(feature = "spendability-pir")]
    if let Some(position) = output.note_commitment_tree_position() {
        super::pir_provisional::reconcile_provisional_for_position(
            conn,
            u64::from(position),
            received_note_id,
        )?;
    }

    if let Some(spent_in) = spent_in {
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
             VALUES (:orchard_received_note_id, :transaction_id)
             ON CONFLICT (orchard_received_note_id, transaction_id) DO NOTHING",
            named_params![
                ":orchard_received_note_id": received_note_id,
                ":transaction_id": spent_in.0
            ],
        )?;
    }
    Ok(account_id)
}

/// Retrieves the set of nullifiers for "potentially spendable" Orchard notes that the
/// wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
pub(crate) fn get_orchard_nullifiers(
    conn: &Connection,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, Nullifier)>, SqliteClientError> {
    super::common::get_nullifiers(conn, ShieldedProtocol::Orchard, query, |nf_bytes| {
        Nullifier::from_bytes(<&[u8; 32]>::try_from(nf_bytes).map_err(|_| {
            SqliteClientError::CorruptedData(
                "unable to parse Orchard nullifier: expected 32 bytes".to_string(),
            )
        })?)
        .into_option()
        .ok_or(SqliteClientError::CorruptedData(
            "unable to parse Orchard nullifier".to_string(),
        ))
    })
}

pub(crate) fn detect_spending_accounts<'a>(
    conn: &Connection,
    nfs: impl Iterator<Item = &'a Nullifier>,
) -> Result<HashSet<AccountUuid>, rusqlite::Error> {
    let mut account_q = conn.prepare_cached(
        "SELECT a.uuid
         FROM orchard_received_notes rn
         JOIN accounts a ON a.id = rn.account_id
         WHERE rn.nf IN rarray(:nf_ptr)",
    )?;

    let nf_values: Vec<Value> = nfs.map(|nf| Value::Blob(nf.to_bytes().to_vec())).collect();
    let nf_ptr = Rc::new(nf_values);
    let res = account_q
        .query_and_then(named_params![":nf_ptr": &nf_ptr], |row| {
            row.get(0).map(AccountUuid)
        })?
        .collect::<Result<HashSet<_>, _>>()?;

    Ok(res)
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
pub(crate) fn mark_orchard_note_spent(
    conn: &Connection,
    tx_ref: TxRef,
    nf: &Nullifier,
) -> Result<bool, SqliteClientError> {
    let mut stmt_mark_orchard_note_spent = conn.prepare_cached(
        "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id)
         SELECT id, :transaction_id FROM orchard_received_notes WHERE nf = :nf
         ON CONFLICT (orchard_received_note_id, transaction_id) DO NOTHING",
    )?;

    match stmt_mark_orchard_note_spent.execute(named_params![
       ":nf": nf.to_bytes(),
       ":transaction_id": tx_ref.0
    ])? {
        0 => Ok(false),
        1 => Ok(true),
        _ => unreachable!("nf column is marked as UNIQUE"),
    }
}

#[cfg(test)]
pub(crate) mod tests {

    use zcash_client_backend::data_api::testing::{
        orchard::OrchardPoolTester, sapling::SaplingPoolTester,
    };

    use crate::testing::{self};

    #[test]
    fn send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_max_spendable_single_step_proposed_transfer() {
        testing::pool::spend_max_spendable_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_everything_single_step_proposed_transfer() {
        testing::pool::spend_everything_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn fails_to_send_max_to_transparent_with_memo() {
        testing::pool::fails_to_send_max_to_transparent_with_memo::<OrchardPoolTester>()
    }

    #[test]
    fn send_max_proposal_fails_when_unconfirmed_funds_present() {
        testing::pool::send_max_proposal_fails_when_unconfirmed_funds_present::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_single_note_proposed_transfer() {
        testing::pool::spend_everything_multi_step_single_note_proposed_transfer::<OrchardPoolTester>(
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_many_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_many_notes_proposed_transfer::<OrchardPoolTester>(
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_everything_multi_step_with_marginal_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_with_marginal_notes_proposed_transfer::<
            OrchardPoolTester,
        >()
    }

    #[test]
    fn send_with_multiple_change_outputs() {
        testing::pool::send_with_multiple_change_outputs::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    fn spend_all_funds_single_step_proposed_transfer() {
        testing::pool::spend_all_funds_single_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn spend_all_funds_multi_step_proposed_transfer() {
        testing::pool::spend_all_funds_multi_step_proposed_transfer::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn proposal_fails_if_not_all_ephemeral_outputs_consumed() {
        testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<OrchardPoolTester>()
    }

    #[test]
    fn create_to_address_fails_on_incorrect_usk() {
        testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
    }

    #[test]
    fn proposal_fails_with_no_blocks() {
        testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_unverified_notes() {
        testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
    }

    #[test]
    fn spend_fails_on_locked_notes() {
        testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
    }

    #[test]
    fn ovk_policy_prevents_recovery_from_chain() {
        testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
    }

    #[test]
    fn spend_succeeds_to_t_addr_zero_change() {
        testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
    }

    #[test]
    fn change_note_spends_succeed() {
        testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
    }

    #[test]
    fn account_deletion() {
        testing::pool::account_deletion::<OrchardPoolTester>()
    }

    #[test]
    fn external_address_change_spends_detected_in_restore_from_seed() {
        testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
            OrchardPoolTester,
        >()
    }

    #[test]
    #[ignore] // FIXME: #1316 This requires support for dust outputs.
    fn zip317_spend() {
        testing::pool::zip317_spend::<OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn shield_transparent() {
        testing::pool::shield_transparent::<OrchardPoolTester>()
    }

    #[test]
    fn birthday_in_anchor_shard() {
        testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
    }

    #[test]
    fn checkpoint_gaps() {
        testing::pool::checkpoint_gaps::<OrchardPoolTester>()
    }

    #[test]
    fn scan_cached_blocks_detects_spends_out_of_order() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
    }

    #[test]
    fn metadata_queries_exclude_unwanted_notes() {
        testing::pool::metadata_queries_exclude_unwanted_notes::<OrchardPoolTester>()
    }

    #[test]
    fn pool_crossing_required() {
        testing::pool::pool_crossing_required::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn fully_funded_fully_private() {
        testing::pool::fully_funded_fully_private::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn fully_funded_send_to_t() {
        testing::pool::fully_funded_send_to_t::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn multi_pool_checkpoint() {
        testing::pool::multi_pool_checkpoint::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[test]
    fn multi_pool_checkpoints_with_pruning() {
        testing::pool::multi_pool_checkpoints_with_pruning::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_only() {
        testing::pool::pczt_single_step::<OrchardPoolTester, OrchardPoolTester>()
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn pczt_single_step_orchard_to_sapling() {
        testing::pool::pczt_single_step::<OrchardPoolTester, SaplingPoolTester>()
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn wallet_recovery_compute_fees() {
        testing::pool::wallet_recovery_computes_fees::<OrchardPoolTester>();
    }

    #[test]
    fn zip315_can_spend_inputs_by_confirmations_policy() {
        testing::pool::can_spend_inputs_by_confirmations_policy::<OrchardPoolTester>();
    }

    #[test]
    fn receive_two_notes_with_same_value() {
        testing::pool::receive_two_notes_with_same_value::<OrchardPoolTester>();
    }

    /// Verifies the full PIR witness fallback path in `create_proposed_transactions`:
    /// when ShardTree checkpoints are unavailable, the transaction builder falls back
    /// to PIR-stored witnesses and anchors to build a valid Orchard spend.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn pir_witness_fallback_creates_transaction() {
        use std::convert::Infallible;
        use zcash_client_backend::{
            data_api::{
                Account as _, WalletCommitmentTrees,
                testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
            wallet::OvkPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        use zip321::Payment;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        assert_eq!(st.get_total_balance(account.id()), value);
        assert_eq!(
            st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
            value,
        );

        // Find note DB id and commitment tree position.
        let (note_id, note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let position = incrementalmerkletree::Position::from(note_position as u64);

        // Extract the real witness from the ShardTree while it is still complete.
        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists at scanned height");

                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists for scanned note");

                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }

                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        // Store as PIR witness (simulates what the PIR client would do).
        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings_bytes,
            u32::from(h) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        assert!(pir_witness::has_pir_witness(st.wallet().conn(), note_id).unwrap());

        // Remove ShardTree checkpoints so the tree path in build_proposed_transaction
        // returns Err, triggering the PIR fallback in pir_orchard_witness_fallback.
        st.wallet()
            .conn()
            .execute_batch(
                "DELETE FROM orchard_tree_checkpoint_marks_removed;
                 DELETE FROM orchard_tree_checkpoints;",
            )
            .unwrap();

        // Propose a transfer — coin selection still works because the shard is
        // marked as scanned and the note has a PIR witness.
        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        // Create the transaction — ShardTree has no checkpoints so the normal
        // witness path fails, and the PIR fallback produces the spend.
        let result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "PIR witness fallback should create transaction: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().len(), 1);
    }

    /// Verifies that a server-produced witness for the wallet's actual note
    /// commitment is rejected if tampered before insert, but succeeds end-to-end
    /// when inserted honestly and later consumed by the PIR fallback path.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn pir_witness_server_round_trip_inserts_and_spends_real_note() {
        use std::convert::Infallible;

        use commitment_tree_db::CommitmentTreeDb;
        use incrementalmerkletree::{Hashable, Level};
        use orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
        use zcash_client_backend::{
            data_api::{
                Account as _, WalletCommitmentTrees,
                testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
            wallet::OvkPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        use zip321::Payment;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        const TREE_DEPTH: usize = 32;
        const SUBSHARD_HEIGHT: u8 = 8;
        const SHARD_HEIGHT: u8 = 16;

        fn hash_combine(level: u8, left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
            let left = MerkleHashOrchard::from_bytes(left).unwrap();
            let right = MerkleHashOrchard::from_bytes(right).unwrap();
            <MerkleHashOrchard as Hashable>::combine(Level::from(level), &left, &right).to_bytes()
        }

        fn empty_root(level: u8) -> [u8; 32] {
            <MerkleHashOrchard as Hashable>::empty_root(Level::from(level)).to_bytes()
        }

        fn extract_siblings(
            nodes: &[[u8; 32]],
            index: usize,
            base_level: u8,
            siblings: &mut [[u8; 32]; TREE_DEPTH],
        ) {
            let num_levels = nodes.len().trailing_zeros() as usize;
            let mut current_nodes = nodes.to_vec();
            let mut idx = index;

            for level_offset in 0..num_levels {
                let tree_level = base_level as usize + level_offset;
                let sibling_idx = idx ^ 1;
                siblings[tree_level] = if sibling_idx < current_nodes.len() {
                    current_nodes[sibling_idx]
                } else {
                    empty_root(tree_level as u8)
                };

                let mut next = Vec::with_capacity(current_nodes.len() / 2);
                for pair in current_nodes.chunks(2) {
                    let left = pair[0];
                    let right = if pair.len() > 1 {
                        pair[1]
                    } else {
                        empty_root(tree_level as u8)
                    };
                    next.push(hash_combine(tree_level as u8, &left, &right));
                }
                current_nodes = next;
                idx /= 2;
            }
        }

        fn compute_root_from_path(
            position: u64,
            leaf: &[u8; 32],
            siblings: &[[u8; 32]; TREE_DEPTH],
        ) -> [u8; 32] {
            let mut current = *leaf;
            let mut pos = position;

            for (level, sibling) in siblings.iter().enumerate() {
                let (left, right) = if pos & 1 == 0 {
                    (&current, sibling)
                } else {
                    (sibling, &current)
                };
                current = hash_combine(level as u8, left, right);
                pos >>= 1;
            }

            current
        }

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);
        let value = Zatoshis::const_from_u64(60_000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        let (note_id, note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();

        let position = incrementalmerkletree::Position::from(note_position as u64);
        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists at scanned height");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists for scanned note");

                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }

                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        let anchor_height = u32::from(h) as u64;
        let initial_validation = st
            .wallet()
            .db()
            .validate_pir_orchard_witness(
                note_id,
                &siblings_bytes,
                anchor_height,
                &anchor_root_bytes,
            )
            .unwrap();
        assert!(
            initial_validation.witness_root_matches_anchor(),
            "wallet's own checkpoint witness should validate before the server round-trip"
        );

        let received_note = st
            .wallet()
            .conn()
            .query_row_and_then(
                "SELECT
                     rn.id,
                     t.txid,
                     rn.action_index,
                     rn.diversifier,
                     rn.value,
                     rn.rho,
                     rn.rseed,
                     rn.commitment_tree_position,
                     accounts.ufvk,
                     rn.recipient_key_scope,
                     t.mined_height,
                     NULL AS max_shielding_input_height
                 FROM orchard_received_notes rn
                 INNER JOIN accounts ON accounts.id = rn.account_id
                 INNER JOIN transactions t ON t.id_tx = rn.transaction_id
                 WHERE rn.id = ?1",
                [note_id],
                |row| super::to_received_note(st.network(), row),
            )
            .unwrap()
            .expect("stored note should be reconstructible");
        let note_commitment: ExtractedNoteCommitment = received_note.note().commitment().into();

        let mut server_leaves =
            vec![MerkleHashOrchard::empty_leaf().to_bytes(); note_position as usize];
        server_leaves.push(MerkleHashOrchard::from_cmx(&note_commitment).to_bytes());

        let mut server_tree = CommitmentTreeDb::new();
        server_tree.append_commitments(anchor_height, [0xAA; 32], &server_leaves);
        let expected_server_root = server_tree.tree_root();
        let (_, broadcast) = server_tree.build_pir_db_and_broadcast(anchor_height);

        let server_position = note_position as u64;
        let shard_idx = (server_position >> SHARD_HEIGHT) as u32;
        let subshard_idx = ((server_position >> SUBSHARD_HEIGHT) & 0xFF) as u8;
        let leaf_idx = (server_position & 0xFF) as usize;

        let leaves = server_tree.subshard_leaves(shard_idx, subshard_idx);
        let mut server_siblings = [[0u8; 32]; TREE_DEPTH];
        extract_siblings(&leaves, leaf_idx, 0, &mut server_siblings);

        let shard_offset = (shard_idx - broadcast.window_start_shard) as usize;
        let ss_roots = &broadcast.subshard_roots[shard_offset].roots;
        extract_siblings(
            ss_roots,
            subshard_idx as usize,
            SUBSHARD_HEIGHT,
            &mut server_siblings,
        );

        let total_cap_slots = 1usize << SHARD_HEIGHT;
        let mut padded_cap = broadcast.cap.shard_roots.clone();
        padded_cap.resize(total_cap_slots, empty_root(SHARD_HEIGHT));
        extract_siblings(
            &padded_cap,
            shard_idx as usize,
            SHARD_HEIGHT,
            &mut server_siblings,
        );

        let server_anchor_root =
            compute_root_from_path(server_position, &leaves[leaf_idx], &server_siblings);
        let server_anchor_height = broadcast.anchor_height;

        assert_eq!(server_anchor_height, anchor_height);
        assert_eq!(server_anchor_root, expected_server_root);

        let mut tampered_siblings = server_siblings;
        tampered_siblings.swap(0, 1);
        let tampered_validation = st
            .wallet()
            .db()
            .validate_pir_orchard_witness(
                note_id,
                &tampered_siblings,
                server_anchor_height,
                &server_anchor_root,
            )
            .unwrap();
        assert!(
            !tampered_validation.witness_root_matches_anchor(),
            "tampered server witness should fail pre-insert validation"
        );
        assert!(
            !pir_witness::has_pir_witness(st.wallet().conn(), note_id).unwrap(),
            "failed validation must not persist a PIR witness row"
        );

        st.wallet()
            .db()
            .insert_pir_witness(
                note_id,
                &server_siblings,
                server_anchor_height,
                &server_anchor_root,
            )
            .unwrap();

        st.wallet()
            .conn()
            .execute_batch(
                "DELETE FROM orchard_tree_checkpoint_marks_removed;
                 DELETE FROM orchard_tree_checkpoints;",
            )
            .unwrap();

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10_000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();
        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "honest server witness should support PIR fallback spending: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().len(), 1);
    }

    /// When no PIR witness is stored for a note, transaction creation should fail
    /// rather than silently produce an invalid spend.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn pir_witness_missing_fails_transaction() {
        use std::convert::Infallible;
        use zcash_client_backend::{
            data_api::{
                Account as _,
                testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
            wallet::OvkPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        use zip321::Payment;

        use crate::testing::{BlockCache, db::TestDbFactory};

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Remove ShardTree checkpoints but do NOT insert a PIR witness.
        st.wallet()
            .conn()
            .execute_batch(
                "DELETE FROM orchard_tree_checkpoint_marks_removed;
                 DELETE FROM orchard_tree_checkpoints;",
            )
            .unwrap();

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_err(),
            "Should fail when no PIR witness is available"
        );
    }

    /// When two notes have PIR witnesses with different anchor roots, transaction
    /// creation should fail because the Orchard bundle requires a single anchor.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn pir_witness_anchor_mismatch_fails_transaction() {
        use std::convert::Infallible;
        use zcash_client_backend::{
            data_api::{
                Account as _, WalletCommitmentTrees,
                testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
            wallet::OvkPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        use zip321::Payment;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        // Generate two blocks with one note each so the proposal selects both.
        let value = Zatoshis::const_from_u64(50000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);

        // Extract real witnesses from ShardTree, but forge a different anchor root
        // for the second note to simulate an anchor mismatch.
        let notes: Vec<(i64, i64)> = {
            let mut stmt = st
                .wallet()
                .conn()
                .prepare(
                    "SELECT id, commitment_tree_position FROM orchard_received_notes \
                     ORDER BY id",
                )
                .unwrap();
            stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .map(|r| r.unwrap())
                .collect()
        };
        assert_eq!(notes.len(), 2);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let pos = incrementalmerkletree::Position::from(notes[0].1 as u64);
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(pos, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        // Note 1: real anchor root
        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            notes[0].0,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        // Note 2: deliberately different anchor root
        let mut bad_root = anchor_root_bytes;
        bad_root[0] ^= 0xFF;
        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            notes[1].0,
            &siblings_bytes,
            u32::from(h2) as u64,
            &bad_root,
        )
        .unwrap();

        // Remove ShardTree checkpoints to force PIR path.
        st.wallet()
            .conn()
            .execute_batch(
                "DELETE FROM orchard_tree_checkpoint_marks_removed;
                 DELETE FROM orchard_tree_checkpoints;",
            )
            .unwrap();

        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        // Request enough to force both notes into the proposal.
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(60000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        let err = result.expect_err("Should fail when PIR witnesses have incompatible anchors");
        assert!(
            format!("{err}").contains("incompatible PIR witness anchors"),
            "unexpected error: {err}"
        );
    }

    /// Verifies that coin selection includes a note whose shard is NOT fully scanned
    /// when a PIR witness is available. This exercises the `OR EXISTS` branch of
    /// `shard_scanned_condition` — without it, the note would be excluded.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn pir_witness_enables_selection_for_unscanned_shard() {
        use std::convert::Infallible;
        use zcash_client_backend::{
            data_api::{
                Account as _, WalletCommitmentTrees,
                testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
                wallet::{ConfirmationsPolicy, input_selection::GreedyInputSelector},
            },
            fees::{DustOutputPolicy, StandardFeeRule, standard::SingleOutputChangeStrategy},
            wallet::OvkPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;
        use zip321::Payment;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Extract the real witness while ShardTree is complete.
        let (note_id, note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let position = incrementalmerkletree::Position::from(note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings_bytes,
            u32::from(h) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        // Mark the shard as unscanned by raising scan_queue priority to ChainTip (50),
        // which is above Scanned (10). This simulates a note in a shard that hasn't
        // been fully scanned yet.
        st.wallet()
            .conn()
            .execute("UPDATE scan_queue SET priority = 50", [])
            .unwrap();

        // Also remove ShardTree checkpoints so the normal witness path fails.
        st.wallet()
            .conn()
            .execute_batch(
                "DELETE FROM orchard_tree_checkpoint_marks_removed;
                 DELETE FROM orchard_tree_checkpoints;",
            )
            .unwrap();

        // Verify the shard really looks unscanned from the view's perspective.
        let max_priority: i64 = st
            .wallet()
            .conn()
            .query_row(
                "SELECT max_priority FROM v_orchard_shards_scan_state LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            max_priority > 10,
            "shard should appear unscanned (priority {max_priority} > Scanned=10)"
        );

        // Coin selection should still include the note thanks to the PIR witness.
        let to_extsk = OrchardPoolTester::sk(&[0xf5; 32]);
        let to = OrchardPoolTester::sk_default_address(&to_extsk);
        let request = zip321::TransactionRequest::new(vec![Payment::without_memo(
            to.to_zcash_address(st.network()),
            Zatoshis::const_from_u64(10000),
        )])
        .unwrap();

        let change_strategy = SingleOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            OrchardPoolTester::SHIELDED_PROTOCOL,
            DustOutputPolicy::default(),
        );
        let input_selector = GreedyInputSelector::new();

        let proposal = st
            .propose_transfer(
                account.id(),
                &input_selector,
                &change_strategy,
                request,
                ConfirmationsPolicy::MIN,
            )
            .unwrap();

        let result = st.create_proposed_transactions::<Infallible, _, Infallible, _>(
            account.usk(),
            OvkPolicy::Sender,
            &proposal,
        );

        assert!(
            result.is_ok(),
            "Note in unscanned shard with PIR witness should be spendable: {:?}",
            result.err()
        );
    }

    /// Verifies that `get_wallet_summary` reports a PIR-witnessed note as spendable
    /// even when its shard is not fully scanned. This exercises the `|| has_pir_witness`
    /// branch in the wallet summary query, separate from coin selection.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn wallet_summary_includes_pir_witnessed_note_as_spendable() {
        use zcash_client_backend::data_api::{
            Account as _, WalletCommitmentTrees,
            testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
            wallet::ConfirmationsPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h, 1);

        // Confirm spendable before we manipulate scan state.
        assert_eq!(
            st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN),
            value,
        );

        // Extract witness and store as PIR.
        let (note_id, note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let position = incrementalmerkletree::Position::from(note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings_bytes,
            u32::from(h) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        // Mark shard as unscanned (ChainTip=50 > Scanned=10).
        st.wallet()
            .conn()
            .execute("UPDATE scan_queue SET priority = 50", [])
            .unwrap();

        // Without PIR witness, the note would NOT be spendable (shard unscanned).
        // With PIR witness, get_wallet_summary should still report it as spendable.
        let spendable = st.get_spendable_balance(account.id(), ConfirmationsPolicy::MIN);
        assert_eq!(
            spendable, value,
            "PIR-witnessed note in unscanned shard should appear spendable in wallet summary"
        );
    }

    /// Verifies that wallet summary aggregation remains note-specific when only a
    /// subset of Orchard notes have PIR witnesses available.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn wallet_summary_only_upgrades_pir_witnessed_notes() {
        use zcash_client_backend::data_api::{
            Account as _, WalletCommitmentTrees,
            testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
            wallet::ConfirmationsPolicy,
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let account = st.test_account().cloned().unwrap();
        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let first_value = Zatoshis::const_from_u64(60_000);
        let second_value = Zatoshis::const_from_u64(80_000);

        let (_h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, first_value);
        st.scan_cached_blocks(_h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, second_value);
        st.scan_cached_blocks(h2, 1);

        let (first_note_id, first_note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes ORDER BY id LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let first_position = incrementalmerkletree::Position::from(first_note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(first_position, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            first_note_id,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        st.wallet()
            .conn()
            .execute("UPDATE scan_queue SET priority = 50", [])
            .unwrap();

        let summary = st
            .get_wallet_summary(ConfirmationsPolicy::MIN)
            .expect("wallet summary should be present");
        let orchard_balance = summary
            .account_balances()
            .get(&account.id())
            .expect("account balance should exist")
            .orchard_balance();

        assert_eq!(
            orchard_balance.spendable_value(),
            first_value,
            "only the PIR-witnessed Orchard note should remain spendable"
        );
        assert_eq!(
            orchard_balance.value_pending_spendability(),
            second_value,
            "unresolved Orchard notes should remain pending spendability"
        );
        assert_eq!(
            orchard_balance.total(),
            (first_value + second_value).expect("sum should fit in Zatoshi range"),
            "wallet summary should preserve the full Orchard total while splitting readiness note-by-note"
        );
    }

    /// Verifies that `truncate_to_height` clears PIR witness data from `pir_notes`
    /// to avoid stale authentication paths after a reorg.
    #[cfg(feature = "spendability-pir")]
    #[test]
    fn truncate_to_height_clears_pir_notes() {
        use zcash_client_backend::data_api::{
            WalletCommitmentTrees,
            testing::{AddressType, TestBuilder, pool::ShieldedPoolTester},
        };
        use zcash_primitives::block::BlockHash;
        use zcash_protocol::value::Zatoshis;

        use crate::{
            testing::{BlockCache, db::TestDbFactory},
            wallet::{commitment_tree, pir_witness},
        };

        let mut st = TestBuilder::new()
            .with_data_store_factory(TestDbFactory::default())
            .with_block_cache(BlockCache::new())
            .with_account_from_sapling_activation(BlockHash([0; 32]))
            .build();

        let dfvk = OrchardPoolTester::test_account_fvk(&st);

        let value = Zatoshis::const_from_u64(60000);
        let (h1, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h1, 1);
        let (h2, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
        st.scan_cached_blocks(h2, 1);

        let (note_id, note_position): (i64, i64) = st
            .wallet()
            .conn()
            .query_row(
                "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        let position = incrementalmerkletree::Position::from(note_position as u64);

        let (siblings_bytes, anchor_root_bytes) = st
            .wallet_mut()
            .with_orchard_tree_mut::<_, _, shardtree::error::ShardTreeError<commitment_tree::Error>>(
                |orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h2)?
                        .expect("root exists");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h2)?
                        .expect("witness exists");
                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }
                    Ok((siblings, root.to_bytes()))
                },
            )
            .unwrap();

        pir_witness::insert_pir_witness(
            st.wallet().conn(),
            note_id,
            &siblings_bytes,
            u32::from(h2) as u64,
            &anchor_root_bytes,
        )
        .unwrap();

        assert!(pir_witness::has_pir_witness(st.wallet().conn(), note_id).unwrap());

        // Truncate to the first block, rewinding past the second.
        st.truncate_to_height(h1);

        assert!(
            !pir_witness::has_pir_witness(st.wallet().conn(), note_id).unwrap(),
            "PIR witness data should be cleared after truncate_to_height"
        );
    }
}
