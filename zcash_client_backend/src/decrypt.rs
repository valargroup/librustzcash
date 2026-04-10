use std::collections::HashMap;

use incrementalmerkletree::Position;
use sapling::note_encryption::{PreparedIncomingViewingKey, SaplingDomain};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_note_encryption::{try_note_decryption, try_output_recovery_with_ovk};
use zcash_primitives::{
    transaction::Transaction, transaction::components::sapling::zip212_enforcement,
};
use zcash_protocol::{
    consensus::{self, BlockHeight, NetworkUpgrade},
    memo::MemoBytes,
    value::Zatoshis,
};
use zip32::Scope;

use crate::data_api::DecryptedTransaction;

#[cfg(feature = "orchard")]
use orchard::note_encryption::OrchardDomain;

/// An enumeration of the possible relationships a TXO can have to the wallet.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum TransferType {
    /// The output was received on one of the wallet's external addresses via decryption using the
    /// associated incoming viewing key, or at one of the wallet's transparent addresses.
    Incoming,
    /// The output was received on one of the wallet's internal-only shielded addresses via trial
    /// decryption using one of the wallet's internal incoming viewing keys.
    WalletInternal,
    /// The output was decrypted using one of the wallet's outgoing viewing keys, or was created
    /// in a transaction constructed by this wallet.
    Outgoing,
}

/// A decrypted shielded output.
pub struct DecryptedOutput<Note, AccountId> {
    index: usize,
    note: Note,
    account: AccountId,
    memo: MemoBytes,
    transfer_type: TransferType,
    nullifier_bytes: Option<[u8; 32]>,
    note_commitment_tree_position: Option<Position>,
}

impl<Note, AccountId> DecryptedOutput<Note, AccountId> {
    pub fn new(
        index: usize,
        note: Note,
        account: AccountId,
        memo: MemoBytes,
        transfer_type: TransferType,
    ) -> Self {
        Self {
            index,
            note,
            account,
            memo,
            transfer_type,
            nullifier_bytes: None,
            note_commitment_tree_position: None,
        }
    }

    /// The index of the output within the shielded outputs of the Sapling bundle or the actions of
    /// the Orchard bundle, depending upon the type of [`Self::note`].
    pub fn index(&self) -> usize {
        self.index
    }

    /// The note within the output.
    pub fn note(&self) -> &Note {
        &self.note
    }

    /// The account that decrypted the note.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The memo bytes included with the note.
    pub fn memo(&self) -> &MemoBytes {
        &self.memo
    }

    /// Returns a [`TransferType`] value that is determined based upon what type of key was used to
    /// decrypt the transaction.
    pub fn transfer_type(&self) -> TransferType {
        self.transfer_type
    }

    /// Returns the serialized nullifier for the note, if known.
    ///
    /// This is populated during transaction enhancement when the note commitment tree
    /// position is available, enabling the wallet to detect future spends of this note.
    /// Returns `None` for [`TransferType::Outgoing`] outputs (which the wallet cannot spend)
    /// or when the position is not yet known.
    pub fn nullifier_bytes(&self) -> Option<[u8; 32]> {
        self.nullifier_bytes
    }

    /// Returns the position of the note in the note commitment tree, if known.
    ///
    /// This is populated during transaction enhancement from compact block metadata.
    /// A note without a known position cannot be spent, because the wallet cannot
    /// construct a Merkle path (witness) for it.
    pub fn note_commitment_tree_position(&self) -> Option<Position> {
        self.note_commitment_tree_position
    }

    /// Attaches note commitment tree position and nullifier metadata to this output.
    ///
    /// This is used during the enhancement phase to enrich a [`DecryptedOutput`] with
    /// the information needed to make the note spendable.
    pub fn with_spend_metadata(
        mut self,
        note_commitment_tree_position: Option<Position>,
        nullifier_bytes: Option<[u8; 32]>,
    ) -> Self {
        self.note_commitment_tree_position = note_commitment_tree_position;
        self.nullifier_bytes = nullifier_bytes;
        self
    }
}

impl<A> DecryptedOutput<sapling::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Sapling note value is expected to have been validated by consensus.")
    }
}

#[cfg(feature = "orchard")]
impl<A> DecryptedOutput<orchard::note::Note, A> {
    pub fn note_value(&self) -> Zatoshis {
        Zatoshis::from_u64(self.note.value().inner())
            .expect("Orchard note value is expected to have been validated by consensus.")
    }
}

/// Scans a [`Transaction`] for any information that can be decrypted by the set of
/// [`UnifiedFullViewingKey`]s.
///
/// # Parameters
/// - `params`: The network parameters corresponding to the network the transaction
///   was created for.
/// - `mined_height`: The height at which the transaction was mined, or `None` for
///   unmined transactions.
/// - `chain_tip_height`: The current chain tip height, if known. This parameter
///   will be unused if `mined_height.is_some()`.
/// - `tx`: The transaction to decrypt.
/// - `ufvks`: The [`UnifiedFullViewingKey`]s to use in trial decryption, keyed
///   by the identifiers for the wallet accounts they correspond to.
pub fn decrypt_transaction<'a, P: consensus::Parameters, AccountId: Copy>(
    params: &P,
    mined_height: Option<BlockHeight>,
    chain_tip_height: Option<BlockHeight>,
    tx: &'a Transaction,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    let zip212_enforcement = zip212_enforcement(
        params,
        // Height is block height for mined transactions, and the "mempool height" (chain height + 1)
        // for mempool transactions. We fall back to Sapling activation if we have no other
        // information.
        mined_height.unwrap_or_else(|| {
            chain_tip_height
                .map(|max_height| max_height + 1) // "mempool height"
                .or_else(|| params.activation_height(NetworkUpgrade::Sapling))
                // Fall back to the genesis block in regtest mode.
                .unwrap_or_else(|| BlockHeight::from(0))
        }),
    );
    let sapling_bundle = tx.sapling_bundle();
    let sapling_outputs = sapling_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(|(account, ufvk)| ufvk.sapling().into_iter().map(|dfvk| (*account, dfvk)))
                .flat_map(|(account, dfvk)| {
                    let sapling_domain = SaplingDomain::new(zip212_enforcement);
                    let ivk_external =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::External));
                    let ivk_internal =
                        PreparedIncomingViewingKey::new(&dfvk.to_ivk(Scope::Internal));
                    let ovk = dfvk.fvk().ovk;

                    bundle
                        .shielded_outputs()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, output)| {
                            try_note_decryption(&sapling_domain, &ivk_external, output)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_note_decryption(&sapling_domain, &ivk_internal, output)
                                        .map(|ret| (ret, TransferType::WalletInternal))
                                })
                                .or_else(|| {
                                    try_output_recovery_with_ovk(
                                        &sapling_domain,
                                        &ovk,
                                        output,
                                        output.cv(),
                                        output.out_ciphertext(),
                                    )
                                    .map(|ret| (ret, TransferType::Outgoing))
                                })
                                .into_iter()
                                .map(move |((note, _, memo), transfer_type)| {
                                    DecryptedOutput::new(
                                        index,
                                        note,
                                        account,
                                        MemoBytes::from_bytes(&memo).expect("correct length"),
                                        transfer_type,
                                    )
                                })
                        })
                })
        })
        .collect();

    #[cfg(feature = "orchard")]
    let orchard_bundle = tx.orchard_bundle();
    #[cfg(feature = "orchard")]
    let orchard_outputs = orchard_bundle
        .iter()
        .flat_map(|bundle| {
            ufvks
                .iter()
                .flat_map(|(account, ufvk)| ufvk.orchard().into_iter().map(|fvk| (*account, fvk)))
                .flat_map(|(account, fvk)| {
                    let ivk_external = orchard::keys::PreparedIncomingViewingKey::new(
                        &fvk.to_ivk(Scope::External),
                    );
                    let ivk_internal = orchard::keys::PreparedIncomingViewingKey::new(
                        &fvk.to_ivk(Scope::Internal),
                    );
                    let ovk = fvk.to_ovk(Scope::External);

                    bundle
                        .actions()
                        .iter()
                        .enumerate()
                        .flat_map(move |(index, action)| {
                            let domain = OrchardDomain::for_action(action);
                            try_note_decryption(&domain, &ivk_external, action)
                                .map(|ret| (ret, TransferType::Incoming))
                                .or_else(|| {
                                    try_note_decryption(&domain, &ivk_internal, action)
                                        .map(|ret| (ret, TransferType::WalletInternal))
                                })
                                .or_else(|| {
                                    try_output_recovery_with_ovk(
                                        &domain,
                                        &ovk,
                                        action,
                                        action.cv_net(),
                                        &action.encrypted_note().out_ciphertext,
                                    )
                                    .map(|ret| (ret, TransferType::Outgoing))
                                })
                                .into_iter()
                                .map(move |((note, _, memo), transfer_type)| {
                                    DecryptedOutput::new(
                                        index,
                                        note,
                                        account,
                                        MemoBytes::from_bytes(&memo).expect("correct length"),
                                        transfer_type,
                                    )
                                })
                        })
                })
        })
        .collect();

    DecryptedTransaction::new(
        mined_height,
        tx,
        sapling_outputs,
        #[cfg(feature = "orchard")]
        orchard_outputs,
    )
}

/// Note commitment tree base positions for the Sapling and Orchard bundles of a single
/// transaction.
///
/// `sapling_base` is the position of the first Sapling output in the transaction's bundle
/// within the global Sapling note commitment tree. `orchard_base` is the analogous position
/// for the first Orchard action. These bases are used by [`compute_enriched_outputs`] to
/// compute per-output positions and (for Sapling) per-output nullifiers.
///
/// For Orchard, nullifier computation does not depend on position, so `orchard_base` is
/// only required to populate the `commitment_tree_position` field on stored notes (which
/// is needed for witness construction during spending). For Sapling, nullifier computation
/// REQUIRES the position because Sapling's nullifier hash mixes the note's tree position.
#[derive(Clone, Copy, Debug, Default)]
pub struct TxBundlePositions {
    /// Position of the first Sapling output in the transaction's bundle within the global
    /// Sapling note commitment tree.
    pub sapling_base: Option<u64>,
    /// Position of the first Orchard action in the transaction's bundle within the global
    /// Orchard note commitment tree.
    #[cfg(feature = "orchard")]
    pub orchard_base: Option<u64>,
}

/// Enriches the outputs of a [`DecryptedTransaction`] with note commitment tree positions
/// and nullifier bytes, returning a new `DecryptedTransaction` with the same outputs but
/// with [`DecryptedOutput::nullifier_bytes`] and
/// [`DecryptedOutput::note_commitment_tree_position`] populated where possible.
///
/// This is used to add spend-tracking metadata to outputs that were discovered via
/// [`decrypt_transaction`] (typically during transaction enhancement, when change notes
/// recovered via Internal-IVK decryption need their nullifiers computed so that subsequent
/// spends of those change notes can be detected).
///
/// # Arguments
/// - `tx`: The transaction whose outputs are being enriched.
/// - `d_tx`: The decrypted form of the transaction, as returned by [`decrypt_transaction`].
/// - `positions`: Optional pre-computed bundle base positions. When `None`, Sapling outputs
///   will not get nullifiers (because Sapling nullifier computation requires position),
///   but Orchard outputs WILL get nullifiers (because Orchard nullifier computation does
///   not depend on position). When `Some`, both pools get nullifiers.
/// - `ufvks`: The wallet's full viewing keys, keyed by account identifier.
///
/// # Returns
/// A new `DecryptedTransaction` containing the enriched outputs.
pub fn compute_enriched_outputs<'a, AccountId: Copy + std::hash::Hash + Eq>(
    tx: &'a Transaction,
    d_tx: &DecryptedTransaction<'a, Transaction, AccountId>,
    positions: Option<&TxBundlePositions>,
    ufvks: &HashMap<AccountId, UnifiedFullViewingKey>,
) -> DecryptedTransaction<'a, Transaction, AccountId> {
    let sapling_outputs = d_tx
        .sapling_outputs()
        .iter()
        .map(|output| {
            let position = positions
                .and_then(|pos| pos.sapling_base)
                .map(|base| Position::from(base + output.index() as u64));
            let nullifier_bytes = if output.transfer_type() == TransferType::Outgoing {
                None
            } else {
                let scope = match output.transfer_type() {
                    TransferType::WalletInternal => Scope::Internal,
                    TransferType::Incoming => Scope::External,
                    TransferType::Outgoing => unreachable!(),
                };
                position.and_then(|position| {
                    ufvks
                        .get(output.account())
                        .and_then(|ufvk| ufvk.sapling())
                        .map(|dfvk| output.note().nf(&dfvk.to_nk(scope), position.into()).0)
                })
            };

            DecryptedOutput::new(
                output.index(),
                output.note().clone(),
                *output.account(),
                output.memo().clone(),
                output.transfer_type(),
            )
            .with_spend_metadata(position, nullifier_bytes)
        })
        .collect();

    #[cfg(feature = "orchard")]
    let orchard_outputs = d_tx
        .orchard_outputs()
        .iter()
        .map(|output| {
            let position = positions
                .and_then(|pos| pos.orchard_base)
                .map(|base| Position::from(base + output.index() as u64));
            // Orchard nullifier computation does not depend on the note commitment tree
            // position; it can be computed from the note plus the wallet's full viewing
            // key alone. This means change notes recovered via Internal-IVK enhancement
            // can have their nullifiers populated even when the caller does not know the
            // tx's position in the global tree (e.g., when called from
            // `decrypt_and_store_transaction` which has no block-source access).
            let nullifier_bytes = if output.transfer_type() == TransferType::Outgoing {
                None
            } else {
                ufvks
                    .get(output.account())
                    .and_then(|ufvk| ufvk.orchard())
                    .map(|fvk| output.note().nullifier(fvk).to_bytes())
            };

            DecryptedOutput::new(
                output.index(),
                *output.note(),
                *output.account(),
                output.memo().clone(),
                output.transfer_type(),
            )
            .with_spend_metadata(position, nullifier_bytes)
        })
        .collect();

    DecryptedTransaction::new(
        d_tx.mined_height(),
        tx,
        sapling_outputs,
        #[cfg(feature = "orchard")]
        orchard_outputs,
    )
}
