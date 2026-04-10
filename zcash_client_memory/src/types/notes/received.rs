use incrementalmerkletree::Position;

use std::collections::BTreeSet;
use std::{
    collections::BTreeMap,
    ops::{Deref, DerefMut},
};
use zip32::Scope;

use zcash_primitives::transaction::TxId;
use zcash_protocol::{PoolType, ShieldedProtocol::Sapling, memo::Memo};

use zcash_client_backend::{
    DecryptedOutput, TransferType,
    data_api::{ReceivedNotes, SentTransactionOutput},
    wallet::{Note, NoteId, Recipient, WalletSaplingOutput},
};

use crate::AccountId;

#[cfg(feature = "orchard")]
use {
    zcash_client_backend::wallet::WalletOrchardOutput, zcash_protocol::ShieldedProtocol::Orchard,
};

use crate::{Nullifier, error::Error};

/// Keeps track of notes that are spent in which transaction
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceievedNoteSpends(pub(crate) BTreeMap<NoteId, TxId>);

impl ReceievedNoteSpends {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn insert_spend(&mut self, note_id: NoteId, txid: TxId) -> Option<TxId> {
        self.0.insert(note_id, txid)
    }
    pub fn get(&self, note_id: &NoteId) -> Option<&TxId> {
        self.0.get(note_id)
    }
}

impl Deref for ReceievedNoteSpends {
    type Target = BTreeMap<NoteId, TxId>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A note that has been received by the wallet
/// TODO: Instead of Vec, perhaps we should identify by some unique ID
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceivedNoteTable(pub(crate) Vec<ReceivedNote>);

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReceivedNote {
    // Uniquely identifies this note
    pub(crate) note_id: NoteId,
    pub(crate) txid: TxId,
    // output_index: sapling, action_index: orchard
    pub(crate) output_index: u32,
    pub(crate) account_id: AccountId,
    //sapling: (diversifier, value, rcm) orchard: (diversifier, value, rho, rseed)
    pub(crate) note: Note,
    pub(crate) nf: Option<Nullifier>,
    pub(crate) is_change: bool,
    pub(crate) memo: Memo,
    pub(crate) commitment_tree_position: Option<Position>,
    pub(crate) recipient_key_scope: Option<Scope>,
}
impl ReceivedNote {
    pub fn pool(&self) -> PoolType {
        match self.note {
            Note::Sapling { .. } => PoolType::SAPLING,
            #[cfg(feature = "orchard")]
            Note::Orchard { .. } => PoolType::ORCHARD,
        }
    }
    pub fn account_id(&self) -> AccountId {
        self.account_id
    }
    pub fn nullifier(&self) -> Option<&Nullifier> {
        self.nf.as_ref()
    }
    pub fn txid(&self) -> TxId {
        self.txid
    }
    pub fn note_id(&self) -> NoteId {
        self.note_id
    }
    pub fn from_sent_tx_output(
        txid: TxId,
        output: &SentTransactionOutput<AccountId>,
    ) -> Result<Self, Error> {
        match output.recipient() {
            Recipient::InternalAccount {
                receiving_account,
                note,
                ..
            } => match note.as_ref() {
                Note::Sapling(note) => Ok(ReceivedNote {
                    note_id: NoteId::new(txid, Sapling, output.output_index() as u16),
                    txid,
                    output_index: output.output_index() as u32,
                    account_id: *receiving_account,
                    note: Note::Sapling(note.clone()),
                    nf: None,
                    is_change: true,
                    memo: output
                        .memo()
                        .map(Memo::try_from)
                        .transpose()?
                        .expect("expected a memo for a non-transparent output"),
                    commitment_tree_position: None,
                    recipient_key_scope: Some(Scope::Internal),
                }),
                #[cfg(feature = "orchard")]
                Note::Orchard(note) => Ok(ReceivedNote {
                    note_id: NoteId::new(txid, Orchard, output.output_index() as u16),
                    txid,
                    output_index: output.output_index() as u32,
                    account_id: *receiving_account,
                    note: Note::Orchard(*note),
                    nf: None,
                    is_change: true,
                    memo: output
                        .memo()
                        .map(Memo::try_from)
                        .transpose()?
                        .expect("expected a memo for a non-transparent output"),
                    commitment_tree_position: None,
                    recipient_key_scope: Some(Scope::Internal),
                }),
            },
            _ => Err(Error::Other(
                "Recipient is not an internal shielded account".to_owned(),
            )),
        }
    }
    pub fn from_wallet_sapling_output(
        note_id: NoteId,
        output: &WalletSaplingOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Sapling(output.note().clone()),
            nf: output.nf().map(|nf| Nullifier::Sapling(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
        }
    }
    #[cfg(feature = "orchard")]
    pub fn from_wallet_orchard_output(
        note_id: NoteId,
        output: &WalletOrchardOutput<AccountId>,
    ) -> Self {
        ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account_id(),
            note: Note::Orchard(*output.note()),
            nf: output.nf().map(|nf| Nullifier::Orchard(*nf)),
            is_change: output.is_change(),
            memo: Memo::Empty,
            commitment_tree_position: Some(output.note_commitment_tree_position()),
            recipient_key_scope: output.recipient_key_scope(),
        }
    }

    /// Constructs a [`ReceivedNote`] from a Sapling [`DecryptedOutput`] produced by the
    /// transaction-enhancement path.
    ///
    /// `is_change` and `recipient_key_scope` are derived from the output's
    /// [`TransferType`]: [`TransferType::WalletInternal`] is change in the
    /// internal scope, [`TransferType::Incoming`] is a regular receive in the
    /// external scope. [`TransferType::Outgoing`] is rejected because outgoing
    /// outputs are not stored as received notes.
    ///
    /// `nf` is populated from `output.nullifier_bytes()` when available;
    /// `commitment_tree_position` is populated from
    /// `output.note_commitment_tree_position()` when available. Both may be
    /// `None` if the enhancement path could not derive them (e.g. Sapling
    /// outputs decrypted via `decrypt_and_store_transaction` without bundle
    /// position information).
    pub fn from_decrypted_sapling_output(
        note_id: NoteId,
        output: &DecryptedOutput<sapling::Note, AccountId>,
    ) -> Result<Self, Error> {
        let (is_change, recipient_key_scope) = match output.transfer_type() {
            TransferType::WalletInternal => (true, Some(Scope::Internal)),
            TransferType::Incoming => (false, Some(Scope::External)),
            TransferType::Outgoing => {
                return Err(Error::Other(
                    "outgoing outputs are not stored as received notes".to_owned(),
                ));
            }
        };
        let nf = output
            .nullifier_bytes()
            .and_then(|bytes| sapling::Nullifier::from_slice(&bytes).ok())
            .map(Nullifier::Sapling);
        Ok(ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account(),
            note: Note::Sapling(output.note().clone()),
            nf,
            is_change,
            memo: Memo::try_from(output.memo().clone())?,
            commitment_tree_position: output.note_commitment_tree_position(),
            recipient_key_scope,
        })
    }

    /// Constructs a [`ReceivedNote`] from an Orchard [`DecryptedOutput`] produced by the
    /// transaction-enhancement path. See [`Self::from_decrypted_sapling_output`] for the
    /// `is_change` / `recipient_key_scope` derivation.
    #[cfg(feature = "orchard")]
    pub fn from_decrypted_orchard_output(
        note_id: NoteId,
        output: &DecryptedOutput<orchard::Note, AccountId>,
    ) -> Result<Self, Error> {
        let (is_change, recipient_key_scope) = match output.transfer_type() {
            TransferType::WalletInternal => (true, Some(Scope::Internal)),
            TransferType::Incoming => (false, Some(Scope::External)),
            TransferType::Outgoing => {
                return Err(Error::Other(
                    "outgoing outputs are not stored as received notes".to_owned(),
                ));
            }
        };
        let nf = output
            .nullifier_bytes()
            .and_then(|bytes| Option::from(orchard::note::Nullifier::from_bytes(&bytes)))
            .map(Nullifier::Orchard);
        Ok(ReceivedNote {
            note_id,
            txid: *note_id.txid(),
            output_index: output.index() as u32,
            account_id: *output.account(),
            note: Note::Orchard(*output.note()),
            nf,
            is_change,
            memo: Memo::try_from(output.memo().clone())?,
            commitment_tree_position: output.note_commitment_tree_position(),
            recipient_key_scope,
        })
    }
}

impl From<ReceivedNote>
    for zcash_client_backend::wallet::ReceivedNote<NoteId, zcash_client_backend::wallet::Note>
{
    fn from(value: ReceivedNote) -> Self {
        zcash_client_backend::wallet::ReceivedNote::from_parts(
            value.note_id,
            value.txid,
            value.output_index.try_into().unwrap(),
            value.note,
            value.recipient_key_scope.unwrap(),
            value.commitment_tree_position.unwrap(),
            None,
            None,
        )
    }
}

impl ReceivedNoteTable {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn get_sapling_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, sapling::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Sapling(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }
    #[cfg(feature = "orchard")]
    pub fn get_orchard_nullifiers(
        &self,
    ) -> impl Iterator<Item = (AccountId, TxId, orchard::note::Nullifier)> + '_ {
        self.0.iter().filter_map(|entry| {
            if let Some(Nullifier::Orchard(nf)) = entry.nullifier() {
                Some((entry.account_id(), entry.txid(), *nf))
            } else {
                None
            }
        })
    }

    pub fn insert_received_note(&mut self, note: ReceivedNote) {
        // ensure note_id is unique.
        // follow upsert rules to update the note if it already exists
        let is_absent = self
            .0
            .iter_mut()
            .find(|n| n.note_id == note.note_id)
            .map(|n| {
                n.nf = note.nf.or(n.nf);
                n.is_change = note.is_change || n.is_change;
                n.commitment_tree_position =
                    note.commitment_tree_position.or(n.commitment_tree_position);
            })
            .is_none();

        if is_absent {
            self.0.push(note);
        }
    }

    #[cfg(feature = "orchard")]
    pub fn detect_orchard_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a orchard::note::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        let nfs = nfs.collect::<Vec<_>>();
        for (nf, id) in self.0.iter().filter_map(|n| match (n.nf, n.account_id) {
            (Some(Nullifier::Orchard(nf)), account_id) => Some((nf, account_id)),
            _ => None,
        }) {
            if nfs.contains(&&nf) {
                acc.insert(id);
            }
        }
        Ok(acc)
    }

    pub fn detect_sapling_spending_accounts<'a>(
        &self,
        nfs: impl Iterator<Item = &'a sapling::Nullifier>,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut acc = BTreeSet::new();
        let nfs = nfs.collect::<Vec<_>>();
        for (nf, id) in self.0.iter().filter_map(|n| match (n.nf, n.account_id) {
            (Some(Nullifier::Sapling(nf)), account_id) => Some((nf, account_id)),
            _ => None,
        }) {
            if nfs.contains(&&nf) {
                acc.insert(id);
            }
        }
        Ok(acc)
    }
}

// We deref to slice so that we can reuse the slice impls
impl Deref for ReceivedNoteTable {
    type Target = [ReceivedNote];

    fn deref(&self) -> &Self::Target {
        &self.0[..]
    }
}
impl DerefMut for ReceivedNoteTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0[..]
    }
}

pub(crate) fn to_spendable_notes(
    sapling_received_notes: &[&ReceivedNote],
    #[cfg(feature = "orchard")] orchard_received_notes: &[&ReceivedNote],
) -> Result<ReceivedNotes<NoteId>, Error> {
    let sapling = sapling_received_notes
        .iter()
        .map(|note| {
            #[allow(irrefutable_let_patterns)]
            if let Note::Sapling(inner) = &note.note {
                Ok(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    note.txid(),
                    note.output_index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    inner.clone(),
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    None,
                    None,
                ))
            } else {
                Err(Error::Other("Note is not a sapling note".to_owned()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    #[cfg(feature = "orchard")]
    let orchard = orchard_received_notes
        .iter()
        .map(|note| {
            if let Note::Orchard(inner) = &note.note {
                Ok(zcash_client_backend::wallet::ReceivedNote::from_parts(
                    note.note_id,
                    note.txid(),
                    note.output_index.try_into().unwrap(), // this overflow can never happen or else the chain is broken
                    *inner,
                    note.recipient_key_scope
                        .ok_or(Error::Missing("recipient key scope".into()))?,
                    note.commitment_tree_position
                        .ok_or(Error::Missing("commitment tree position".into()))?,
                    None,
                    None,
                ))
            } else {
                Err(Error::Other("Note is not an orchard note".to_owned()))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ReceivedNotes::new(
        sapling,
        #[cfg(feature = "orchard")]
        orchard,
    ))
}

mod serialization {
    use super::*;
    use crate::{proto::memwallet as proto, read_optional};

    impl From<ReceivedNote> for proto::ReceivedNote {
        fn from(value: ReceivedNote) -> Self {
            Self {
                note_id: Some(value.note_id.into()),
                tx_id: Some(value.txid.into()),
                output_index: value.output_index,
                account_id: *value.account_id,
                note: Some(value.note.into()),
                nullifier: value.nf.map(|nf| nf.into()),
                is_change: value.is_change,
                memo: value.memo.encode().as_array().to_vec(),
                commitment_tree_position: value.commitment_tree_position.map(|pos| pos.into()),
                recipient_key_scope: match value.recipient_key_scope {
                    Some(Scope::Internal) => Some(proto::Scope::Internal as i32),
                    Some(Scope::External) => Some(proto::Scope::External as i32),
                    None => None,
                },
            }
        }
    }

    impl TryFrom<proto::ReceivedNote> for ReceivedNote {
        type Error = Error;

        fn try_from(value: proto::ReceivedNote) -> Result<ReceivedNote, Error> {
            Ok(Self {
                note_id: read_optional!(value, note_id)?.try_into()?,
                txid: read_optional!(value, tx_id)?.try_into()?,
                output_index: value.output_index,
                account_id: value.account_id.into(),
                note: read_optional!(value, note)?.into(),
                nf: value.nullifier.map(|nf| nf.try_into()).transpose()?,
                is_change: value.is_change,
                memo: Memo::from_bytes(&value.memo)?,
                commitment_tree_position: value.commitment_tree_position.map(|pos| pos.into()),
                recipient_key_scope: match value.recipient_key_scope {
                    Some(0) => Some(Scope::Internal),
                    Some(1) => Some(Scope::External),
                    _ => None,
                },
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::memo::MemoBytes;

    /// Builds a stub Sapling note for use in classification tests. Field
    /// values are arbitrary; the test only cares about how the constructor
    /// maps `transfer_type` to `is_change` and `recipient_key_scope`.
    fn stub_sapling_note() -> sapling::Note {
        sapling::note::Note::from_parts(
            sapling::PaymentAddress::from_bytes(&[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x8e, 0x11,
                0x9d, 0x72, 0x99, 0x2b, 0x56, 0x0d, 0x26, 0x50, 0xff, 0xe0, 0xbe, 0x7f, 0x35, 0x42,
                0xfd, 0x97, 0x00, 0x3c, 0xb7, 0xcc, 0x3a, 0xbf, 0xf8, 0x1a, 0x7f, 0x90, 0x37, 0xf3,
                0xea,
            ])
            .unwrap(),
            sapling::value::NoteValue::from_raw(99),
            sapling::Rseed::AfterZip212([0; 32]),
        )
    }

    fn stub_note_id() -> NoteId {
        NoteId::new(TxId::from_bytes([0; 32]), Sapling, 0)
    }

    fn make_decrypted_output(
        transfer_type: TransferType,
    ) -> DecryptedOutput<sapling::Note, AccountId> {
        DecryptedOutput::new(
            0,
            stub_sapling_note(),
            AccountId::from(0),
            MemoBytes::empty(),
            transfer_type,
        )
    }

    /// Regression test for the bug where `TransferType::Incoming` shielded
    /// outputs were stored via `from_sent_tx_output`, which hardcoded
    /// `is_change = true` and `recipient_key_scope = Some(Scope::Internal)`,
    /// silently reclassifying ordinary incoming receipts as change in the
    /// internal scope.
    #[test]
    fn from_decrypted_sapling_output_incoming_is_external_receive() {
        let output = make_decrypted_output(TransferType::Incoming);
        let received = ReceivedNote::from_decrypted_sapling_output(stub_note_id(), &output)
            .expect("Incoming should produce a valid ReceivedNote");
        assert!(
            !received.is_change,
            "Incoming output should NOT be marked as change"
        );
        assert_eq!(
            received.recipient_key_scope,
            Some(Scope::External),
            "Incoming output should be in the external scope"
        );
    }

    /// Sanity check that `WalletInternal` still maps to change in the
    /// internal scope, since we use the same constructor for both transfer
    /// types.
    #[test]
    fn from_decrypted_sapling_output_internal_is_change() {
        let output = make_decrypted_output(TransferType::WalletInternal);
        let received = ReceivedNote::from_decrypted_sapling_output(stub_note_id(), &output)
            .expect("WalletInternal should produce a valid ReceivedNote");
        assert!(
            received.is_change,
            "WalletInternal output should be marked as change"
        );
        assert_eq!(
            received.recipient_key_scope,
            Some(Scope::Internal),
            "WalletInternal output should be in the internal scope"
        );
    }

    /// `Outgoing` outputs are not received notes and must be rejected.
    #[test]
    fn from_decrypted_sapling_output_outgoing_is_rejected() {
        let output = make_decrypted_output(TransferType::Outgoing);
        let result = ReceivedNote::from_decrypted_sapling_output(stub_note_id(), &output);
        assert!(
            result.is_err(),
            "Outgoing output should be rejected by from_decrypted_sapling_output"
        );
    }
}
