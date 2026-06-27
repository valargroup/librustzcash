//! Orchard-shaped bundle fields of a PCZT.
//!
//! Under NU6.3, PCZT uses this module for both the Orchard bundle and the
//! Ironwood bundle because Ironwood actions reuse Orchard-shaped data
//! structures. Orchard bundle actions must use V2 note plaintexts, while
//! Ironwood bundle actions must use V3 note plaintexts.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

#[cfg(feature = "orchard")]
use ff::PrimeField;
use getset::Getters;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    common::{Global, Zip32Derivation},
    roles::combiner::{merge_map, merge_optional},
};

/// Orchard-style note plaintext version.
///
/// PCZT represents both Orchard and Ironwood bundles using Orchard-shaped
/// actions. V2 is the Orchard note plaintext version, while V3 is the
/// quantum-recoverable note plaintext version used by Ironwood actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotePlaintextVersion {
    /// The [ZIP 212] Orchard note plaintext format, identified by lead byte
    /// `0x02`.
    ///
    /// [ZIP 212]: https://zips.z.cash/zip-0212
    V2,
    /// The quantum-recoverable Orchard-style note plaintext version defined in
    /// [ZIP 2005] for Ironwood actions.
    ///
    /// [ZIP 2005]: https://zips.z.cash/zip-2005
    V3,
}

/// Errors that can occur when an Orchard-shaped PCZT bundle uses a note
/// plaintext version that is not valid for its pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum NotePlaintextVersionError {
    /// An Orchard action spend used a note plaintext version other than V2.
    OrchardSpend {
        /// The action index containing the invalid spend.
        action_index: usize,
        /// The invalid note plaintext version.
        version: NotePlaintextVersion,
    },
    /// An Orchard action output used a note plaintext version other than V2.
    OrchardOutput {
        /// The action index containing the invalid output.
        action_index: usize,
        /// The invalid note plaintext version.
        version: NotePlaintextVersion,
    },
    /// An Ironwood action spend used a note plaintext version other than V3.
    IronwoodSpend {
        /// The action index containing the invalid spend.
        action_index: usize,
        /// The invalid note plaintext version.
        version: NotePlaintextVersion,
    },
    /// An Ironwood action output used a note plaintext version other than V3.
    IronwoodOutput {
        /// The action index containing the invalid output.
        action_index: usize,
        /// The invalid note plaintext version.
        version: NotePlaintextVersion,
    },
}

impl core::fmt::Display for NotePlaintextVersionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NotePlaintextVersionError::OrchardSpend {
                action_index,
                version,
            } => write!(
                f,
                "Orchard action {action_index} spend uses {version:?}; expected V2"
            ),
            NotePlaintextVersionError::OrchardOutput {
                action_index,
                version,
            } => write!(
                f,
                "Orchard action {action_index} output uses {version:?}; expected V2"
            ),
            NotePlaintextVersionError::IronwoodSpend {
                action_index,
                version,
            } => write!(
                f,
                "Ironwood action {action_index} spend uses {version:?}; expected V3"
            ),
            NotePlaintextVersionError::IronwoodOutput {
                action_index,
                version,
            } => write!(
                f,
                "Ironwood action {action_index} output uses {version:?}; expected V3"
            ),
        }
    }
}

/// Errors that can occur while preparing an Orchard-shaped PCZT bundle for a role.
#[cfg(feature = "orchard")]
#[derive(Debug)]
#[non_exhaustive]
pub enum BundleParseError {
    /// A role requiring version 6 on NU6.3 was used with unsupported global fields.
    #[cfg(zcash_unstable = "nu6.3")]
    V6ConsensusBranch(crate::common::V6ConsensusBranchError),
    /// The bundle uses a note plaintext version that is not valid for its pool.
    NotePlaintextVersion(NotePlaintextVersionError),
    /// The bundle failed Orchard PCZT parsing.
    Parse(orchard::pczt::ParseError),
}

#[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
impl From<crate::common::V6ConsensusBranchError> for BundleParseError {
    fn from(e: crate::common::V6ConsensusBranchError) -> Self {
        BundleParseError::V6ConsensusBranch(e)
    }
}

#[cfg(feature = "orchard")]
impl From<NotePlaintextVersionError> for BundleParseError {
    fn from(e: NotePlaintextVersionError) -> Self {
        BundleParseError::NotePlaintextVersion(e)
    }
}

#[cfg(feature = "orchard")]
impl From<orchard::pczt::ParseError> for BundleParseError {
    fn from(e: orchard::pczt::ParseError) -> Self {
        BundleParseError::Parse(e)
    }
}

#[cfg(feature = "orchard")]
impl core::fmt::Display for BundleParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            #[cfg(zcash_unstable = "nu6.3")]
            BundleParseError::V6ConsensusBranch(e) => e.fmt(f),
            BundleParseError::NotePlaintextVersion(e) => e.fmt(f),
            BundleParseError::Parse(_) => write!(f, "invalid Orchard-shaped PCZT bundle"),
        }
    }
}

#[cfg(feature = "orchard")]
impl From<NotePlaintextVersion> for orchard::note::NoteVersion {
    fn from(version: NotePlaintextVersion) -> Self {
        match version {
            NotePlaintextVersion::V2 => Self::V2,
            NotePlaintextVersion::V3 => Self::V3,
        }
    }
}

#[cfg(feature = "orchard")]
impl From<orchard::note::NoteVersion> for NotePlaintextVersion {
    fn from(version: orchard::note::NoteVersion) -> Self {
        match version {
            orchard::note::NoteVersion::V2 => Self::V2,
            orchard::note::NoteVersion::V3 => Self::V3,
        }
    }
}

impl Bundle {
    pub(crate) fn validate_orchard_note_plaintext_versions(
        &self,
    ) -> Result<(), NotePlaintextVersionError> {
        for (action_index, action) in self.actions.iter().enumerate() {
            if action.spend.note_version != NotePlaintextVersion::V2 {
                return Err(NotePlaintextVersionError::OrchardSpend {
                    action_index,
                    version: action.spend.note_version,
                });
            }

            if action.output.note_version != NotePlaintextVersion::V2 {
                return Err(NotePlaintextVersionError::OrchardOutput {
                    action_index,
                    version: action.output.note_version,
                });
            }
        }

        Ok(())
    }

    #[cfg(zcash_unstable = "nu6.3")]
    pub(crate) fn validate_ironwood_note_plaintext_versions(
        &self,
    ) -> Result<(), NotePlaintextVersionError> {
        for (action_index, action) in self.actions.iter().enumerate() {
            if action.spend.note_version != NotePlaintextVersion::V3 {
                return Err(NotePlaintextVersionError::IronwoodSpend {
                    action_index,
                    version: action.spend.note_version,
                });
            }

            if action.output.note_version != NotePlaintextVersion::V3 {
                return Err(NotePlaintextVersionError::IronwoodOutput {
                    action_index,
                    version: action.output.note_version,
                });
            }
        }

        Ok(())
    }
}

/// PCZT fields that are specific to producing an Orchard-shaped bundle.
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Bundle {
    /// The Orchard-shaped actions in this bundle.
    ///
    /// Entries are added by the Constructor, and modified by an Updater, IO Finalizer,
    /// Signer, Combiner, or Spend Finalizer.
    #[getset(get = "pub")]
    pub(crate) actions: Vec<Action>,

    /// The flags for the Orchard bundle.
    ///
    /// Contains:
    /// - `enableSpendsOrchard` flag (bit 0)
    /// - `enableOutputsOrchard` flag (bit 1)
    /// - Reserved, zeros (bits 2..=7)
    ///
    /// This is set by the Creator. The Constructor MUST only add spends and outputs that
    /// are consistent with these flags (i.e. are dummies as appropriate).
    #[getset(get = "pub")]
    pub(crate) flags: u8,

    /// The net value of Orchard spends minus outputs.
    ///
    /// This is initialized by the Creator, and updated by the Constructor as spends or
    /// outputs are added to the PCZT. It enables per-spend and per-output values to be
    /// redacted from the PCZT after they are no longer necessary.
    #[getset(get = "pub")]
    pub(crate) value_sum: (u64, bool),

    /// The Orchard anchor for this transaction.
    ///
    /// Set by the Creator.
    #[getset(get = "pub")]
    pub(crate) anchor: [u8; 32],

    /// The Orchard bundle proof.
    ///
    /// This is `None` until it is set by the Prover.
    pub(crate) zkproof: Option<Vec<u8>>,

    /// The Orchard binding signature signing key.
    ///
    /// - This is `None` until it is set by the IO Finalizer.
    /// - The Transaction Extractor uses this to produce the binding signature.
    pub(crate) bsk: Option<[u8; 32]>,
}

/// Information about an Orchard action within a transaction.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Action {
    //
    // Action effecting data.
    //
    // These fields are part of the final transaction. The Constructor fills them in when
    // adding an output, but a sender may omit any of the derived ones (here, `cv_net`) and
    // let the receiver recompute it from the note fields before parsing. See
    // [`Bundle::into_parsed`].
    //
    #[serde_as(as = "Option<[_; 32]>")]
    #[getset(get = "pub")]
    pub(crate) cv_net: Option<[u8; 32]>,
    #[getset(get = "pub")]
    pub(crate) spend: Spend,
    #[getset(get = "pub")]
    pub(crate) output: Output,

    /// The value commitment randomness.
    ///
    /// - This is set by the Constructor.
    /// - The IO Finalizer compresses it into the bsk.
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value correctly matches `cv`.
    ///
    /// This opens `cv` for all participants. For Signers who don't need this information,
    /// or after proofs / signatures have been applied, this can be redacted.
    pub(crate) rcv: Option<[u8; 32]>,
}

/// Information about the spend part of an Orchard action.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Spend {
    //
    // Spend-specific Action effecting data.
    //
    // These fields are part of the final transaction. The Constructor fills them in when
    // adding a spend, but a sender may omit any of the derived ones (here, `nullifier` and
    // `rk`) and let the receiver recompute them from the note fields before parsing. See
    // [`Bundle::into_parsed`].
    //
    #[serde_as(as = "Option<[_; 32]>")]
    #[getset(get = "pub")]
    pub(crate) nullifier: Option<[u8; 32]>,
    #[serde_as(as = "Option<[_; 32]>")]
    #[getset(get = "pub")]
    pub(crate) rk: Option<[u8; 32]>,

    /// The spend authorization signature.
    ///
    /// This is set by the Signer.
    #[serde_as(as = "Option<[_; 64]>")]
    #[getset(get = "pub")]
    pub(crate) spend_auth_sig: Option<[u8; 64]>,

    /// The [raw encoding] of the Orchard payment address that received the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#orchardpaymentaddrencoding
    #[serde_as(as = "Option<[_; 43]>")]
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the input being spent.
    ///
    /// - This is required by the Prover.
    /// - This may be used by Signers to verify that the value matches `cv`, and to
    ///   confirm the values and change involved in the transaction.
    ///
    /// This exposes the input value to all participants. For Signers who don't need this
    /// information, or after signatures have been applied, this can be redacted.
    pub(crate) value: Option<u64>,

    /// The rho value for the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) rho: Option<[u8; 32]>,

    /// The seed randomness for the note being spent.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    pub(crate) rseed: Option<[u8; 32]>,

    /// The Orchard-style plaintext version of the note being spent.
    ///
    /// This is set by the Constructor, and is required by Verifiers and
    /// Provers to reconstruct the note commitment.
    #[getset(get = "pub")]
    pub(crate) note_version: NotePlaintextVersion,

    /// The full viewing key that received the note being spent.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    #[serde_as(as = "Option<[_; 96]>")]
    pub(crate) fvk: Option<[u8; 96]>,

    /// A witness from the note to the bundle's anchor.
    ///
    /// - This is set by the Updater.
    /// - This is required by the Prover.
    pub(crate) witness: Option<(u32, [[u8; 32]; 32])>,

    /// The spend authorization randomizer.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the Signer for creating `spend_auth_sig`, and may be used to
    ///   validate `rk`.
    /// - After `zkproof` / `spend_auth_sig` has been set, this can be redacted.
    pub(crate) alpha: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the note
    /// being spent.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    /// The spending key for this spent note, if it is a dummy note.
    ///
    /// - This is chosen by the Constructor.
    /// - This is required by the IO Finalizer, and is cleared by it once used.
    /// - Signers MUST reject PCZTs that contain `dummy_sk` values.
    pub(crate) dummy_sk: Option<[u8; 32]>,

    /// Proprietary fields related to the note being spent.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

/// Information about the output part of an Orchard action.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, Getters)]
pub struct Output {
    //
    // Output-specific Action effecting data.
    //
    // These fields are part of the final transaction. The Constructor fills them in when
    // adding an output, but a sender may omit any of the derived ones (here, `cmx`,
    // `ephemeral_key`, and `enc_ciphertext`) and let the receiver recompute them from the
    // note fields before parsing. See [`Bundle::into_parsed`]. `out_ciphertext` is NOT
    // recomputable (it is derived using RNG), so it remains required.
    //
    #[serde_as(as = "Option<[_; 32]>")]
    #[getset(get = "pub")]
    pub(crate) cmx: Option<[u8; 32]>,
    /// The Orchard-style plaintext version of the note being created.
    ///
    /// This is set by the Constructor, and is required by Verifiers and
    /// Provers to reconstruct the note commitment.
    #[getset(get = "pub")]
    pub(crate) note_version: NotePlaintextVersion,
    #[serde_as(as = "Option<[_; 32]>")]
    #[getset(get = "pub")]
    pub(crate) ephemeral_key: Option<[u8; 32]>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    ///
    /// Once we have memo bundles, we will be able to set memos independently of Outputs.
    /// For now, the Constructor sets both at the same time.
    ///
    /// This may be omitted by a sender and recomputed by the receiver from the note fields
    /// (it is deterministic given the note and the empty memo).
    #[getset(get = "pub")]
    pub(crate) enc_ciphertext: Option<Vec<u8>>,
    /// The encrypted note plaintext for the output.
    ///
    /// Encoded as a `Vec<u8>` because its length depends on the transaction version.
    #[getset(get = "pub")]
    pub(crate) out_ciphertext: Vec<u8>,

    /// The [raw encoding] of the Orchard payment address that will receive the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover.
    ///
    /// [raw encoding]: https://zips.z.cash/protocol/protocol.pdf#orchardpaymentaddrencoding
    #[serde_as(as = "Option<[_; 43]>")]
    #[getset(get = "pub")]
    pub(crate) recipient: Option<[u8; 43]>,

    /// The value of the output.
    ///
    /// This may be used by Signers to verify that the value matches `cv`, and to confirm
    /// the values and change involved in the transaction.
    ///
    /// This exposes the value to all participants. For Signers who don't need this
    /// information, we can drop the values and compress the rcvs into the bsk global.
    #[getset(get = "pub")]
    pub(crate) value: Option<u64>,

    /// The seed randomness for the output.
    ///
    /// - This is set by the Constructor.
    /// - This is required by the Prover, instead of disclosing `shared_secret` to them.
    #[getset(get = "pub")]
    pub(crate) rseed: Option<[u8; 32]>,

    /// The `ock` value used to encrypt `out_ciphertext`.
    ///
    /// This enables Signers to verify that `out_ciphertext` is correctly encrypted.
    ///
    /// This may be `None` if the Constructor added the output using an OVK policy of
    /// "None", to make the output unrecoverable from the chain by the sender.
    pub(crate) ock: Option<[u8; 32]>,

    /// The ZIP 32 derivation path at which the spending key can be found for the output.
    pub(crate) zip32_derivation: Option<Zip32Derivation>,

    /// The user-facing address to which this output is being sent, if any.
    ///
    /// - This is set by an Updater.
    /// - Signers must parse this address (if present) and confirm that it contains
    ///   `recipient` (either directly, or e.g. as a receiver within a Unified Address).
    #[getset(get = "pub")]
    pub(crate) user_address: Option<String>,

    /// Proprietary fields related to the note being created.
    #[getset(get = "pub")]
    pub(crate) proprietary: BTreeMap<String, Vec<u8>>,
}

impl Bundle {
    /// Merges this bundle with another.
    ///
    /// Returns `None` if the bundles have conflicting data.
    pub(crate) fn merge(
        mut self,
        other: Self,
        self_global: &Global,
        other_global: &Global,
    ) -> Option<Self> {
        // Destructure `other` to ensure we handle everything.
        let Self {
            mut actions,
            flags,
            value_sum,
            anchor,
            zkproof,
            bsk,
        } = other;

        if self.flags != flags {
            return None;
        }

        // If `bsk` is set on either bundle, the IO Finalizer has run, which means we
        // cannot have differing numbers of actions, and the value sums must match.
        match (self.bsk.as_mut(), bsk) {
            (Some(lhs), Some(rhs)) if lhs != &rhs => return None,
            (Some(_), _) | (_, Some(_))
                if self.actions.len() != actions.len() || self.value_sum != value_sum =>
            {
                return None;
            }
            // IO Finalizer has run, and neither bundle has excess spends or outputs.
            (Some(_), _) | (_, Some(_)) => (),
            // IO Finalizer has not run on either bundle.
            (None, None) => match (
                self_global.shielded_modifiable(),
                other_global.shielded_modifiable(),
                self.actions.len().cmp(&actions.len()),
            ) {
                // Fail if the merge would add actions to a non-modifiable bundle.
                (false, _, Ordering::Less) | (_, false, Ordering::Greater) => return None,
                // If the other bundle has more actions than us, move them over; these
                // cannot conflict by construction.
                (true, _, Ordering::Less) => {
                    self.actions.extend(actions.drain(self.actions.len()..));

                    // We check below that the overlapping actions match. Assuming here
                    // that they will, we can take the other bundle's value sum.
                    self.value_sum = value_sum;
                }
                // Do nothing otherwise.
                (_, _, Ordering::Equal) | (_, true, Ordering::Greater) => (),
            },
        }

        if self.anchor != anchor {
            return None;
        }

        if !merge_optional(&mut self.zkproof, zkproof) {
            return None;
        }

        // Leverage the early-exit behaviour of zip to confirm that the remaining data in
        // the other bundle matches this one.
        for (lhs, rhs) in self.actions.iter_mut().zip(actions) {
            // Destructure `rhs` to ensure we handle everything.
            let Action {
                cv_net,
                spend:
                    Spend {
                        nullifier,
                        rk,
                        spend_auth_sig,
                        recipient,
                        value,
                        rho,
                        rseed,
                        note_version: spend_note_version,
                        fvk,
                        witness,
                        alpha,
                        zip32_derivation: spend_zip32_derivation,
                        dummy_sk,
                        proprietary: spend_proprietary,
                    },
                output:
                    Output {
                        cmx,
                        note_version: output_note_version,
                        ephemeral_key,
                        enc_ciphertext,
                        out_ciphertext,
                        recipient: output_recipient,
                        value: output_value,
                        rseed: output_rseed,
                        ock,
                        zip32_derivation: output_zip32_derivation,
                        user_address,
                        proprietary: output_proprietary,
                    },
                rcv,
            } = rhs;

            // `note_version` and `out_ciphertext` are required fields that cannot be
            // recomputed, so any divergence is a hard conflict. The six derived fields
            // (`cv_net`, `nullifier`, `rk`, `cmx`, `ephemeral_key`, `enc_ciphertext`) are
            // now optional and are merged via `merge_optional` so a participant that
            // supplies one (e.g. a signatures-only response refilling its clone, or a
            // device recomputing from a leaner request) can fill in a peer's omission.
            if lhs.spend.note_version != spend_note_version
                || lhs.output.note_version != output_note_version
                || lhs.output.out_ciphertext != out_ciphertext
            {
                return None;
            }

            if !(merge_optional(&mut lhs.cv_net, cv_net)
                && merge_optional(&mut lhs.spend.nullifier, nullifier)
                && merge_optional(&mut lhs.spend.rk, rk)
                && merge_optional(&mut lhs.output.cmx, cmx)
                && merge_optional(&mut lhs.output.ephemeral_key, ephemeral_key)
                && merge_optional(&mut lhs.output.enc_ciphertext, enc_ciphertext)
                && merge_optional(&mut lhs.spend.spend_auth_sig, spend_auth_sig)
                && merge_optional(&mut lhs.spend.recipient, recipient)
                && merge_optional(&mut lhs.spend.value, value)
                && merge_optional(&mut lhs.spend.rho, rho)
                && merge_optional(&mut lhs.spend.rseed, rseed)
                && merge_optional(&mut lhs.spend.fvk, fvk)
                && merge_optional(&mut lhs.spend.witness, witness)
                && merge_optional(&mut lhs.spend.alpha, alpha)
                && merge_optional(&mut lhs.spend.zip32_derivation, spend_zip32_derivation)
                && merge_optional(&mut lhs.spend.dummy_sk, dummy_sk)
                && merge_map(&mut lhs.spend.proprietary, spend_proprietary)
                && merge_optional(&mut lhs.output.recipient, output_recipient)
                && merge_optional(&mut lhs.output.value, output_value)
                && merge_optional(&mut lhs.output.rseed, output_rseed)
                && merge_optional(&mut lhs.output.ock, ock)
                && merge_optional(&mut lhs.output.zip32_derivation, output_zip32_derivation)
                && merge_optional(&mut lhs.output.user_address, user_address)
                && merge_map(&mut lhs.output.proprietary, output_proprietary)
                && merge_optional(&mut lhs.rcv, rcv))
            {
                return None;
            }
        }

        Some(self)
    }
}

/// The six derived Orchard-shaped fields after recompute-and-fill, as their byte encodings.
///
/// Produced by [`recompute_derived_fields`] from an [`Action`]: each field is taken verbatim
/// when present on the wire, or recomputed from the action's note-component fields when
/// omitted.
#[cfg(feature = "orchard")]
struct DerivedFields {
    cv_net: [u8; 32],
    nullifier: [u8; 32],
    rk: [u8; 32],
    cmx: [u8; 32],
    ephemeral_key: [u8; 32],
    enc_ciphertext: Vec<u8>,
}

/// Resolves the six derived Orchard-shaped fields of an action, recomputing any that were
/// omitted on the wire.
///
/// The recompute primitives live in the orchard crate (the output `rho` derivation
/// `Rho::from_nf_old` is crate-private there) and are the same primitives that back the
/// `verify_*` comparison methods, so a recomputed value is byte-identical to what a verifier
/// would have checked.
///
/// Ordering hazard: the spend `nullifier` is resolved FIRST, because the output note's `rho`
/// is derived from it, so `cmx`, `ephemeral_key`, and `enc_ciphertext` all depend on the
/// resolved nullifier. `ephemeral_key` and `enc_ciphertext` are recomputed together (they
/// share the note encryptor); if either is omitted, both are recomputed and the wire value is
/// kept for whichever was present.
#[cfg(feature = "orchard")]
fn recompute_derived_fields(action: &Action) -> Result<DerivedFields, orchard::pczt::VerifyError> {
    use orchard::pczt::{recompute, VerifyError};

    let spend = &action.spend;
    let output = &action.output;

    // Resolve the nullifier first (the output rho depends on it).
    let nullifier = match spend.nullifier {
        Some(nullifier) => nullifier,
        None => recompute::nullifier(
            spend.recipient.as_ref().ok_or(VerifyError::MissingRecipient)?,
            spend.value.ok_or(VerifyError::MissingValue)?,
            spend.rho.as_ref().ok_or(VerifyError::MissingRho)?,
            spend.rseed.as_ref().ok_or(VerifyError::MissingRandomSeed)?,
            spend.fvk.as_ref().ok_or(VerifyError::MissingFullViewingKey)?,
            spend.note_version.into(),
        )?,
    };

    let rk = match spend.rk {
        Some(rk) => rk,
        None => recompute::rk(
            spend.fvk.as_ref().ok_or(VerifyError::MissingFullViewingKey)?,
            spend
                .alpha
                .as_ref()
                .ok_or(VerifyError::MissingSpendAuthRandomizer)?,
        )?,
    };

    let cmx = match output.cmx {
        Some(cmx) => cmx,
        None => recompute::cmx(
            output
                .recipient
                .as_ref()
                .ok_or(VerifyError::MissingRecipient)?,
            output.value.ok_or(VerifyError::MissingValue)?,
            &nullifier,
            output.rseed.as_ref().ok_or(VerifyError::MissingRandomSeed)?,
            output.note_version.into(),
        )?,
    };

    let (ephemeral_key, enc_ciphertext) = match (output.ephemeral_key, output.enc_ciphertext.clone())
    {
        (Some(ephemeral_key), Some(enc_ciphertext)) => (ephemeral_key, enc_ciphertext),
        (ephemeral_key, enc_ciphertext) => {
            let (recomputed_epk, recomputed_enc) = recompute::ephemeral_key_and_enc_ciphertext(
                output
                    .recipient
                    .as_ref()
                    .ok_or(VerifyError::MissingRecipient)?,
                output.value.ok_or(VerifyError::MissingValue)?,
                &nullifier,
                output.rseed.as_ref().ok_or(VerifyError::MissingRandomSeed)?,
                output.note_version.into(),
            )?;
            (
                ephemeral_key.unwrap_or(recomputed_epk),
                enc_ciphertext.unwrap_or(recomputed_enc),
            )
        }
    };

    let cv_net = match action.cv_net {
        Some(cv_net) => cv_net,
        None => recompute::cv_net(
            spend.value.ok_or(VerifyError::MissingValue)?,
            output.value.ok_or(VerifyError::MissingValue)?,
            action
                .rcv
                .as_ref()
                .ok_or(VerifyError::MissingValueCommitTrapdoor)?,
        )?,
    };

    Ok(DerivedFields {
        cv_net,
        nullifier,
        rk,
        cmx,
        ephemeral_key,
        enc_ciphertext,
    })
}

#[cfg(feature = "orchard")]
impl Bundle {
    pub(crate) fn into_parsed_orchard(
        self,
        bundle_format: orchard::bundle::BundlePoolRestrictions,
    ) -> Result<orchard::pczt::Bundle, BundleParseError> {
        self.validate_orchard_note_plaintext_versions()?;
        self.into_parsed(bundle_format)
            .map_err(BundleParseError::Parse)
    }

    #[cfg(zcash_unstable = "nu6.3")]
    pub(crate) fn into_parsed_ironwood(self) -> Result<orchard::pczt::Bundle, BundleParseError> {
        self.validate_ironwood_note_plaintext_versions()?;
        self.into_parsed(orchard::bundle::BundlePoolRestrictions::IronwoodNu6_3Onward)
            .map_err(BundleParseError::Parse)
    }

    /// Recompute-and-fill every omitted derived field in place, so that on each
    /// action `cv_net`, `nullifier`, `rk`, `cmx`, `ephemeral_key`, and
    /// `enc_ciphertext` are all `Some`.
    ///
    /// This is the inverse of the redactor's `clear_*` methods. A producer may omit
    /// these fields because they are recomputable from the action's other contents
    /// (the same derivation a verifier runs); a consumer that reads the wire-format
    /// fields directly, rather than parsing the bundle (which already fills them),
    /// calls this first. Each recomputed value is byte-identical to what a verifier
    /// would check; already-present fields are left unchanged.
    ///
    /// This is a strict, lazy per-field fill: a field that is already `Some` is never
    /// recomputed or overwritten, and the expensive cryptographic work behind each
    /// field is performed only when that field is actually missing. In particular the
    /// note-encryption (`recompute::ephemeral_key_and_enc_ciphertext`, one per action)
    /// is run ONLY when `enc_ciphertext` or `ephemeral_key` is omitted. The wallet
    /// always keeps `enc_ciphertext` (the recomputed value is built under a `[0u8; 512]`
    /// memo and does NOT reproduce the real migration output — see the WARNING on
    /// [`recompute::ephemeral_key_and_enc_ciphertext`]), so on the device's inbound path
    /// the note-encryption is never run. Consequently a fully-populated PCZT does ZERO
    /// crypto here.
    ///
    /// [`recompute::ephemeral_key_and_enc_ciphertext`]: orchard::pczt::recompute::ephemeral_key_and_enc_ciphertext
    pub fn fill_derived_fields(&mut self) -> Result<(), orchard::pczt::VerifyError> {
        use orchard::pczt::{recompute, VerifyError};

        for action in &mut self.actions {
            // Resolve the spend nullifier lazily. The output note's `rho` is derived
            // from it, so `cmx`, `ephemeral_key`, and `enc_ciphertext` all need it —
            // but only when at least one of those (or the nullifier itself) is missing.
            // A `None` here means "not yet computed and not yet needed".
            let mut resolved_nullifier = action.spend.nullifier;
            let mut nullifier = |spend: &Spend| -> Result<[u8; 32], VerifyError> {
                if let Some(nf) = resolved_nullifier {
                    return Ok(nf);
                }
                let nf = recompute::nullifier(
                    spend.recipient.as_ref().ok_or(VerifyError::MissingRecipient)?,
                    spend.value.ok_or(VerifyError::MissingValue)?,
                    spend.rho.as_ref().ok_or(VerifyError::MissingRho)?,
                    spend.rseed.as_ref().ok_or(VerifyError::MissingRandomSeed)?,
                    spend.fvk.as_ref().ok_or(VerifyError::MissingFullViewingKey)?,
                    spend.note_version.into(),
                )?;
                resolved_nullifier = Some(nf);
                Ok(nf)
            };

            // cv_net: cheap (a value commitment), only when omitted.
            if action.cv_net.is_none() {
                action.cv_net = Some(recompute::cv_net(
                    action.spend.value.ok_or(VerifyError::MissingValue)?,
                    action.output.value.ok_or(VerifyError::MissingValue)?,
                    action
                        .rcv
                        .as_ref()
                        .ok_or(VerifyError::MissingValueCommitTrapdoor)?,
                )?);
            }

            // rk: cheap (a key randomization), only when omitted.
            if action.spend.rk.is_none() {
                action.spend.rk = Some(recompute::rk(
                    action
                        .spend
                        .fvk
                        .as_ref()
                        .ok_or(VerifyError::MissingFullViewingKey)?,
                    action
                        .spend
                        .alpha
                        .as_ref()
                        .ok_or(VerifyError::MissingSpendAuthRandomizer)?,
                )?);
            }

            // cmx: cheap (a note commitment), only when omitted. Needs the nullifier.
            if action.output.cmx.is_none() {
                let nf = nullifier(&action.spend)?;
                action.output.cmx = Some(recompute::cmx(
                    action
                        .output
                        .recipient
                        .as_ref()
                        .ok_or(VerifyError::MissingRecipient)?,
                    action.output.value.ok_or(VerifyError::MissingValue)?,
                    &nf,
                    action
                        .output
                        .rseed
                        .as_ref()
                        .ok_or(VerifyError::MissingRandomSeed)?,
                    action.output.note_version.into(),
                )?);
            }

            // ephemeral_key + enc_ciphertext: EXPENSIVE (a full note-encryption). Run
            // the recompute ONLY if at least one of the two is missing; whichever is
            // already present is kept verbatim. A fully-populated output (the wallet's
            // inbound case) skips the note-encryption entirely.
            if action.output.ephemeral_key.is_none() || action.output.enc_ciphertext.is_none() {
                let nf = nullifier(&action.spend)?;
                let (recomputed_epk, recomputed_enc) =
                    recompute::ephemeral_key_and_enc_ciphertext(
                        action
                            .output
                            .recipient
                            .as_ref()
                            .ok_or(VerifyError::MissingRecipient)?,
                        action.output.value.ok_or(VerifyError::MissingValue)?,
                        &nf,
                        action
                            .output
                            .rseed
                            .as_ref()
                            .ok_or(VerifyError::MissingRandomSeed)?,
                        action.output.note_version.into(),
                    )?;
                if action.output.ephemeral_key.is_none() {
                    action.output.ephemeral_key = Some(recomputed_epk);
                }
                if action.output.enc_ciphertext.is_none() {
                    action.output.enc_ciphertext = Some(recomputed_enc);
                }
            }

            // nullifier: fill last from whatever we resolved above (it may have been
            // computed for cmx/epk; if nothing needed it and it was omitted, compute
            // it now so the field is populated per this method's contract).
            if action.spend.nullifier.is_none() {
                action.spend.nullifier = Some(nullifier(&action.spend)?);
            }
        }
        Ok(())
    }

    pub(crate) fn into_parsed(
        self,
        bundle_format: orchard::bundle::BundlePoolRestrictions,
    ) -> Result<orchard::pczt::Bundle, orchard::pczt::ParseError> {
        let actions = self
            .actions
            .into_iter()
            .map(|action| {
                // Recompute-and-fill any omitted derived field BEFORE parsing, so the
                // parsed `orchard::pczt` structs are fully populated and every downstream
                // consumer (verifier, prover, signer, extractor) sees a complete action.
                // The recomputed value is byte-identical to what a verifier would have
                // checked (the `recompute` primitives back both paths). A recompute failure
                // (a required component field is missing or invalid) is surfaced as
                // `ParseError::Recompute`.
                let DerivedFields {
                    cv_net,
                    nullifier,
                    rk,
                    cmx,
                    ephemeral_key,
                    enc_ciphertext,
                } = recompute_derived_fields(&action)
                    .map_err(orchard::pczt::ParseError::Recompute)?;

                let spend_note_version = action.spend.note_version;
                let output_note_version = action.output.note_version;

                let spend = orchard::pczt::Spend::parse(
                    nullifier,
                    rk,
                    action.spend.spend_auth_sig,
                    action.spend.recipient,
                    action.spend.value,
                    action.spend.rho,
                    action.spend.rseed,
                    action.spend.fvk,
                    action.spend.witness,
                    action.spend.alpha,
                    action
                        .spend
                        .zip32_derivation
                        .map(|z| {
                            orchard::pczt::Zip32Derivation::parse(
                                z.seed_fingerprint,
                                z.derivation_path,
                            )
                        })
                        .transpose()?,
                    action.spend.dummy_sk,
                    spend_note_version.into(),
                    action.spend.proprietary,
                )?;

                let output = orchard::pczt::Output::parse(
                    *spend.nullifier(),
                    cmx,
                    ephemeral_key,
                    enc_ciphertext,
                    action.output.out_ciphertext,
                    action.output.recipient,
                    action.output.value,
                    action.output.rseed,
                    action.output.ock,
                    action
                        .output
                        .zip32_derivation
                        .map(|z| {
                            orchard::pczt::Zip32Derivation::parse(
                                z.seed_fingerprint,
                                z.derivation_path,
                            )
                        })
                        .transpose()?,
                    action.output.user_address,
                    output_note_version.into(),
                    action.output.proprietary,
                )?;

                orchard::pczt::Action::parse(cv_net, spend, output, action.rcv)
            })
            .collect::<Result<_, _>>()?;

        orchard::pczt::Bundle::parse(
            actions,
            self.flags,
            bundle_format,
            self.value_sum,
            self.anchor,
            self.zkproof,
            self.bsk,
        )
    }

    pub(crate) fn serialize_from(
        bundle: orchard::pczt::Bundle,
        bundle_format: orchard::bundle::BundlePoolRestrictions,
    ) -> Self {
        let actions = bundle
            .actions()
            .iter()
            .map(|action| {
                let spend = action.spend();
                let output = action.output();

                Action {
                    // A parsed `orchard::pczt` bundle always has these derived fields
                    // populated, so serializing back always yields `Some`.
                    cv_net: Some(action.cv_net().to_bytes()),
                    spend: Spend {
                        nullifier: Some(spend.nullifier().to_bytes()),
                        rk: Some(spend.rk().into()),
                        spend_auth_sig: spend.spend_auth_sig().as_ref().map(|s| s.into()),
                        recipient: action
                            .spend()
                            .recipient()
                            .map(|recipient| recipient.to_raw_address_bytes()),
                        value: spend.value().map(|value| value.inner()),
                        rho: spend.rho().map(|rho| rho.to_bytes()),
                        rseed: spend.rseed().map(|rseed| *rseed.as_bytes()),
                        note_version: (*spend.note_version()).into(),
                        fvk: spend.fvk().as_ref().map(|fvk| fvk.to_bytes()),
                        witness: spend.witness().as_ref().map(|witness| {
                            (
                                u32::try_from(u64::from(witness.position()))
                                    .expect("Sapling positions fit in u32"),
                                witness
                                    .auth_path()
                                    .iter()
                                    .map(|node| node.to_bytes())
                                    .collect::<Vec<_>>()[..]
                                    .try_into()
                                    .expect("path is length 32"),
                            )
                        }),
                        alpha: spend.alpha().map(|alpha| alpha.to_repr()),
                        zip32_derivation: spend.zip32_derivation().as_ref().map(|z| {
                            Zip32Derivation {
                                seed_fingerprint: *z.seed_fingerprint(),
                                derivation_path: z
                                    .derivation_path()
                                    .iter()
                                    .map(|i| i.index())
                                    .collect(),
                            }
                        }),
                        dummy_sk: action
                            .spend()
                            .dummy_sk()
                            .map(|dummy_sk| *dummy_sk.to_bytes()),
                        proprietary: spend.proprietary().clone(),
                    },
                    output: Output {
                        cmx: Some(output.cmx().to_bytes()),
                        note_version: (*output.note_version()).into(),
                        ephemeral_key: Some(output.encrypted_note().epk_bytes),
                        enc_ciphertext: Some(output.encrypted_note().enc_ciphertext.to_vec()),
                        out_ciphertext: output.encrypted_note().out_ciphertext.to_vec(),
                        recipient: action
                            .output()
                            .recipient()
                            .map(|recipient| recipient.to_raw_address_bytes()),
                        value: output.value().map(|value| value.inner()),
                        rseed: output.rseed().map(|rseed| *rseed.as_bytes()),
                        ock: output.ock().as_ref().map(|ock| ock.0),
                        zip32_derivation: output.zip32_derivation().as_ref().map(|z| {
                            Zip32Derivation {
                                seed_fingerprint: *z.seed_fingerprint(),
                                derivation_path: z
                                    .derivation_path()
                                    .iter()
                                    .map(|i| i.index())
                                    .collect(),
                            }
                        }),
                        user_address: output.user_address().clone(),
                        proprietary: output.proprietary().clone(),
                    },
                    rcv: action.rcv().as_ref().map(|rcv| rcv.to_bytes()),
                }
            })
            .collect();

        let value_sum = {
            let (magnitude, sign) = bundle.value_sum().magnitude_sign();
            (magnitude, matches!(sign, orchard::value::Sign::Negative))
        };

        Self {
            actions,
            flags: bundle
                .flags()
                .to_byte(bundle_format)
                .expect("PCZT Orchard-style flags must encode in the requested bundle format"),
            value_sum,
            anchor: bundle.anchor().to_bytes(),
            zkproof: bundle
                .zkproof()
                .as_ref()
                .map(|zkproof| zkproof.as_ref().to_vec()),
            bsk: bundle.bsk().as_ref().map(|bsk| bsk.into()),
        }
    }
}
