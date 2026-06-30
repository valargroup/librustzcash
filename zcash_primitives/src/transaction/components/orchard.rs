//! Functions for parsing & serialization of Orchard transaction components.
use crate::encoding::ReadBytesExt;

use alloc::vec::Vec;
use core::convert::TryFrom;
use corez::io::{self, Read, Write};

use nonempty::NonEmpty;

use orchard::{
    Action, Anchor,
    bundle::{Authorization, Authorized, BundleVersion, Flags},
    note::{ExtractedNoteCommitment, Nullifier, TransmittedNoteCiphertext},
    primitives::redpallas::{self, SigType, Signature, SpendAuth, VerificationKey},
    value::ValueCommitment,
};
use zcash_encoding::{Array, CompactSize, Vector};
use zcash_protocol::{consensus::BranchId, value::ZatBalance};

use crate::transaction::Transaction;

pub const FLAG_SPENDS_ENABLED: u8 = 0b0000_0001;
pub const FLAG_OUTPUTS_ENABLED: u8 = 0b0000_0010;
pub const FLAGS_EXPECTED_UNSET: u8 = !(FLAG_SPENDS_ENABLED | FLAG_OUTPUTS_ENABLED);

pub trait MapAuth<A: Authorization, B: Authorization> {
    fn map_spend_auth(&self, s: A::SpendAuth) -> B::SpendAuth;
    fn map_authorization(&self, a: A) -> B;
}

/// The identity map.
///
/// This can be used with [`TransactionData::map_authorization`] when you want to map the
/// authorization of a subset of the transaction's bundles.
///
/// [`TransactionData::map_authorization`]: crate::transaction::TransactionData::map_authorization
impl MapAuth<Authorized, Authorized> for () {
    fn map_spend_auth(
        &self,
        s: <Authorized as Authorization>::SpendAuth,
    ) -> <Authorized as Authorization>::SpendAuth {
        s
    }

    fn map_authorization(&self, a: Authorized) -> Authorized {
        a
    }
}

fn read_bundle<R: Read>(
    mut reader: R,
    bundle_version: BundleVersion,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    #[allow(clippy::redundant_closure)]
    let actions_without_auth = Vector::read(&mut reader, |r| read_action_without_auth(r))?;
    if actions_without_auth.is_empty() {
        Ok(None)
    } else {
        let flags = read_flags(&mut reader, bundle_version)?;
        let value_balance = Transaction::read_amount(&mut reader)?;
        let anchor = read_anchor(&mut reader)?;
        let proof_bytes = Vector::read(&mut reader, |r| r.read_u8())?;
        let actions = NonEmpty::from_vec(
            actions_without_auth
                .into_iter()
                .map(|act| act.try_map(|_| read_signature::<_, redpallas::SpendAuth>(&mut reader)))
                .collect::<Result<Vec<_>, _>>()?,
        )
        .expect("A nonzero number of actions was read from the transaction data.");
        let binding_signature = read_signature::<_, redpallas::Binding>(&mut reader)?;

        let authorization = orchard::bundle::Authorized::from_parts(
            orchard::Proof::new(proof_bytes),
            binding_signature,
        );

        // `try_from_parts` rejects a proof whose length is not the canonical size for the
        // number of actions, preventing a proof padded with arbitrary data (GHSA-2x4w-pxqw-58v9).
        // The proof-size check is enforced for every bundle version except the historical
        // pre-NU6.2 Orchard pool (`orchard_insecure_v1`); the branch-derived `BundleVersion`
        // carries that Unenforced/Strict distinction internally (via
        // `BundleVersion::enforces_canonical_proof_size`).
        orchard::Bundle::try_from_parts(
            actions,
            flags,
            value_balance,
            anchor,
            authorization,
            bundle_version,
        )
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

/// Reads an [`orchard::Bundle`] from a v5 transaction format.
///
/// The Orchard [`BundleVersion`] is selected from the transaction's consensus branch:
/// per ZIP 229 the pool restriction (and hence the flag decoding and the proof-size
/// enforcement, both carried by the bundle version) is keyed on the branch rather than
/// the transaction version, and it must agree with how the bundle was committed.
pub fn read_v5_bundle<R: Read>(
    reader: R,
    consensus_branch_id: BranchId,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(
        reader,
        crate::transaction::builder::orchard_protocol_for_branch(consensus_branch_id),
    )
}

#[cfg(any(
    zcash_unstable = "zfuture",
    zcash_unstable = "nu6.3",
    zcash_unstable = "nu7"
))]
pub fn read_v6_bundle<R: Read>(
    reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(reader, BundleVersion::orchard_v3())
}

pub fn read_value_commitment<R: Read>(mut reader: R) -> io::Result<ValueCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cv = ValueCommitment::from_bytes(&bytes);

    if cv.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for value commitment",
        ))
    } else {
        Ok(cv.unwrap())
    }
}

pub fn read_nullifier<R: Read>(mut reader: R) -> io::Result<Nullifier> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let nullifier_ctopt = Nullifier::from_bytes(&bytes);
    if nullifier_ctopt.is_none().into() {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas point for nullifier",
        ))
    } else {
        Ok(nullifier_ctopt.unwrap())
    }
}

pub fn read_verification_key<R: Read>(mut reader: R) -> io::Result<VerificationKey<SpendAuth>> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    VerificationKey::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid verification key"))
}

pub fn read_cmx<R: Read>(mut reader: R) -> io::Result<ExtractedNoteCommitment> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    let cmx = ExtractedNoteCommitment::from_bytes(&bytes);
    Option::from(cmx).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid Pallas base for field cmx",
        )
    })
}

pub fn read_note_ciphertext<R: Read>(mut reader: R) -> io::Result<TransmittedNoteCiphertext> {
    let mut tnc = TransmittedNoteCiphertext {
        epk_bytes: [0u8; 32],
        enc_ciphertext: [0u8; 580],
        out_ciphertext: [0u8; 80],
    };

    reader.read_exact(&mut tnc.epk_bytes)?;
    reader.read_exact(&mut tnc.enc_ciphertext)?;
    reader.read_exact(&mut tnc.out_ciphertext)?;

    Ok(tnc)
}

pub fn read_action_without_auth<R: Read>(mut reader: R) -> io::Result<Action<()>> {
    let cv_net = read_value_commitment(&mut reader)?;
    let nf_old = read_nullifier(&mut reader)?;
    let rk = read_verification_key(&mut reader)?;
    let cmx = read_cmx(&mut reader)?;
    let encrypted_note = read_note_ciphertext(&mut reader)?;

    Action::from_parts(nf_old, rk, cmx, encrypted_note, cv_net, ())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

pub fn read_flags<R: Read>(mut reader: R, bundle_version: BundleVersion) -> io::Result<Flags> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Flags::from_byte(byte[0], bundle_version)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard flags"))
}

pub fn read_anchor<R: Read>(mut reader: R) -> io::Result<Anchor> {
    let mut bytes = [0u8; 32];
    reader.read_exact(&mut bytes)?;
    Option::from(Anchor::from_bytes(bytes))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid Orchard anchor"))
}

pub fn read_signature<R: Read, T: SigType>(mut reader: R) -> io::Result<Signature<T>> {
    let mut bytes = [0u8; 64];
    reader.read_exact(&mut bytes)?;
    Ok(Signature::from(bytes))
}

fn write_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    mut writer: W,
    bundle_version: BundleVersion,
) -> io::Result<()> {
    if let Some(bundle) = &bundle {
        Vector::write_nonempty(&mut writer, bundle.actions(), |w, a| {
            write_action_without_auth(w, a)
        })?;

        let flags = bundle.flags().to_byte(bundle_version).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Orchard flags cannot be encoded in this transaction format",
            )
        })?;
        writer.write_all(&[flags])?;
        writer.write_all(&bundle.value_balance().to_i64_le_bytes())?;
        writer.write_all(&bundle.anchor().to_bytes())?;
        Vector::write(
            &mut writer,
            bundle.authorization().proof().as_ref(),
            |w, b| w.write_all(&[*b]),
        )?;
        Array::write(
            &mut writer,
            bundle.actions().iter().map(|a| a.authorization()),
            |w, auth| w.write_all(&<[u8; 64]>::from(*auth)),
        )?;
        writer.write_all(&<[u8; 64]>::from(
            bundle.authorization().binding_signature(),
        ))?;
    } else {
        CompactSize::write(&mut writer, 0)?;
    }

    Ok(())
}

/// Writes an [`orchard::Bundle`] in the v5 transaction format.
pub fn write_v5_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
    consensus_branch_id: BranchId,
) -> io::Result<()> {
    write_bundle(
        bundle,
        writer,
        crate::transaction::builder::orchard_protocol_for_branch(consensus_branch_id),
    )
}

#[cfg(any(
    zcash_unstable = "zfuture",
    zcash_unstable = "nu6.3",
    zcash_unstable = "nu7"
))]
pub fn write_v6_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    write_bundle(bundle, writer, BundleVersion::orchard_v3())
}

/// Reads an Ironwood-pool [`orchard::Bundle`] from a v6 transaction.
///
/// Same wire format as [`read_v6_bundle`], but parses flags under the Ironwood
/// bundle version, which (unlike the Orchard pool) permits the v6
/// cross-address flag bit.
#[cfg(zcash_unstable = "nu6.3")]
pub fn read_ironwood_v6_bundle<R: Read>(
    reader: R,
) -> io::Result<Option<orchard::Bundle<Authorized, ZatBalance>>> {
    read_bundle(reader, BundleVersion::ironwood_v3())
}

/// Writes an Ironwood-pool [`orchard::Bundle`] in the v6 transaction format.
#[cfg(zcash_unstable = "nu6.3")]
pub fn write_ironwood_v6_bundle<W: Write>(
    bundle: Option<&orchard::Bundle<Authorized, ZatBalance>>,
    writer: W,
) -> io::Result<()> {
    write_bundle(bundle, writer, BundleVersion::ironwood_v3())
}

pub fn write_value_commitment<W: Write>(mut writer: W, cv: &ValueCommitment) -> io::Result<()> {
    writer.write_all(&cv.to_bytes())
}

pub fn write_nullifier<W: Write>(mut writer: W, nf: &Nullifier) -> io::Result<()> {
    writer.write_all(&nf.to_bytes())
}

pub fn write_verification_key<W: Write>(
    mut writer: W,
    rk: &redpallas::VerificationKey<SpendAuth>,
) -> io::Result<()> {
    writer.write_all(&<[u8; 32]>::from(rk))
}

pub fn write_cmx<W: Write>(mut writer: W, cmx: &ExtractedNoteCommitment) -> io::Result<()> {
    writer.write_all(&cmx.to_bytes())
}

pub fn write_note_ciphertext<W: Write>(
    mut writer: W,
    nc: &TransmittedNoteCiphertext,
) -> io::Result<()> {
    writer.write_all(&nc.epk_bytes)?;
    writer.write_all(&nc.enc_ciphertext)?;
    writer.write_all(&nc.out_ciphertext)
}

pub fn write_action_without_auth<W: Write>(
    mut writer: W,
    act: &Action<<Authorized as Authorization>::SpendAuth>,
) -> io::Result<()> {
    write_value_commitment(&mut writer, act.cv_net())?;
    write_nullifier(&mut writer, act.nullifier())?;
    write_verification_key(&mut writer, act.rk())?;
    write_cmx(&mut writer, act.cmx())?;
    write_note_ciphertext(&mut writer, act.encrypted_note())?;
    Ok(())
}

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use proptest::prelude::*;

    use orchard::bundle::{
        Authorized, Bundle,
        testing::{self as t_orch},
    };
    use zcash_protocol::value::{ZatBalance, testing::arb_zat_balance};

    use crate::transaction::TxVersion;

    prop_compose! {
        pub fn arb_bundle(n_actions: usize)(
            orchard_value_balance in arb_zat_balance(),
            bundle in t_orch::arb_bundle(n_actions)
        ) -> Bundle<Authorized, ZatBalance> {
            // overwrite the value balance, as we can't guarantee that the
            // value doesn't exceed the MAX_MONEY bounds.
            bundle.try_map_value_balance::<_, (), _>(|_| Ok(orchard_value_balance)).unwrap()
        }
    }

    pub fn arb_bundle_for_version(
        v: TxVersion,
    ) -> impl Strategy<Value = Option<Bundle<Authorized, ZatBalance>>> {
        if v.has_orchard() {
            // The Orchard slot's bundle version is selected by the transaction version
            // (see `orchard_pool_forbids_cross_address`): a v6 transaction encodes the
            // Orchard pool as `orchard_v3()`, which forbids cross-address transfers, while
            // a v5 transaction encodes it as a pre-NU6.3 Orchard version (`orchard_v2()`),
            // which requires cross-address transfers.
            //
            // `orchard::bundle::testing::arb_bundle` produces bundles of an *arbitrary*
            // `BundleVersion` (including the Ironwood pool, and either cross-address
            // setting). Such a bundle is not necessarily representable in this Orchard
            // slot — e.g. an Ironwood bundle cannot be committed in a v5 transaction, and
            // a cross-address-disabled bundle cannot be encoded in a pre-NU6.3 Orchard
            // slot. Coerce the arbitrary bundle into the Orchard-pool `BundleVersion` the
            // slot requires (preserving its spends/outputs flags), so the resulting
            // transaction round-trips and commits.
            let force_cross_address_disabled = orchard_pool_forbids_cross_address(v);
            (1usize..100)
                .prop_flat_map(move |n| {
                    prop::option::of(arb_bundle(n).prop_map(move |bundle| {
                        if force_cross_address_disabled {
                            with_orchard_bundle_version(bundle, false)
                        } else {
                            with_orchard_bundle_version(bundle, true)
                        }
                    }))
                })
                .boxed()
        } else {
            Just(None).boxed()
        }
    }

    /// Mirrors `txid::orchard_commitment_domain`: v6 (and zfuture) Orchard bundles
    /// use `orchard_v3()`, which forbids cross-address transfers; v5 uses
    /// `orchard_v2()`, which requires them enabled.
    fn orchard_pool_forbids_cross_address(v: TxVersion) -> bool {
        #[cfg(zcash_unstable = "nu6.3")]
        if matches!(v, TxVersion::V6) {
            return true;
        }
        #[cfg(all(zcash_unstable = "nu7", not(zcash_unstable = "nu6.3")))]
        if matches!(v, TxVersion::V6) {
            return true;
        }
        #[cfg(zcash_unstable = "zfuture")]
        if matches!(v, TxVersion::ZFuture) {
            return true;
        }
        let _ = v;
        false
    }

    /// Rebuilds an Orchard bundle under the Orchard-pool [`BundleVersion`](orchard::bundle::BundleVersion)
    /// required by an Orchard transaction slot (preserving its spends/outputs flags).
    ///
    /// `cross_address_enabled` selects the slot's version: `false` rebuilds under
    /// `orchard_v3()` (the NU6.3-onward Orchard pool, which forbids cross-address
    /// transfers), `true` under `orchard_v2()` (a pre-NU6.3 Orchard pool, which requires
    /// them). Both encode a flag byte with bit 2 clear (the spends/outputs bits only), so
    /// the action set's note ciphertexts are unchanged; only the bundle's recorded version
    /// and cross-address flag interpretation differ. This coerces an arbitrary-version
    /// `arb_bundle` (which may be in the Ironwood pool, or have the opposite cross-address
    /// setting) into a bundle the slot can serialize and commit to.
    fn with_orchard_bundle_version(
        bundle: Bundle<Authorized, ZatBalance>,
        cross_address_enabled: bool,
    ) -> Bundle<Authorized, ZatBalance> {
        use orchard::bundle::{BundleVersion, Flags};
        let bundle_version = if cross_address_enabled {
            BundleVersion::orchard_v2()
        } else {
            BundleVersion::orchard_v3()
        };
        let byte = u8::from(bundle.flags().spends_enabled())
            | (u8::from(bundle.flags().outputs_enabled()) << 1);
        let flags = Flags::from_byte(byte, bundle_version)
            .expect("spends/outputs-only flags encode under an Orchard bundle version");
        orchard::Bundle::try_from_parts(
            bundle.actions().clone(),
            flags,
            *bundle.value_balance(),
            *bundle.anchor(),
            bundle.authorization().clone(),
            bundle_version,
        )
        .expect("coercing to an Orchard bundle version yields a representable bundle")
    }
}
