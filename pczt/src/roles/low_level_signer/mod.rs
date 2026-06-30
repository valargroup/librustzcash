//! A low-level variant of the Signer role, for dependency-constrained environments.

use crate::Pczt;

pub struct Signer {
    pczt: Pczt,
}

impl Signer {
    /// Instantiates the low-level Signer role with the given PCZT.
    pub fn new(pczt: Pczt) -> Self {
        Self { pczt }
    }

    /// Exposes the capability to sign the Orchard spends.
    #[cfg(feature = "orchard")]
    pub fn sign_orchard_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<crate::orchard::BundleParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;
        let bundle_format = crate::orchard_bundle_format(&pczt.global);

        let fvk_snapshot = snapshot_spend_fvks(&pczt.orchard);
        let mut bundle = pczt
            .orchard
            .clone()
            .into_parsed_orchard_for_signing(bundle_format)?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.orchard = crate::orchard::Bundle::serialize_from(bundle, bundle_format);
        restore_spend_fvks(&mut pczt.orchard, &fvk_snapshot);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Ironwood spends.
    ///
    /// Returns an error without invoking the closure if the PCZT is not version 6 on
    /// NU6.3.
    #[cfg(all(feature = "orchard", zcash_unstable = "nu6.3"))]
    pub fn sign_ironwood_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<crate::orchard::BundleParseError>,
        F: FnOnce(&Pczt, &mut orchard::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        crate::common::ensure_v6_consensus_branch(&pczt.global)
            .map_err(crate::orchard::BundleParseError::from)?;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let fvk_snapshot = snapshot_spend_fvks(&pczt.ironwood);
        let mut bundle = pczt.ironwood.clone().into_parsed_ironwood_for_signing()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.ironwood = crate::orchard::Bundle::serialize_from(
            bundle,
            orchard::bundle::BundleVersion::ironwood_v3(),
        );
        restore_spend_fvks(&mut pczt.ironwood, &fvk_snapshot);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the Sapling spends.
    #[cfg(feature = "sapling")]
    pub fn sign_sapling_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<sapling::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut sapling::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.sapling.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.sapling = crate::sapling::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Exposes the capability to sign the transparent spends.
    #[cfg(feature = "transparent")]
    pub fn sign_transparent_with<E, F>(self, f: F) -> Result<Self, E>
    where
        E: From<transparent::pczt::ParseError>,
        F: FnOnce(&Pczt, &mut transparent::pczt::Bundle, &mut u8) -> Result<(), E>,
    {
        let mut pczt = self.pczt;

        let mut tx_modifiable = pczt.global.tx_modifiable;

        let mut bundle = pczt.transparent.clone().into_parsed()?;

        f(&pczt, &mut bundle, &mut tx_modifiable)?;

        pczt.global.tx_modifiable = tx_modifiable;
        pczt.transparent = crate::transparent::Bundle::serialize_from(bundle);

        Ok(Self { pczt })
    }

    /// Finishes the low-level Signer role, returning the updated PCZT.
    pub fn finish(self) -> Pczt {
        self.pczt
    }
}

#[cfg(feature = "orchard")]
fn snapshot_spend_fvks(bundle: &crate::orchard::Bundle) -> alloc::vec::Vec<Option<[u8; 96]>> {
    bundle
        .actions()
        .iter()
        .map(|action| action.spend.fvk)
        .collect()
}

#[cfg(feature = "orchard")]
fn restore_spend_fvks(bundle: &mut crate::orchard::Bundle, snapshot: &[Option<[u8; 96]>]) {
    for (action, fvk) in bundle.actions.iter_mut().zip(snapshot.iter()) {
        if fvk.is_some() {
            action.spend.fvk = *fvk;
        }
    }
}

#[cfg(all(test, feature = "orchard"))]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec::Vec;

    use crate::orchard::{Action, Bundle, NotePlaintextVersion, Output, Spend};

    use super::{restore_spend_fvks, snapshot_spend_fvks};

    #[test]
    fn restore_spend_fvks_preserves_original_wire_fields() {
        let original_fvk = Some([7u8; 96]);
        let inserted_fvk = Some([9u8; 96]);
        let mut bundle = bundle_with_fvks([original_fvk, None]);
        let snapshot = snapshot_spend_fvks(&bundle);

        bundle.actions[0].spend.fvk = None;
        bundle.actions[1].spend.fvk = inserted_fvk;

        restore_spend_fvks(&mut bundle, &snapshot);

        assert_eq!(bundle.actions[0].spend.fvk, original_fvk);
        assert_eq!(bundle.actions[1].spend.fvk, inserted_fvk);
    }

    fn bundle_with_fvks(fvks: [Option<[u8; 96]>; 2]) -> Bundle {
        Bundle {
            actions: fvks.into_iter().map(action_with_fvk).collect(),
            flags: 0,
            value_sum: (0, false),
            anchor: [0; 32],
            zkproof: None,
            bsk: None,
        }
    }

    fn action_with_fvk(fvk: Option<[u8; 96]>) -> Action {
        Action {
            cv_net: [0; 32],
            spend: Spend {
                nullifier: [0; 32],
                rk: [1; 32],
                spend_auth_sig: None,
                recipient: None,
                value: None,
                rho: None,
                rseed: None,
                note_version: NotePlaintextVersion::V2,
                fvk,
                witness: None,
                alpha: None,
                zip32_derivation: None,
                dummy_sk: None,
                proprietary: BTreeMap::new(),
            },
            output: Output {
                cmx: [0; 32],
                note_version: NotePlaintextVersion::V2,
                ephemeral_key: [0; 32],
                enc_ciphertext: Vec::new(),
                out_ciphertext: Vec::new(),
                recipient: None,
                value: None,
                rseed: None,
                ock: None,
                zip32_derivation: None,
                user_address: Option::<String>::None,
                proprietary: BTreeMap::new(),
            },
            rcv: None,
        }
    }
}
