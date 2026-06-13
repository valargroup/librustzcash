use orchard::circuit::ProvingKey;
use rand_core::OsRng;

use crate::Pczt;

impl super::Prover {
    pub fn create_orchard_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            #[cfg(zcash_unstable = "nu7")]
            ironwood,
        } = self.pczt;

        let mut bundle = orchard
            .into_parsed_orchard()
            .map_err(OrchardError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard: crate::orchard::Bundle::serialize_from(bundle),
                #[cfg(zcash_unstable = "nu7")]
                ironwood,
            },
        })
    }

    /// Creates an Ironwood proof.
    ///
    /// Returns an error before proof creation if the PCZT is not version 6 on NU7.
    #[cfg(zcash_unstable = "nu7")]
    pub fn create_ironwood_proof(self, pk: &ProvingKey) -> Result<Self, OrchardError> {
        let Pczt {
            global,
            transparent,
            sapling,
            orchard,
            ironwood,
        } = self.pczt;

        crate::common::ensure_v6_nu7(&global)
            .map_err(crate::orchard::BundleParseError::from)
            .map_err(OrchardError::Parser)?;

        let mut bundle = ironwood
            .into_parsed_ironwood()
            .map_err(OrchardError::Parser)?;

        bundle
            .create_proof(pk, OsRng)
            .map_err(OrchardError::Prover)?;

        Ok(Self {
            pczt: Pczt {
                global,
                transparent,
                sapling,
                orchard,
                ironwood: crate::orchard::Bundle::serialize_from(bundle),
            },
        })
    }
}

/// Errors that can occur while creating Orchard proofs for a PCZT.
#[derive(Debug)]
pub enum OrchardError {
    Parser(crate::orchard::BundleParseError),
    Prover(orchard::pczt::ProverError),
}
