//! Types related to computation of fees and change related to the Orchard components
//! of a transaction.

use std::convert::Infallible;

use orchard::{builder::BundleType, bundle::BundleVersion};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

pub(crate) fn bundle_pool_restrictions_for_target_height<P: consensus::Parameters>(
    params: &P,
    target_height: BlockHeight,
) -> BundleVersion {
    #[cfg(zcash_unstable = "nu6.3")]
    if params.is_nu_active(consensus::NetworkUpgrade::Nu6_3, target_height) {
        return BundleVersion::orchard_v3();
    }

    if params.is_nu_active(consensus::NetworkUpgrade::Nu6_2, target_height) {
        BundleVersion::orchard_v2()
    } else {
        BundleVersion::orchard_insecure_v1()
    }
}

pub(crate) fn transactional_action_count(
    bundle_version: BundleVersion,
    num_spends: usize,
    num_outputs: usize,
) -> Result<usize, &'static str> {
    // These bundles are always built with `BundleType::DEFAULT` (non-coinbase), so the
    // action count uses the bundle version's default flags, matching how the orchard
    // builder is constructed in `zcash_primitives`.
    BundleType::DEFAULT.num_actions(bundle_version.default_flags(), num_spends, num_outputs)
}

/// A trait that provides a minimized view of Orchard bundle configuration
/// suitable for use in fee and change calculation.
pub trait BundleView<NoteRef> {
    /// The type of inputs to the bundle.
    type In: InputView<NoteRef>;
    /// The type of inputs of the bundle.
    type Out: OutputView;

    /// Returns the inputs to the bundle.
    fn inputs(&self) -> &[Self::In];
    /// Returns the outputs of the bundle.
    fn outputs(&self) -> &[Self::Out];
}

impl<'a, NoteRef, In: InputView<NoteRef>, Out: OutputView> BundleView<NoteRef>
    for (&'a [In], &'a [Out])
{
    type In = In;
    type Out = Out;

    fn inputs(&self) -> &[In] {
        self.0
    }

    fn outputs(&self) -> &[Out] {
        self.1
    }
}

/// A [`BundleView`] for an empty Orchard bundle.
pub struct EmptyBundleView;

impl<NoteRef> BundleView<NoteRef> for EmptyBundleView {
    type In = Infallible;
    type Out = Infallible;

    fn inputs(&self) -> &[Self::In] {
        &[]
    }

    fn outputs(&self) -> &[Self::Out] {
        &[]
    }
}

/// A trait that provides a minimized view of an Orchard input suitable for use in fee and change
/// calculation.
pub trait InputView<NoteRef> {
    /// An identifier for the input being spent.
    fn note_id(&self) -> &NoteRef;
    /// The value of the input being spent.
    fn value(&self) -> Zatoshis;
    /// Returns whether this input is an Ironwood note.
    #[cfg(zcash_unstable = "nu6.3")]
    fn is_ironwood(&self) -> bool {
        false
    }
}

impl<N> InputView<N> for Infallible {
    fn note_id(&self) -> &N {
        unreachable!()
    }
    fn value(&self) -> Zatoshis {
        unreachable!()
    }
}

/// A trait that provides a minimized view of a Orchard output suitable for use in fee and change
/// calculation.
pub trait OutputView {
    /// The value of the output being produced.
    fn value(&self) -> Zatoshis;
}

impl OutputView for Infallible {
    fn value(&self) -> Zatoshis {
        unreachable!()
    }
}

impl OutputView for Zatoshis {
    fn value(&self) -> Zatoshis {
        *self
    }
}
