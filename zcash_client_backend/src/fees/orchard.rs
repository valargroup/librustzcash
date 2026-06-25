//! Types related to computation of fees and change related to the Orchard components
//! of a transaction.

use std::convert::Infallible;

use orchard::{builder::BundleType, bundle::BundlePoolRestrictions};
use zcash_protocol::{
    consensus::{self, BlockHeight},
    value::Zatoshis,
};

pub(crate) fn bundle_pool_restrictions_for_target_height<P: consensus::Parameters>(
    params: &P,
    target_height: BlockHeight,
) -> BundlePoolRestrictions {
    #[cfg(zcash_unstable = "nu6.3")]
    if params.is_nu_active(consensus::NetworkUpgrade::Nu6_3, target_height) {
        return BundlePoolRestrictions::OrchardNu6_3Onward;
    }

    if params.is_nu_active(consensus::NetworkUpgrade::Nu6_2, target_height) {
        BundlePoolRestrictions::OrchardNu6_2Only
    } else {
        BundlePoolRestrictions::OrchardPreNu6_2
    }
}

pub(crate) fn transactional_action_count(
    pool_restrictions: BundlePoolRestrictions,
    num_spends: usize,
    num_outputs: usize,
) -> Result<usize, &'static str> {
    BundleType::DEFAULT.num_actions(num_spends, num_outputs, pool_restrictions)
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
