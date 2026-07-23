# zcash_primitives — proving-key cache branch

This branch carries the crates.io `zcash_primitives 0.29.0` source with one
change: `Builder::build` memoizes the Orchard proving key per circuit version
instead of rebuilding it (several seconds) on every call.

It exists to be referenced from `[patch.crates-io]` by valargroup/kresko, which
otherwise rebuilds the proving key on every transaction. Measured effect: ~2.3x
faster steady-state transaction building.

Base: crates.io zcash_primitives 0.29.0 (repository zcash/librustzcash).
The only functional diff is in src/transaction/builder.rs — see
`cached_orchard_proving_key`.
