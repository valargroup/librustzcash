//! # Regtest constants
//!
//! `regtest` is a `zcashd`-specific environment used for local testing. They mostly reuse
//! the testnet constants.
//! These constants are defined in [the `zcashd` codebase].
//!
//! [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L482-L496>
//!
//! ## Opt-in mainnet-masquerade (`--cfg zcash_regtest_mainnet_keys`)
//!
//! When the crate is built with the `zcash_regtest_mainnet_keys` cfg (set via `RUSTFLAGS`,
//! OFF by default), every Regtest constant below takes its **mainnet** value instead. This
//! makes a regtest network derive (BIP-44 coin type `133'`) and encode (`u`/`uview`/`zs`/`t1`
//! HRPs) exactly like mainnet, so a normal-mode hardware wallet works against a private
//! Ironwood/NU6.3 test chain without a "testnet mode" toggle.
//!
//! This is a TEST-ONLY masquerade for an isolated chain. It is opt-in via a build cfg (not a
//! cargo feature) precisely so it cannot be enabled transitively by a dependency — when the cfg
//! is absent, Mainnet/Testnet/Regtest behaviour is byte-for-byte unchanged. The cfg must also be
//! honoured by `zcash_address::convert_if_network` (a sibling crate) for decode round-trips to
//! work; see that function.

/// The regtest cointype reuses the testnet cointype.
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const COIN_TYPE: u32 = 1;
/// Mainnet-masquerade: regtest derives at the mainnet coin type (`133'`).
#[cfg(zcash_regtest_mainnet_keys)]
pub const COIN_TYPE: u32 = super::mainnet::COIN_TYPE;

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedSpendingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedSpendingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedSpendingKey.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L496>
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = "secret-extended-key-regtest";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_SAPLING_EXTENDED_SPENDING_KEY: &str = super::mainnet::HRP_SAPLING_EXTENDED_SPENDING_KEY;

/// The HRP for a Bech32-encoded regtest Sapling [`ExtendedFullViewingKey`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`ExtendedFullViewingKey`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/zip32/struct.ExtendedFullViewingKey.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L494>
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = "zxviewregtestsapling";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY: &str = super::mainnet::HRP_SAPLING_EXTENDED_FULL_VIEWING_KEY;

/// The HRP for a Bech32-encoded regtest Sapling [`PaymentAddress`].
///
/// It is defined in [the `zcashd` codebase].
///
/// [`PaymentAddress`]: https://docs.rs/sapling-crypto/latest/sapling_crypto/struct.PaymentAddress.html
/// [the `zcashd` codebase]: <https://github.com/zcash/zcash/blob/128d863fb8be39ee294fda397c1ce3ba3b889cb2/src/chainparams.cpp#L493>
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = "zregtestsapling";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_SAPLING_PAYMENT_ADDRESS: &str = super::mainnet::HRP_SAPLING_PAYMENT_ADDRESS;

/// The prefix for a Base58Check-encoded regtest Sprout address.
///
/// Defined in the [Zcash Protocol Specification section 5.6.3][sproutpaymentaddrencoding].
/// Same as the testnet prefix.
///
/// [sproutpaymentaddrencoding]: https://zips.z.cash/protocol/protocol.pdf#sproutpaymentaddrencoding
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = [0x16, 0xb6];
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const B58_SPROUT_ADDRESS_PREFIX: [u8; 2] = super::mainnet::B58_SPROUT_ADDRESS_PREFIX;

/// The prefix for a Base58Check-encoded DER-encoded regtest [`SecretKey`], as specified via the
/// bitcoin-derived [`EncodeSecret`] format function.
///
/// [`SecretKey`]: https://docs.rs/secp256k1/latest/secp256k1/struct.SecretKey.html
/// [`EncodeSecret`]: https://github.com/zcash/zcash/blob/1f1f7a385adc048154e7f25a3a0de76f3658ca09/src/key_io.cpp#L298
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const B58_SECRET_KEY_PREFIX: [u8; 1] = [0xef];
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const B58_SECRET_KEY_PREFIX: [u8; 1] = super::mainnet::B58_SECRET_KEY_PREFIX;

/// The prefix for a Base58Check-encoded regtest transparent [`PublicKeyHash`].
/// Same as the testnet prefix.
///
/// [`PublicKeyHash`]: https://docs.rs/zcash_primitives/latest/zcash_primitives/legacy/enum.TransparentAddress.html
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = [0x1d, 0x25];
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const B58_PUBKEY_ADDRESS_PREFIX: [u8; 2] = super::mainnet::B58_PUBKEY_ADDRESS_PREFIX;

/// The prefix for a Base58Check-encoded regtest transparent [`ScriptHash`].
/// Same as the testnet prefix.
///
/// [`ScriptHash`]: https://docs.rs/zcash_primitives/latest/zcash_primitives/legacy/enum.TransparentAddress.html
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = [0x1c, 0xba];
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const B58_SCRIPT_ADDRESS_PREFIX: [u8; 2] = super::mainnet::B58_SCRIPT_ADDRESS_PREFIX;

/// The HRP for a Bech32m-encoded regtest [ZIP 320] TEX address.
///
/// [ZIP 320]: https://zips.z.cash/zip-0320
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_TEX_ADDRESS: &str = "texregtest";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_TEX_ADDRESS: &str = super::mainnet::HRP_TEX_ADDRESS;

/// The HRP for a Bech32m-encoded regtest Unified Address.
///
/// Defined in [ZIP 316][zip-0316].
///
/// [zip-0316]: https://zips.z.cash/zip-0316
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_UNIFIED_ADDRESS: &str = "uregtest";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_UNIFIED_ADDRESS: &str = super::mainnet::HRP_UNIFIED_ADDRESS;

/// The HRP for a Bech32m-encoded regtest Unified FVK.
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_UNIFIED_FVK: &str = "uviewregtest";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_UNIFIED_FVK: &str = super::mainnet::HRP_UNIFIED_FVK;

/// The HRP for a Bech32m-encoded regtest Unified IVK.
#[cfg(not(zcash_regtest_mainnet_keys))]
pub const HRP_UNIFIED_IVK: &str = "uivkregtest";
/// Mainnet-masquerade value.
#[cfg(zcash_regtest_mainnet_keys)]
pub const HRP_UNIFIED_IVK: &str = super::mainnet::HRP_UNIFIED_IVK;
