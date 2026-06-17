use std::collections::HashMap;

use transparent::{
    address::TransparentAddress,
    bundle::{OutPoint, TxOut},
    keys::TransparentKeyScope,
};
use zcash_client_backend::data_api::{
    WalletRead as _,
    testing::{
        TestBuilder,
        transparent::put_received_transparent_utxo as test_put_received_transparent_utxo,
    },
};
use zcash_protocol::{TxId, value::Zatoshis};

use crate::{
    AccountId, MemoryWalletDb,
    testing::{MemBlockCache, TestMemDbFactory},
    types::transparent::ReceivedTransparentOutput,
};

#[test]
#[ignore] //FIXME
fn put_received_transparent_utxo() {
    test_put_received_transparent_utxo(TestMemDbFactory::new());
}

#[test]
fn txids_spending_transparent_outputs() {
    let mut wallet = MemoryWalletDb::new(TestBuilder::DEFAULT_NETWORK, 100);
    let account_id = AccountId::default();
    let taddr = TransparentAddress::PublicKeyHash([7; 20]);
    let outpoint = OutPoint::fake();
    let txout = TxOut::new(Zatoshis::const_from_u64(100000), taddr.script().into());

    wallet.transparent_received_outputs.insert(
        outpoint.clone(),
        ReceivedTransparentOutput::new(
            TxId::from_bytes([1; 32]),
            account_id,
            taddr,
            TransparentKeyScope::EXTERNAL,
            txout,
            TestBuilder::DEFAULT_NETWORK.sapling.unwrap(),
        ),
    );

    let spending_txid = TxId::from_bytes([2; 32]);
    let unrelated_txid = TxId::from_bytes([3; 32]);
    let tx_spends = HashMap::from([
        (spending_txid, vec![outpoint]),
        (unrelated_txid, vec![OutPoint::new([4; 32], 0)]),
    ]);

    let txids = wallet
        .get_txids_spending_wallet_transparent_outputs(&tx_spends)
        .unwrap();
    assert!(txids.contains(&spending_txid));
    assert!(!txids.contains(&unrelated_txid));
}

#[test]
#[ignore] //FIXME
fn transparent_balance_across_shielding() {
    zcash_client_backend::data_api::testing::transparent::transparent_balance_across_shielding(
        TestMemDbFactory::new(),
        MemBlockCache::new(),
    );
}
