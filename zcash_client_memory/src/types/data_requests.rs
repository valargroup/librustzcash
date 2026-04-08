use std::{collections::VecDeque, ops::Deref};

use zcash_client_backend::data_api::TransactionDataRequest;
use zcash_primitives::transaction::TxId;

#[derive(Debug, Default, PartialEq)]
pub struct TransactionDataRequestQueue(pub(crate) VecDeque<TransactionDataRequest>);

impl TransactionDataRequestQueue {
    pub fn new() -> Self {
        Self(VecDeque::new())
    }

    pub fn queue_status_retrieval(&mut self, txid: &TxId) {
        self.0.push_back(TransactionDataRequest::GetStatus(*txid));
    }

    pub fn queue_enhancement(&mut self, txid: &TxId) {
        self.0.push_back(TransactionDataRequest::Enhancement(*txid));
    }

    /// Removes any pending [`TransactionDataRequest::Enhancement`] entries for
    /// the given txid.
    ///
    /// This deliberately does NOT remove [`TransactionDataRequest::GetStatus`]
    /// entries: `store_decrypted_tx` queues fresh `GetStatus` requests for
    /// unmined transparent-bundle transactions, and those need to survive the
    /// end-of-function cleanup so the sync orchestrator can later poll for
    /// their mined status. Removing them here would silently drop the work
    /// `store_decrypted_tx` just queued.
    pub fn remove_enhancement_entries_for_txid(&mut self, txid: &TxId) {
        self.0
            .retain(|req| !matches!(req, TransactionDataRequest::Enhancement(id) if id == txid));
    }
}

impl Deref for TransactionDataRequestQueue {
    type Target = VecDeque<TransactionDataRequest>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_txid(byte: u8) -> TxId {
        TxId::from_bytes([byte; 32])
    }

    /// Regression test for the bug where the end-of-`store_decrypted_tx`
    /// cleanup wiped both `Enhancement` and `GetStatus` entries for the
    /// stored txid, silently dropping `GetStatus` requests that
    /// `store_decrypted_tx` had just queued for unmined transparent-bundle
    /// transactions.
    #[test]
    fn remove_enhancement_entries_for_txid_preserves_get_status() {
        let tx_a = make_txid(1);
        let tx_b = make_txid(2);
        let mut queue = TransactionDataRequestQueue::new();
        queue.queue_enhancement(&tx_a);
        queue.queue_status_retrieval(&tx_a);
        queue.queue_enhancement(&tx_b);
        queue.queue_status_retrieval(&tx_b);

        queue.remove_enhancement_entries_for_txid(&tx_a);

        let remaining: Vec<_> = queue.0.iter().collect();
        assert_eq!(
            remaining.len(),
            3,
            "should have removed exactly one entry (the Enhancement for tx_a)"
        );
        assert!(
            remaining
                .iter()
                .any(|r| matches!(r, TransactionDataRequest::GetStatus(t) if *t == tx_a)),
            "GetStatus(tx_a) must survive remove_enhancement_entries_for_txid(&tx_a)"
        );
        assert!(
            remaining
                .iter()
                .any(|r| matches!(r, TransactionDataRequest::Enhancement(t) if *t == tx_b)),
            "Enhancement(tx_b) must survive (different txid)"
        );
        assert!(
            remaining
                .iter()
                .any(|r| matches!(r, TransactionDataRequest::GetStatus(t) if *t == tx_b)),
            "GetStatus(tx_b) must survive (different txid)"
        );
        assert!(
            !remaining
                .iter()
                .any(|r| matches!(r, TransactionDataRequest::Enhancement(t) if *t == tx_a)),
            "Enhancement(tx_a) should have been removed"
        );
    }
}

mod serialization {
    use super::*;
    use crate::{error::Error, proto::memwallet as proto, read_optional};

    #[cfg(feature = "transparent-inputs")]
    use {
        ::transparent::address::TransparentAddress, zcash_keys::encoding::AddressCodec as _,
        zcash_protocol::consensus::Network::MainNetwork as EncodingParams,
    };

    impl From<TransactionDataRequest> for proto::TransactionDataRequest {
        fn from(request: TransactionDataRequest) -> Self {
            match request {
                TransactionDataRequest::GetStatus(txid) => Self {
                    request_type: proto::TransactionDataRequestType::GetStatus as i32,
                    tx_id: Some(txid.into()),
                    address: None,
                    block_range_start: None,
                    block_range_end: None,
                },
                TransactionDataRequest::Enhancement(txid) => Self {
                    request_type: proto::TransactionDataRequestType::Enhancement as i32,
                    tx_id: Some(txid.into()),
                    address: None,
                    block_range_start: None,
                    block_range_end: None,
                },
                #[cfg(feature = "transparent-inputs")]
                TransactionDataRequest::TransactionsInvolvingAddress(req) => Self {
                    request_type: proto::TransactionDataRequestType::SpendsFromAddress as i32,
                    tx_id: None,
                    address: Some(req.address().encode(&EncodingParams).as_bytes().to_vec()),
                    block_range_start: Some(u32::from(req.block_range_start())),
                    block_range_end: req.block_range_end().map(u32::from),
                },
            }
        }
    }

    impl TryFrom<proto::TransactionDataRequest> for TransactionDataRequest {
        type Error = crate::Error;

        fn try_from(request: proto::TransactionDataRequest) -> Result<Self, crate::Error> {
            Ok(match request.request_type() {
                proto::TransactionDataRequestType::GetStatus => {
                    TransactionDataRequest::GetStatus(read_optional!(request, tx_id)?.try_into()?)
                }
                proto::TransactionDataRequestType::Enhancement => {
                    TransactionDataRequest::Enhancement(read_optional!(request, tx_id)?.try_into()?)
                }
                #[cfg(feature = "transparent-inputs")]
                proto::TransactionDataRequestType::SpendsFromAddress => {
                    use zcash_client_backend::data_api::{
                        OutputStatusFilter, TransactionStatusFilter,
                    };

                    TransactionDataRequest::transactions_involving_address(
                        TransparentAddress::decode(
                            &EncodingParams,
                            &String::from_utf8(read_optional!(request, address)?)?,
                        )?,
                        read_optional!(request, block_range_start)?.into(),
                        Some(read_optional!(request, block_range_end)?.into()),
                        None,
                        TransactionStatusFilter::Mined,
                        OutputStatusFilter::All,
                    )
                }
                #[cfg(not(feature = "transparent-inputs"))]
                _ => panic!("invalid request type"),
            })
        }
    }
}
