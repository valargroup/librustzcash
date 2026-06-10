//! Updates public wallet views to expose Ironwood outputs as a distinct SQLite pool code.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::{
    db,
    init::{
        WalletMigrationError,
        migrations::{ironwood_shardtree, v_tx_outputs_key_scopes},
    },
};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xf6fb571a_2e78_4218_a2d2_241b4f787cbf);

const DEPENDENCIES: &[Uuid] = &[
    ironwood_shardtree::MIGRATION_ID,
    v_tx_outputs_key_scopes::MIGRATION_ID,
];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Updates wallet output views to expose Ironwood rows as pool code 4."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            "DROP VIEW v_tx_outputs;
             DROP VIEW v_transactions;
             DROP VIEW v_received_output_spends;
             DROP VIEW v_received_outputs;",
        )?;

        transaction.execute(
            "UPDATE sent_notes
             SET output_pool = 4
             WHERE output_pool = 3
             AND EXISTS (
                SELECT 1
                FROM orchard_received_notes rn
                WHERE rn.transaction_id = sent_notes.transaction_id
                AND rn.action_index = sent_notes.output_index
                AND rn.note_version = 3
             )",
            [],
        )?;

        transaction.execute_batch(db::VIEW_RECEIVED_OUTPUTS)?;
        transaction.execute_batch(db::VIEW_RECEIVED_OUTPUT_SPENDS)?;
        transaction.execute_batch(db::VIEW_TRANSACTIONS)?;
        transaction.execute_batch(db::VIEW_TX_OUTPUTS)?;

        Ok(())
    }

    fn down(&self, _transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        Err(WalletMigrationError::CannotRevert(MIGRATION_ID))
    }
}

#[cfg(test)]
mod tests {
    use crate::wallet::init::migrations::tests::test_migrate;

    #[test]
    fn migrate() {
        test_migrate(&[super::MIGRATION_ID]);
    }
}
