//! This migration adds the `pir_witness_data` table for storing Merkle authentication
//! paths obtained via PIR (Private Information Retrieval) from a witness server.
//!
//! The table is created unconditionally (not gated by `#[cfg(feature = "spendability-pir")]`)
//! to keep the migration DAG identical across all builds. When the feature is off, the table
//! exists but is empty and unused.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::pir_spent_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xae2c615d_5ff7_45e3_92dd_eb4519a9f313);

const DEPENDENCIES: &[Uuid] = &[pir_spent_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a table for storing PIR-obtained note commitment witnesses."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        debug!("Creating pir_witness_data table");
        transaction.execute_batch(
            "CREATE TABLE pir_witness_data (
                note_id INTEGER NOT NULL PRIMARY KEY
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                siblings BLOB NOT NULL CHECK(length(siblings) = 1024),
                anchor_height INTEGER NOT NULL,
                anchor_root BLOB NOT NULL CHECK(length(anchor_root) = 32)
            )",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP TABLE pir_witness_data;")?;
        Ok(())
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
