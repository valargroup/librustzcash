//! This migration adds the `pir_provisional_notes` table for storing change notes
//! discovered via PIR trial decryption.
//!
//! When a note is spent (detected by nullifier PIR), the wallet downloads the spending
//! block and trial-decrypts its actions to find change notes. These provisional notes
//! are ahead-of-scan hints: they become spendable once a PIR witness is obtained, and
//! are deleted when the canonical scanner catches up or on reorg.
//!
//! The table is created unconditionally (not gated by `#[cfg(feature = "spendability-pir")]`)
//! to keep the migration DAG identical across all builds.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::pir_witness_data;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xb3d7a1f4_2e89_4c06_a1d3_9f4e2b8c7d51);

const DEPENDENCIES: &[Uuid] = &[pir_witness_data::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds a table for storing change notes discovered via PIR trial decryption."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        debug!("Creating pir_provisional_notes table");
        transaction.execute_batch(
            "CREATE TABLE pir_provisional_notes (
                id INTEGER PRIMARY KEY,
                account_id INTEGER NOT NULL REFERENCES accounts(id),
                spent_note_id INTEGER NOT NULL,
                value INTEGER NOT NULL,
                position INTEGER NOT NULL UNIQUE,
                diversifier BLOB NOT NULL,
                rseed BLOB NOT NULL,
                rho BLOB NOT NULL,
                nullifier BLOB NOT NULL UNIQUE,
                cmx BLOB NOT NULL,
                spend_height INTEGER NOT NULL,
                has_pir_witness INTEGER NOT NULL DEFAULT 0
            )",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP TABLE pir_provisional_notes;")?;
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
