//! Extends `pir_provisional_notes` with columns for recursive change discovery
//! and safe scanner reconciliation.
//!
//! New columns:
//! - `depth`: hop count from the canonical note (1 = direct change).
//! - `parent_provisional_id`: self-referencing FK for chain traversal.
//! - `pir_checked`: whether this note's nullifier has been PIR-queried.
//! - `is_spent`: PIR confirmed this note is spent (value carried by children).
//! - `discovered_by_scanner`: scanner created the canonical note at this position;
//!   this row is retired and excluded from balance queries, but its descendants
//!   remain valid.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::pir_provisional_notes;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xc4e8b2a5_3f9a_4d17_b2e4_0a5f3c9d8e62);

const DEPENDENCIES: &[Uuid] = &[pir_provisional_notes::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Extends pir_provisional_notes for recursive change discovery and scanner reconciliation."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        debug!("Adding recursive tracking columns to pir_provisional_notes");
        transaction.execute_batch(
            "ALTER TABLE pir_provisional_notes ADD COLUMN depth INTEGER NOT NULL DEFAULT 1;
             ALTER TABLE pir_provisional_notes ADD COLUMN parent_provisional_id INTEGER
                 REFERENCES pir_provisional_notes(id);
             ALTER TABLE pir_provisional_notes ADD COLUMN pir_checked INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE pir_provisional_notes ADD COLUMN is_spent INTEGER NOT NULL DEFAULT 0;
             ALTER TABLE pir_provisional_notes ADD COLUMN discovered_by_scanner INTEGER NOT NULL DEFAULT 0;",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        // SQLite does not support DROP COLUMN before 3.35.0, so recreate the table
        // without the new columns.
        transaction.execute_batch(
            "CREATE TABLE pir_provisional_notes_backup AS
                 SELECT id, account_id, spent_note_id, value, position, diversifier,
                        rseed, rho, nullifier, cmx, spend_height, has_pir_witness
                 FROM pir_provisional_notes;
             DROP TABLE pir_provisional_notes;
             CREATE TABLE pir_provisional_notes (
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
             );
             INSERT INTO pir_provisional_notes
                 SELECT * FROM pir_provisional_notes_backup;
             DROP TABLE pir_provisional_notes_backup;",
        )?;
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
