//! PIR note tracking table.
//!
//! A single `pir_notes` table that tracks the full PIR lifecycle for any
//! note — canonical or provisional: spent-state, witness data, recursive
//! change-discovery chain, and scanner reconciliation.
//!
//! The table is created unconditionally (not gated by `#[cfg(feature = "spendability-pir")]`)
//! to keep the migration DAG identical across all builds.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use tracing::debug;
use uuid::Uuid;

use crate::wallet::init::WalletMigrationError;

use super::account_delete_cascade;

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0xd5f9c3b6_4a0b_4e28_c3f5_1b6a4d0e9f73);

const DEPENDENCIES: &[Uuid] = &[account_delete_cascade::MIGRATION_ID];

pub(super) struct Migration;

impl schemerz::Migration<Uuid> for Migration {
    fn id(&self) -> Uuid {
        MIGRATION_ID
    }

    fn dependencies(&self) -> HashSet<Uuid> {
        DEPENDENCIES.iter().copied().collect()
    }

    fn description(&self) -> &'static str {
        "Adds unified pir_notes table for PIR note lifecycle tracking."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        debug!("Creating pir_notes table");
        transaction.execute_batch(
            "CREATE TABLE pir_notes (
                id INTEGER PRIMARY KEY,
                canonical_note_id INTEGER UNIQUE
                    REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
                account_id INTEGER NOT NULL REFERENCES accounts(id),
                position INTEGER NOT NULL UNIQUE,
                value INTEGER NOT NULL,
                diversifier BLOB,
                rseed BLOB,
                rho BLOB,
                cmx BLOB,
                nullifier BLOB UNIQUE,
                is_spent INTEGER NOT NULL DEFAULT 0,
                spend_height INTEGER,
                witness_siblings BLOB
                    CHECK(witness_siblings IS NULL OR length(witness_siblings) = 1024),
                witness_anchor_height INTEGER,
                witness_anchor_root BLOB
                    CHECK(witness_anchor_root IS NULL OR length(witness_anchor_root) = 32),
                depth INTEGER NOT NULL DEFAULT 0,
                parent_id INTEGER REFERENCES pir_notes(id),
                pir_checked INTEGER NOT NULL DEFAULT 0,
                discovered_by_scanner INTEGER NOT NULL DEFAULT 0
            )",
        )?;

        Ok(())
    }

    fn down(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch("DROP TABLE pir_notes;")?;
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
