//! This migration adds a filter to `v_transactions` that hides transactions in the
//! intermediate scan-only state, where compact-block scanning has recorded their input
//! spends but transaction enhancement has not yet stored their output change notes.
//!
//! Under the External-only batch scanning optimization, Internal-scope change notes
//! are discovered only during post-scan transaction enhancement. This creates a time
//! window between `put_tx_meta` (scan path, which does NOT set `raw`) and `put_tx_data`
//! (enhancement path, which does set `raw`). In that window, the `v_transactions` view
//! computes `account_balance_delta = SUM(received) - SUM(spent)` from an inconsistent
//! DB state: the input is marked spent but the change output isn't stored yet, so the
//! UI transiently displays `-total_input` instead of the final `-(external_sent + fee)`.
//!
//! The filter `WHERE transactions.raw IS NOT NULL` hides any transaction that hasn't
//! been through `put_tx_data` at least once, deferring its visibility to the UI until
//! enhancement has committed a consistent snapshot.

use std::collections::HashSet;

use schemerz_rusqlite::RusqliteMigration;
use uuid::Uuid;

use crate::wallet::init::{WalletMigrationError, migrations::account_delete_cascade};

pub(super) const MIGRATION_ID: Uuid = Uuid::from_u128(0x25dad60f_ffc1_44a9_9e54_154c51749c28);

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
        "Adds a filter to v_transactions that hides transactions in the intermediate \
         scan-only state (inputs marked spent by scanning but outputs not yet recovered \
         by enhancement). This prevents the UI from displaying a transiently-wrong \
         balance delta during sync."
    }
}

impl RusqliteMigration for Migration {
    type Error = WalletMigrationError;

    fn up(&self, transaction: &rusqlite::Transaction) -> Result<(), Self::Error> {
        transaction.execute_batch(
            r#"
            DROP VIEW v_transactions;
            CREATE VIEW v_transactions AS
            WITH
            notes AS (
                -- Outputs received in this transaction
                SELECT ro.account_id              AS account_id,
                       ro.transaction_id          AS transaction_id,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       ro.value                   AS value,
                       ro.value                   AS received_value,
                       0                          AS spent_value,
                       0                          AS spent_note_count,
                       CASE
                            WHEN ro.is_change THEN 1
                            ELSE 0
                       END AS change_note_count,
                       CASE
                            WHEN ro.is_change THEN 0
                            ELSE 1
                       END AS received_count,
                       CASE
                         WHEN (ro.memo IS NULL OR ro.memo = X'F6')
                           THEN 0
                         ELSE 1
                       END AS memo_present,
                       -- The wallet cannot receive transparent outputs in shielding transactions.
                       CASE
                         WHEN ro.pool = 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                UNION
                -- Outputs spent in this transaction
                SELECT ro.account_id              AS account_id,
                       ros.transaction_id         AS transaction_id,
                       ro.pool                    AS pool,
                       id_within_pool_table,
                       -ro.value                  AS value,
                       0                          AS received_value,
                       ro.value                   AS spent_value,
                       1                          AS spent_note_count,
                       0                          AS change_note_count,
                       0                          AS received_count,
                       0                          AS memo_present,
                       -- The wallet cannot spend shielded outputs in shielding transactions.
                       CASE
                         WHEN ro.pool != 0
                           THEN 1
                         ELSE 0
                       END AS does_not_match_shielding
                FROM v_received_outputs ro
                JOIN v_received_output_spends ros
                     ON ros.pool = ro.pool
                     AND ros.received_output_id = ro.id_within_pool_table
            ),
            -- Obtain a count of the notes that the wallet created in each transaction,
            -- not counting change notes.
            sent_note_counts AS (
                SELECT sent_notes.from_account_id     AS account_id,
                       sent_notes.transaction_id      AS transaction_id,
                       COUNT(DISTINCT sent_notes.id)  AS sent_notes,
                       SUM(
                         CASE
                           WHEN (sent_notes.memo IS NULL OR sent_notes.memo = X'F6' OR ro.transaction_id IS NOT NULL)
                             THEN 0
                           ELSE 1
                         END
                       ) AS memo_count
                FROM sent_notes
                LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
                WHERE COALESCE(ro.is_change, 0) = 0
                GROUP BY account_id, sent_notes.transaction_id
            ),
            blocks_max_height AS (
                SELECT MAX(blocks.height) AS max_height FROM blocks
            )
            SELECT accounts.uuid                AS account_uuid,
                   transactions.mined_height    AS mined_height,
                   transactions.txid            AS txid,
                   transactions.tx_index        AS tx_index,
                   transactions.expiry_height   AS expiry_height,
                   transactions.raw             AS raw,
                   SUM(notes.value)             AS account_balance_delta,
                   SUM(notes.spent_value)       AS total_spent,
                   SUM(notes.received_value)    AS total_received,
                   transactions.fee             AS fee_paid,
                   SUM(notes.change_note_count) > 0  AS has_change,
                   MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
                   SUM(notes.received_count)         AS received_note_count,
                   SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
                   blocks.time                       AS block_time,
                   (
                        transactions.mined_height IS NULL
                        AND transactions.expiry_height BETWEEN 1 AND blocks_max_height.max_height
                   ) AS expired_unmined,
                   SUM(notes.spent_note_count) AS spent_note_count,
                   (
                        -- All of the wallet-spent and wallet-received notes are consistent with a
                        -- shielding transaction.
                        SUM(notes.does_not_match_shielding) = 0
                        -- The transaction contains at least one wallet-spent output.
                        AND SUM(notes.spent_note_count) > 0
                        -- The transaction contains at least one wallet-received note.
                        AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
                        -- We do not know about any external outputs of the transaction.
                        AND MAX(COALESCE(sent_note_counts.sent_notes, 0)) = 0
                   ) AS is_shielding,
                   transactions.trust_status
            FROM notes
            JOIN accounts ON accounts.id = notes.account_id
            JOIN transactions ON transactions.id_tx = notes.transaction_id
            LEFT JOIN blocks_max_height
            LEFT JOIN blocks ON blocks.height = transactions.mined_height
            LEFT JOIN sent_note_counts
                 ON sent_note_counts.account_id = notes.account_id
                 AND sent_note_counts.transaction_id = notes.transaction_id
            GROUP BY notes.account_id, notes.transaction_id
            -- NOTE: This HAVING clause is duplicated in the inline VIEW_TRANSACTIONS
            -- constant at wallet/db.rs. If you modify it here, update that constant
            -- as well (and vice versa).
            --
            -- Hide transactions whose DB state is transiently inconsistent during
            -- sync, to prevent v_transactions from reporting a wrong balance delta
            -- in the brief window between when pieces of the transaction are
            -- recorded and when all of them are in place. Two disjoint failure
            -- modes are caught:
            --
            -- Cause A (intra-tx scan-to-enhance window): scanning has recorded the
            -- wallet's spent inputs via `mark_notes_spent`, but enhancement has
            -- not yet recovered the Internal-scope change output via
            -- decrypt_transaction → put_received_note. `raw IS NULL` signals that
            -- enhancement's `put_tx_data` has not yet run. If the tx has wallet
            -- spends in this state, its computed delta is `-total_input` instead
            -- of the final `-(external_sent + fee)`.
            --
            -- Cause B (post-own-enhance, pre-cascade): the tx's own enhancement
            -- has run and stored change notes (so `raw IS NOT NULL`) but the
            -- cascade that marks its wallet-side spend has not yet fired. This
            -- happens when a downstream-in-chain-order dependency transaction
            -- has not yet been enhanced, so when THIS tx's `mark_notes_spent`
            -- looked up its spend nullifier it found nothing in `received_notes`.
            -- The cascade from the dependency's eventual enhancement then records
            -- the spend relationship via `put_received_note`'s `spent_in` param.
            -- We detect this inconsistent state via the invariant: 'a transaction
            -- with a wallet change note can only be wallet-sent, therefore it
            -- must also have wallet spend markings to be consistent.' A nonzero
            -- `change_note_count` with a zero `spent_note_count` is a violation
            -- of that invariant.
            --
            -- Pure receives (no change notes, no wallet spends) always satisfy
            -- both conditions and are immediately visible. Wallet-created mempool
            -- transactions have `raw` set and both sides populated at creation
            -- time, so they also pass immediately.
            HAVING NOT (
                (transactions.raw IS NULL AND SUM(notes.spent_note_count) > 0)
                OR (SUM(notes.change_note_count) > 0 AND SUM(notes.spent_note_count) = 0)
            )
            "#,
        )?;

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
