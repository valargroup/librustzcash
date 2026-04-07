//! PIR provisional note storage.
//!
//! When nullifier PIR detects a note as spent, the wallet trial-decrypts the
//! spending transaction's actions to discover change notes. These "provisional"
//! notes live here until the canonical scanner catches up.
//!
//! A provisional note becomes spendable once a PIR witness is obtained
//! (`has_pir_witness = 1`). When the scanner processes the same block and
//! inserts the canonical note into `orchard_received_notes`, the provisional
//! row is deleted (reconciliation).

use rusqlite::{Connection, named_params};

use crate::error::SqliteClientError;

/// Inserts a provisional note discovered via PIR trial decryption.
///
/// Uses `INSERT OR IGNORE` so that duplicate positions are silently skipped
/// (idempotent across retries).
///
/// Returns the row ID of the inserted (or existing) row.
pub fn insert_pir_provisional_note(
    conn: &Connection,
    account_id: i64,
    spent_note_id: i64,
    value: u64,
    position: u64,
    diversifier: &[u8; 11],
    rseed: &[u8; 32],
    rho: &[u8; 32],
    nullifier: &[u8; 32],
    cmx: &[u8; 32],
    spend_height: u32,
) -> Result<i64, SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO pir_provisional_notes
            (account_id, spent_note_id, value, position, diversifier,
             rseed, rho, nullifier, cmx, spend_height)
         VALUES
            (:account_id, :spent_note_id, :value, :position, :diversifier,
             :rseed, :rho, :nullifier, :cmx, :spend_height)",
        named_params! {
            ":account_id": account_id,
            ":spent_note_id": spent_note_id,
            ":value": i64::try_from(value).expect("note value fits i64"),
            ":position": i64::try_from(position).expect("position fits i64"),
            ":diversifier": &diversifier[..],
            ":rseed": &rseed[..],
            ":rho": &rho[..],
            ":nullifier": &nullifier[..],
            ":cmx": &cmx[..],
            ":spend_height": spend_height,
        },
    )?;

    // Return the row ID (either newly inserted or the existing conflicting row).
    let row_id: i64 = conn.query_row(
        "SELECT id FROM pir_provisional_notes WHERE position = :position",
        named_params! { ":position": i64::try_from(position).expect("position fits i64") },
        |row| row.get(0),
    )?;

    Ok(row_id)
}

/// Sets `has_pir_witness = 1` for a provisional note after a PIR witness is
/// obtained, making it eligible for balance and coin selection.
pub fn mark_provisional_note_witnessed(
    conn: &Connection,
    note_id: i64,
) -> Result<bool, SqliteClientError> {
    let rows = conn.execute(
        "UPDATE pir_provisional_notes SET has_pir_witness = 1 WHERE id = :id",
        named_params! { ":id": note_id },
    )?;
    Ok(rows > 0)
}

/// Deletes a provisional note whose position matches a canonically-scanned note.
/// Called during scanner reconciliation.
pub fn delete_provisional_for_position(
    conn: &Connection,
    position: u64,
) -> Result<bool, SqliteClientError> {
    let rows = conn.execute(
        "DELETE FROM pir_provisional_notes WHERE position = :position",
        named_params! { ":position": i64::try_from(position).expect("position fits i64") },
    )?;
    Ok(rows > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::pir::testing::PirTestDb;

    fn insert_test_provisional(conn: &Connection, position: u64, value: u64) -> i64 {
        insert_pir_provisional_note(
            conn,
            1, // account_id
            1, // spent_note_id
            value,
            position,
            &[0u8; 11],
            &[0u8; 32],
            &[0u8; 32],
            &[position as u8; 32], // unique nullifier per position
            &[0u8; 32],
            3_200_000,
        )
        .unwrap()
    }

    #[test]
    fn insert_and_retrieve() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        assert!(id > 0);

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_provisional_notes",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_idempotent_by_position() {
        let db = PirTestDb::new();
        let id1 = insert_test_provisional(db.conn(), 1000, 50_000);
        let id2 = insert_pir_provisional_note(
            db.conn(),
            1, 1, 50_000, 1000,
            &[0u8; 11], &[0u8; 32], &[0u8; 32],
            &[1u8; 32], // different nullifier but same position
            &[0u8; 32], 3_200_000,
        )
        .unwrap();
        assert_eq!(id1, id2);

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_provisional_notes",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn mark_witnessed() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);

        let has_witness: bool = db
            .conn()
            .query_row(
                "SELECT has_pir_witness FROM pir_provisional_notes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_witness);

        let updated = mark_provisional_note_witnessed(db.conn(), id).unwrap();
        assert!(updated);

        let has_witness: bool = db
            .conn()
            .query_row(
                "SELECT has_pir_witness FROM pir_provisional_notes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(has_witness);
    }

    #[test]
    fn mark_witnessed_nonexistent() {
        let db = PirTestDb::new();
        let updated = mark_provisional_note_witnessed(db.conn(), 9999).unwrap();
        assert!(!updated);
    }

    #[test]
    fn delete_for_position() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        let deleted = delete_provisional_for_position(db.conn(), 1000).unwrap();
        assert!(deleted);

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_provisional_notes",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn delete_for_position_nonexistent() {
        let db = PirTestDb::new();
        let deleted = delete_provisional_for_position(db.conn(), 9999).unwrap();
        assert!(!deleted);
    }
}
