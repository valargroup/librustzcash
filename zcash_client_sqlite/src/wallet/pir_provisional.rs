//! PIR provisional note storage.
//!
//! When nullifier PIR detects a note as spent, the wallet trial-decrypts the
//! spending transaction's actions to discover change notes. These "provisional"
//! notes live here until the canonical scanner catches up.
//!
//! A provisional note becomes spendable once a PIR witness is obtained
//! (`has_pir_witness = 1`). When the scanner processes the same block and
//! inserts the canonical note into `orchard_received_notes`, the provisional
//! row is marked `discovered_by_scanner = 1` (reconciliation) rather than
//! deleted, so that its descendants in the recursive chain remain valid.

use rusqlite::{Connection, OptionalExtension, named_params};

use crate::error::SqliteClientError;

/// A provisional note ready for nullifier PIR checking.
pub struct ProvisionalNoteForPIR {
    pub id: i64,
    pub nullifier: [u8; 32],
    pub value: u64,
    /// The canonical `orchard_received_notes` ID that started this chain.
    /// Needed for FVK lookup when discovering deeper change notes.
    pub spent_note_id: i64,
    /// This note's depth in the chain (1 = direct change from canonical).
    /// Used to compute `depth + 1` for children accurately.
    pub depth: u32,
}

/// Inserts a provisional note discovered via PIR trial decryption.
///
/// Uses `INSERT OR IGNORE` so that duplicate positions are silently skipped
/// (idempotent across retries).
///
/// Returns the row ID of the inserted (or existing) row.
#[allow(clippy::too_many_arguments)]
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
    depth: u32,
    parent_provisional_id: Option<i64>,
) -> Result<i64, SqliteClientError> {
    conn.execute(
        "INSERT OR IGNORE INTO pir_provisional_notes
            (account_id, spent_note_id, value, position, diversifier,
             rseed, rho, nullifier, cmx, spend_height, depth, parent_provisional_id)
         VALUES
            (:account_id, :spent_note_id, :value, :position, :diversifier,
             :rseed, :rho, :nullifier, :cmx, :spend_height, :depth, :parent_provisional_id)",
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
            ":depth": depth,
            ":parent_provisional_id": parent_provisional_id,
        },
    )?;

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

/// Returns provisional notes whose nullifiers have not yet been checked via PIR.
///
/// Excludes notes already reconciled by the scanner (`discovered_by_scanner = 1`).
pub fn get_provisional_notes_for_pir_check(
    conn: &Connection,
) -> Result<Vec<ProvisionalNoteForPIR>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT id, nullifier, value, spent_note_id, depth FROM pir_provisional_notes
         WHERE pir_checked = 0
           AND discovered_by_scanner = 0",
    )?;
    let rows = stmt.query_map(
        [],
        |row| {
            let nf_blob: Vec<u8> = row.get("nullifier")?;
            Ok(ProvisionalNoteForPIR {
                id: row.get("id")?,
                nullifier: nf_blob
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidColumnType(1, "nullifier".into(), rusqlite::types::Type::Blob))?,
                value: row.get::<_, i64>("value").map(|v| v as u64)?,
                spent_note_id: row.get("spent_note_id")?,
                depth: row.get::<_, i64>("depth").map(|v| v as u32)?,
            })
        },
    )?;

    rows.collect::<Result<Vec<_>, _>>().map_err(SqliteClientError::from)
}

/// Marks a provisional note as PIR-checked after a nullifier lookup.
///
/// Always sets `pir_checked = 1`. If `is_spent` is true, also sets
/// `is_spent = 1` (the note's value is carried by its children).
/// The `is_spent` flag is monotonic: once set to 1 it cannot revert to 0,
/// even if this function is called again with `is_spent = false`.
pub fn mark_provisional_pir_result(
    conn: &Connection,
    note_id: i64,
    is_spent: bool,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE pir_provisional_notes
         SET pir_checked = 1, is_spent = MAX(is_spent, :is_spent)
         WHERE id = :id",
        named_params! {
            ":id": note_id,
            ":is_spent": is_spent,
        },
    )?;
    Ok(())
}

/// Reconciles a provisional note with the canonical scanner.
///
/// When the scanner inserts a canonical note at the same tree position, this
/// function marks the provisional row as `discovered_by_scanner = 1` instead
/// of deleting it. If the provisional note was already detected as spent by
/// PIR (`is_spent = 1`), the canonical note's id is inserted into
/// `pir_spent_notes` to prevent double-counting (the scanner hasn't reached
/// the spending block yet, so it considers the canonical note unspent).
///
/// The provisional note's descendants remain valid in the DB.
pub fn reconcile_provisional_for_position(
    conn: &Connection,
    position: u64,
    canonical_note_id: i64,
) -> Result<bool, SqliteClientError> {
    let pos_i64 = i64::try_from(position).expect("position fits i64");

    let is_spent: Option<bool> = conn
        .query_row(
            "SELECT is_spent FROM pir_provisional_notes WHERE position = :position",
            named_params! { ":position": pos_i64 },
            |row| row.get(0),
        )
        .optional()?;

    let Some(is_spent) = is_spent else {
        return Ok(false);
    };

    if is_spent {
        conn.execute(
            "INSERT INTO pir_spent_notes (note_id)
             SELECT :note_id
             WHERE NOT EXISTS (
                 SELECT 1 FROM orchard_received_note_spends
                 WHERE orchard_received_note_id = :note_id
             )
             AND NOT EXISTS (
                 SELECT 1 FROM pir_spent_notes WHERE note_id = :note_id
             )",
            named_params! { ":note_id": canonical_note_id },
        )?;
    }

    conn.execute(
        "UPDATE pir_provisional_notes SET discovered_by_scanner = 1 WHERE position = :position",
        named_params! { ":position": pos_i64 },
    )?;

    Ok(true)
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
            1,    // depth
            None, // parent_provisional_id
        )
        .unwrap()
    }

    fn insert_test_provisional_with_depth(
        conn: &Connection,
        position: u64,
        value: u64,
        depth: u32,
        parent_id: Option<i64>,
    ) -> i64 {
        insert_pir_provisional_note(
            conn,
            1,
            1,
            value,
            position,
            &[0u8; 11],
            &[0u8; 32],
            &[0u8; 32],
            &[position as u8; 32],
            &[0u8; 32],
            3_200_000,
            depth,
            parent_id,
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
            &[1u8; 32],
            &[0u8; 32], 3_200_000,
            1, None,
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
    fn get_notes_for_pir_check() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
    }

    #[test]
    fn get_notes_for_pir_check_excludes_checked() {
        let db = PirTestDb::new();
        let id1 = insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        mark_provisional_pir_result(db.conn(), id1, false).unwrap();

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value, 75_000);
    }

    #[test]
    fn get_notes_for_pir_check_excludes_scanner_reconciled() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);

        db.conn()
            .execute(
                "UPDATE pir_provisional_notes SET discovered_by_scanner = 1 WHERE position = 1000",
                [],
            )
            .unwrap();

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn mark_pir_result_not_spent() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);

        mark_provisional_pir_result(db.conn(), id, false).unwrap();

        let (checked, spent): (bool, bool) = db
            .conn()
            .query_row(
                "SELECT pir_checked, is_spent FROM pir_provisional_notes WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(checked);
        assert!(!spent);
    }

    #[test]
    fn mark_pir_result_spent() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);

        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        let (checked, spent): (bool, bool) = db
            .conn()
            .query_row(
                "SELECT pir_checked, is_spent FROM pir_provisional_notes WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(checked);
        assert!(spent);
    }

    #[test]
    fn reconcile_marks_discovered_by_scanner() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);

        let reconciled = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(reconciled);

        let dbs: bool = db
            .conn()
            .query_row(
                "SELECT discovered_by_scanner FROM pir_provisional_notes WHERE position = 1000",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(dbs);
    }

    #[test]
    fn reconcile_propagates_spent_to_pir_spent_notes() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        // Insert a canonical note to satisfy the FK
        db.conn()
            .execute(
                "INSERT INTO orchard_received_notes
                    (id, tx, action_index, account_id, diversifier, value, rho, rseed,
                     commitment_tree_position, recipient_key_scope)
                 VALUES (42, 100, 0, 1, X'0000000000000000000000', 50000,
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         1000, 0)",
                [],
            )
            .unwrap();

        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let pir_spent_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_spent_notes WHERE note_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pir_spent_count, 1);
    }

    #[test]
    fn reconcile_no_propagation_when_not_spent() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);

        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let pir_spent_count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_spent_notes",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(pir_spent_count, 0);
    }

    #[test]
    fn reconcile_nonexistent_position() {
        let db = PirTestDb::new();
        let reconciled = reconcile_provisional_for_position(db.conn(), 9999, 42).unwrap();
        assert!(!reconciled);
    }

    #[test]
    fn recursive_chain_depth() {
        let db = PirTestDb::new();
        let b = insert_test_provisional_with_depth(db.conn(), 1000, 70_000, 1, None);
        let c = insert_test_provisional_with_depth(db.conn(), 2000, 40_000, 2, Some(b));

        let (depth, parent): (i64, Option<i64>) = db
            .conn()
            .query_row(
                "SELECT depth, parent_provisional_id FROM pir_provisional_notes WHERE id = ?1",
                [c],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(depth, 2);
        assert_eq!(parent, Some(b));
    }

    #[test]
    fn reconcile_mid_chain_preserves_descendants() {
        let db = PirTestDb::new();
        let b = insert_test_provisional_with_depth(db.conn(), 1000, 70_000, 1, None);
        mark_provisional_pir_result(db.conn(), b, true).unwrap();
        let _c = insert_test_provisional_with_depth(db.conn(), 2000, 40_000, 2, Some(b));

        db.conn()
            .execute(
                "INSERT INTO orchard_received_notes
                    (id, tx, action_index, account_id, diversifier, value, rho, rseed,
                     commitment_tree_position, recipient_key_scope)
                 VALUES (42, 100, 0, 1, X'0000000000000000000000', 70000,
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         1000, 0)",
                [],
            )
            .unwrap();

        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        // B is reconciled, C remains untouched
        let total: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_provisional_notes WHERE discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, 1); // only C

        // C is still a valid leaf
        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value, 40_000);
    }

    #[test]
    fn mark_pir_result_spent_is_monotonic() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);

        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        // Calling again with false must not revert is_spent
        db.conn()
            .execute(
                "UPDATE pir_provisional_notes SET pir_checked = 0 WHERE id = ?1",
                [id],
            )
            .unwrap();
        mark_provisional_pir_result(db.conn(), id, false).unwrap();

        let spent: bool = db
            .conn()
            .query_row(
                "SELECT is_spent FROM pir_provisional_notes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(spent);
    }

    #[test]
    fn mark_pir_result_nonexistent_is_noop() {
        let db = PirTestDb::new();
        mark_provisional_pir_result(db.conn(), 9999, true).unwrap();
    }

    #[test]
    fn reconcile_idempotent() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);

        let r1 = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(r1);

        // Second call is a no-op (already discovered_by_scanner=1, SELECT still finds the row)
        let r2 = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(r2);

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_provisional_notes WHERE discovered_by_scanner = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn get_notes_for_pir_check_returns_spent_note_id_and_depth() {
        let db = PirTestDb::new();
        insert_pir_provisional_note(
            db.conn(),
            1,
            42, // spent_note_id
            50_000,
            1000,
            &[0u8; 11],
            &[0u8; 32],
            &[0u8; 32],
            &[1u8; 32],
            &[0u8; 32],
            3_200_000,
            3,    // depth
            None,
        )
        .unwrap();

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].spent_note_id, 42);
        assert_eq!(notes[0].depth, 3);
    }

    #[test]
    fn balance_excludes_spent_and_scanner_reconciled() {
        let db = PirTestDb::new();
        // A -> B (spent) -> C (leaf)
        let b = insert_test_provisional_with_depth(db.conn(), 1000, 70_000, 1, None);
        mark_provisional_pir_result(db.conn(), b, true).unwrap();
        let _c = insert_test_provisional_with_depth(db.conn(), 2000, 40_000, 2, Some(b));

        // B is mid-chain spent, C is the leaf. Balance should only count C.
        let balance: i64 = db
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(value), 0) FROM pir_provisional_notes
                 WHERE is_spent = 0 AND discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(balance, 40_000);

        // Now scanner reconciles B (creates canonical B)
        db.conn()
            .execute(
                "INSERT INTO orchard_received_notes
                    (id, tx, action_index, account_id, diversifier, value, rho, rseed,
                     commitment_tree_position, recipient_key_scope)
                 VALUES (42, 100, 0, 1, X'0000000000000000000000', 70000,
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         X'0000000000000000000000000000000000000000000000000000000000000000',
                         1000, 0)",
                [],
            )
            .unwrap();
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        // After reconciliation, B is discovered_by_scanner=1 and canonical B is
        // in pir_spent_notes. Only provisional C (leaf) contributes.
        let balance_after: i64 = db
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(value), 0) FROM pir_provisional_notes
                 WHERE is_spent = 0 AND discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(balance_after, 40_000);

        // Canonical B should be in pir_spent_notes (prevents double-counting)
        let canonical_b_pir_spent: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_spent_notes WHERE note_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(canonical_b_pir_spent, 1);
    }
}
