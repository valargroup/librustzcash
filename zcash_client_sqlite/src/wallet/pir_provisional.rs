//! PIR provisional note storage.
//!
//! When nullifier PIR detects a note as spent, the wallet trial-decrypts the
//! spending transaction's actions to discover change notes. These "provisional"
//! notes live in `pir_notes` (with `canonical_note_id = NULL`) until the
//! canonical scanner catches up.
//!
//! A provisional note becomes spendable once a PIR witness is obtained
//! (`witness_siblings IS NOT NULL`). When the scanner processes the same block
//! and inserts the canonical note into `orchard_received_notes`, the row is
//! reconciled by setting `canonical_note_id` and `discovered_by_scanner = 1`,
//! rather than deleted, so that its descendants in the recursive chain remain
//! valid.

use rusqlite::{Connection, named_params};

use crate::error::SqliteClientError;

/// A provisional note that needs a PIR witness before it can be spent.
pub struct ProvisionalNoteNeedingWitness {
    pub id: i64,
    pub position: u64,
    pub value: u64,
}

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
        "INSERT OR IGNORE INTO pir_notes
            (account_id, value, position, diversifier,
             rseed, rho, nullifier, cmx, spend_height, depth, parent_id)
         VALUES
            (:account_id, :value, :position, :diversifier,
             :rseed, :rho, :nullifier, :cmx, :spend_height, :depth, :parent_id)",
        named_params! {
            ":account_id": account_id,
            ":value": i64::try_from(value).expect("note value fits i64"),
            ":position": i64::try_from(position).expect("position fits i64"),
            ":diversifier": &diversifier[..],
            ":rseed": &rseed[..],
            ":rho": &rho[..],
            ":nullifier": &nullifier[..],
            ":cmx": &cmx[..],
            ":spend_height": spend_height,
            ":depth": depth,
            ":parent_id": parent_provisional_id,
        },
    )?;

    let row_id: i64 = conn.query_row(
        "SELECT id FROM pir_notes WHERE position = :position",
        named_params! { ":position": i64::try_from(position).expect("position fits i64") },
        |row| row.get(0),
    )?;

    Ok(row_id)
}

/// Sets witness data on a provisional note after a PIR witness is obtained,
/// making it eligible for balance and coin selection.
pub fn mark_provisional_note_witnessed(
    conn: &Connection,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_height: u64,
    anchor_root: &[u8; 32],
) -> Result<bool, SqliteClientError> {
    let siblings_blob: Vec<u8> = siblings.iter().flat_map(|s| s.iter()).copied().collect();
    let rows = conn.execute(
        "UPDATE pir_notes
         SET witness_siblings = :siblings,
             witness_anchor_height = :anchor_height,
             witness_anchor_root = :anchor_root
         WHERE id = :id AND canonical_note_id IS NULL",
        named_params! {
            ":id": note_id,
            ":siblings": siblings_blob,
            ":anchor_height": anchor_height as i64,
            ":anchor_root": &anchor_root[..],
        },
    )?;
    Ok(rows > 0)
}

/// Returns provisional notes whose nullifiers have not yet been checked via PIR.
///
/// Excludes notes already reconciled by the scanner (`discovered_by_scanner = 1`).
///
/// `spent_note_id` is the canonical `orchard_received_notes` ID at the root of each
/// note's parent chain. It is resolved via a recursive CTE that walks `parent_id`
/// links up to the node whose `canonical_note_id` is set.
pub fn get_provisional_notes_for_pir_check(
    conn: &Connection,
) -> Result<Vec<ProvisionalNoteForPIR>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "WITH RECURSIVE root_chain(node_id, root_canonical_id) AS (
             SELECT id, canonical_note_id FROM pir_notes
             WHERE canonical_note_id IS NOT NULL
             UNION ALL
             SELECT child.id, rc.root_canonical_id
             FROM pir_notes child
             JOIN root_chain rc ON child.parent_id = rc.node_id
         )
         SELECT pn.id, pn.nullifier, pn.value, pn.depth,
                COALESCE(rc.root_canonical_id, 0) AS spent_note_id
         FROM pir_notes pn
         LEFT JOIN root_chain rc ON rc.node_id = pn.id
         WHERE pn.canonical_note_id IS NULL
           AND pn.pir_checked = 0
           AND pn.discovered_by_scanner = 0",
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
        "UPDATE pir_notes
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
/// function sets `canonical_note_id` and `discovered_by_scanner = 1` on the
/// existing row. The `is_spent` flag is already on the same row, so no
/// cross-table transfer is needed — the `spent_notes_clause` will pick it up
/// via `canonical_note_id`.
///
/// The provisional note's descendants remain valid in the DB.
pub fn reconcile_provisional_for_position(
    conn: &Connection,
    position: u64,
    canonical_note_id: i64,
) -> Result<bool, SqliteClientError> {
    let pos_i64 = i64::try_from(position).expect("position fits i64");

    let rows = conn.execute(
        "UPDATE pir_notes
         SET canonical_note_id = :canonical_note_id,
             discovered_by_scanner = 1
         WHERE position = :position
           AND canonical_note_id IS NULL",
        named_params! {
            ":canonical_note_id": canonical_note_id,
            ":position": pos_i64,
        },
    )?;

    Ok(rows > 0)
}

/// Returns provisional notes that have a tree position but lack a witness.
///
/// These are active change notes discovered via PIR trial decryption that
/// haven't been reconciled by the scanner and aren't yet spendable because
/// `witness_siblings` is NULL. The caller fetches witnesses from the PIR
/// server and stores them via [`mark_provisional_note_witnessed`].
pub fn get_provisional_notes_needing_witness(
    conn: &Connection,
) -> Result<Vec<ProvisionalNoteNeedingWitness>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT pn.id, pn.position, pn.value
         FROM pir_notes pn
         WHERE pn.canonical_note_id IS NULL
           AND pn.is_spent = 0
           AND pn.discovered_by_scanner = 0
           AND pn.position IS NOT NULL
           AND pn.witness_siblings IS NULL",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok(ProvisionalNoteNeedingWitness {
            id: row.get("id")?,
            position: row.get::<_, i64>("position").map(|v| v as u64)?,
            value: row.get::<_, i64>("value").map(|v| v as u64)?,
        })
    })?;

    rows.collect::<Result<Vec<_>, _>>()
        .map_err(SqliteClientError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::pir::testing::PirTestDb;

    fn insert_test_provisional(conn: &Connection, position: u64, value: u64) -> i64 {
        insert_pir_provisional_note(
            conn,
            1, // account_id
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
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id IS NULL",
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
            1, 50_000, 1000,
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
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id IS NULL",
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
                "SELECT witness_siblings IS NOT NULL FROM pir_notes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!has_witness);

        let siblings = [[0x10u8; 32]; 32];
        let updated = mark_provisional_note_witnessed(db.conn(), id, &siblings, 100, &[0xFF; 32]).unwrap();
        assert!(updated);

        let has_witness: bool = db
            .conn()
            .query_row(
                "SELECT witness_siblings IS NOT NULL FROM pir_notes WHERE id = ?1",
                [id],
                |r| r.get(0),
            )
            .unwrap();
        assert!(has_witness);
    }

    #[test]
    fn mark_witnessed_nonexistent() {
        let db = PirTestDb::new();
        let siblings = [[0x10u8; 32]; 32];
        let updated = mark_provisional_note_witnessed(db.conn(), 9999, &siblings, 100, &[0xFF; 32]).unwrap();
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
                "UPDATE pir_notes SET discovered_by_scanner = 1 WHERE position = 1000",
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
                "SELECT pir_checked, is_spent FROM pir_notes WHERE id = ?1",
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
                "SELECT pir_checked, is_spent FROM pir_notes WHERE id = ?1",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(checked);
        assert!(spent);
    }

    fn insert_canonical_note(conn: &Connection, id: i64, position: i64, value: i64) {
        crate::wallet::pir_witness::testing::insert_test_note_with_position(
            conn,
            id,
            value,
            Some(&[id as u8; 32]),
            Some(position),
        );
    }

    #[test]
    fn reconcile_marks_discovered_by_scanner() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_canonical_note(db.conn(), 42, 1000, 50_000);

        let reconciled = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(reconciled);

        let (dbs, canonical): (bool, Option<i64>) = db
            .conn()
            .query_row(
                "SELECT discovered_by_scanner, canonical_note_id FROM pir_notes WHERE position = 1000",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert!(dbs);
        assert_eq!(canonical, Some(42));
    }

    #[test]
    fn reconcile_spent_note_visible_in_spent_clause() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        insert_canonical_note(db.conn(), 42, 1000, 50_000);
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 42 AND is_spent = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
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
                "SELECT depth, parent_id FROM pir_notes WHERE id = ?1",
                [c],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(depth, 2);
        assert_eq!(parent, Some(b));
    }

    #[test]
    fn spent_note_id_resolves_via_parent_chain() {
        let db = PirTestDb::new();
        insert_canonical_note(db.conn(), 42, 5000, 100_000);
        crate::wallet::pir::insert_pir_spent_note(db.conn(), 42).unwrap();

        let parent_pir_id: i64 = db
            .conn()
            .query_row(
                "SELECT id FROM pir_notes WHERE canonical_note_id = 42",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let b = insert_test_provisional_with_depth(db.conn(), 6000, 70_000, 1, Some(parent_pir_id));
        let _c = insert_test_provisional_with_depth(db.conn(), 7000, 40_000, 2, Some(b));

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        for note in &notes {
            assert_eq!(note.spent_note_id, 42, "depth-{} should resolve to canonical note 42", note.depth);
        }
    }

    #[test]
    fn reconcile_mid_chain_preserves_descendants() {
        let db = PirTestDb::new();
        let b = insert_test_provisional_with_depth(db.conn(), 1000, 70_000, 1, None);
        mark_provisional_pir_result(db.conn(), b, true).unwrap();
        let _c = insert_test_provisional_with_depth(db.conn(), 2000, 40_000, 2, Some(b));

        insert_canonical_note(db.conn(), 42, 1000, 70_000);
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let total: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(total, 1); // only C

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value, 40_000);
    }

    #[test]
    fn mark_pir_result_spent_is_monotonic() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);

        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        db.conn()
            .execute(
                "UPDATE pir_notes SET pir_checked = 0 WHERE id = ?1",
                [id],
            )
            .unwrap();
        mark_provisional_pir_result(db.conn(), id, false).unwrap();

        let spent: bool = db
            .conn()
            .query_row(
                "SELECT is_spent FROM pir_notes WHERE id = ?1",
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
        insert_canonical_note(db.conn(), 42, 1000, 50_000);

        let r1 = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(r1);

        // Second call: canonical_note_id is already set, so the WHERE clause excludes it
        let r2 = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(!r2);

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE discovered_by_scanner = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn balance_excludes_spent_and_scanner_reconciled() {
        let db = PirTestDb::new();
        let b = insert_test_provisional_with_depth(db.conn(), 1000, 70_000, 1, None);
        mark_provisional_pir_result(db.conn(), b, true).unwrap();
        let _c = insert_test_provisional_with_depth(db.conn(), 2000, 40_000, 2, Some(b));

        let balance: i64 = db
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(value), 0) FROM pir_notes
                 WHERE is_spent = 0 AND discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(balance, 40_000);

        insert_canonical_note(db.conn(), 42, 1000, 70_000);
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let balance_after: i64 = db
            .conn()
            .query_row(
                "SELECT COALESCE(SUM(value), 0) FROM pir_notes
                 WHERE is_spent = 0 AND discovered_by_scanner = 0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(balance_after, 40_000);

        let canonical_b_spent: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 42 AND is_spent = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(canonical_b_spent, 1);
    }

    // =========================================================================
    // Provisional notes needing witness
    // =========================================================================

    #[test]
    fn needing_witness_returns_unwitnessed_provisionals() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].position, 1000);
        assert_eq!(notes[0].value, 50_000);
        assert_eq!(notes[1].position, 2000);
        assert_eq!(notes[1].value, 75_000);
    }

    #[test]
    fn needing_witness_excludes_witnessed() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        let siblings = [[0x10u8; 32]; 32];
        mark_provisional_note_witnessed(db.conn(), id, &siblings, 100, &[0xFF; 32]).unwrap();

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 2000);
    }

    #[test]
    fn needing_witness_excludes_spent() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 2000);
    }

    #[test]
    fn needing_witness_excludes_scanner_reconciled() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_canonical_note(db.conn(), 42, 1000, 50_000);
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn needing_witness_empty_table() {
        let db = PirTestDb::new();
        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }
}
