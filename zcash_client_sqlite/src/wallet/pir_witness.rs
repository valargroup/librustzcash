//! PIR (Private Information Retrieval) note commitment witness data.
//!
//! When the `spendability-pir` feature is enabled, Merkle authentication paths for
//! Orchard notes are obtained from an external PIR server during sync, enabling notes
//! to be spent before the wallet finishes scanning. This module provides the data layer
//! for storing and querying PIR-obtained witnesses.
//!
//! The `pir_witness_data` table is created unconditionally by migration so the
//! schema is identical across all builds. When the feature is off, the table is
//! empty and unused.

use rusqlite::{Connection, OptionalExtension, params};

use crate::error::SqliteClientError;

#[cfg(feature = "orchard")]
use {
    incrementalmerkletree::{MerklePath, Position},
    orchard::tree::MerkleHashOrchard,
};

#[cfg(feature = "orchard")]
type PirWitnessResult =
    Result<Option<(MerklePath<MerkleHashOrchard, 32>, u64, [u8; 32])>, SqliteClientError>;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use rusqlite::Connection;

    #[cfg(test)]
    fn migrate_and_setup(path: impl AsRef<std::path::Path>) -> Connection {
        use secrecy::SecretVec;
        use zcash_protocol::consensus::Network;

        use crate::{WalletDb, wallet::init::WalletMigrator};
        let mut db = WalletDb::for_path(
            path.as_ref(),
            Network::TestNetwork,
            crate::util::SystemClock,
            rand_core::OsRng,
        )
        .unwrap();
        WalletMigrator::new()
            .with_seed(SecretVec::new(vec![0xab; 32]))
            .init_or_migrate(&mut db)
            .unwrap();
        drop(db);

        let conn = Connection::open(path.as_ref()).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn.execute_batch(
            "INSERT INTO accounts (
                 uuid, account_kind, uivk, birthday_height, has_spend_key
             ) VALUES (
                 X'00000000000000000000000000000001', 1,
                 'test-uivk-for-pir-witness', 1, 1
             );
             INSERT INTO transactions (id_tx, txid, min_observed_height)
             VALUES (
                 100,
                 X'0000000000000000000000000000000000000000000000000000000000000001',
                 1
             );",
        )
        .unwrap();

        conn
    }

    #[cfg(test)]
    pub struct PirWitnessTestDb {
        conn: Connection,
        _data_file: tempfile::NamedTempFile,
    }

    #[cfg(test)]
    impl Default for PirWitnessTestDb {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    impl PirWitnessTestDb {
        pub fn new() -> Self {
            let data_file = tempfile::NamedTempFile::new().unwrap();
            let conn = migrate_and_setup(data_file.path());
            Self {
                conn,
                _data_file: data_file,
            }
        }

        pub fn conn(&self) -> &Connection {
            &self.conn
        }
    }

    pub fn insert_test_note(conn: &Connection, id: i64, value: i64, nf: Option<&[u8]>) {
        insert_test_note_with_position(conn, id, value, nf, None);
    }

    pub fn insert_test_note_with_position(
        conn: &Connection,
        id: i64,
        value: i64,
        nf: Option<&[u8]>,
        position: Option<i64>,
    ) {
        conn.execute(
            "INSERT INTO orchard_received_notes \
             (id, transaction_id, action_index, account_id, diversifier, value, \
              rho, rseed, nf, is_change, commitment_tree_position, recipient_key_scope) \
             VALUES (?1, 100, ?1, 1, X'00', ?2, X'00', X'00', ?3, 0, ?4, 0)",
            rusqlite::params![id, value, nf, position],
        )
        .unwrap();
    }
}

/// An Orchard note whose shard is not fully scanned and that lacks a PIR witness.
pub struct NoteNeedingWitness {
    pub id: i64,
    pub position: u64,
    pub value: u64,
}

/// A stored PIR witness for an Orchard note.
pub struct PirWitnessRow {
    pub note_id: i64,
    pub siblings: [[u8; 32]; 32],
    pub anchor_height: u64,
    pub anchor_root: [u8; 32],
}

/// A note that has a PIR witness but whose shard hasn't caught up yet.
pub struct PirWitnessedNote {
    pub note_id: i64,
    pub value: u64,
    pub anchor_height: u64,
}

/// The `ScanPriority::Scanned` value as stored in the DB (must match
/// `scanning::priority_code(&ScanPriority::Scanned)`).
const SCANNED_PRIORITY_CODE: i64 = 10;

const NOTES_NEEDING_WITNESS_SQL: &str = "\
    SELECT rn.id, rn.commitment_tree_position, rn.value \
    FROM orchard_received_notes rn \
    LEFT OUTER JOIN v_orchard_shards_scan_state scan_state \
        ON rn.commitment_tree_position >= scan_state.start_position \
        AND rn.commitment_tree_position < scan_state.end_position_exclusive \
    WHERE rn.commitment_tree_position IS NOT NULL \
    AND rn.nf IS NOT NULL \
    AND rn.recipient_key_scope IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM pir_spent_notes pir \
        WHERE pir.note_id = rn.id \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM pir_witness_data pw \
        WHERE pw.note_id = rn.id \
    ) \
    AND (scan_state.max_priority IS NULL \
         OR scan_state.max_priority > ?1)";

const WITNESSED_NOTES_SQL: &str = "\
    SELECT pw.note_id, rn.value, pw.anchor_height \
    FROM pir_witness_data pw \
    JOIN orchard_received_notes rn ON pw.note_id = rn.id \
    WHERE NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = pw.note_id \
    )";

/// Returns Orchard notes that need a PIR witness: they have a tree position,
/// are unspent, and their shard is not fully scanned.
pub fn get_notes_needing_pir_witness(
    conn: &Connection,
) -> Result<Vec<NoteNeedingWitness>, SqliteClientError> {
    let mut stmt = conn.prepare(NOTES_NEEDING_WITNESS_SQL)?;

    let notes = stmt
        .query_map([SCANNED_PRIORITY_CODE], |row| {
            let id: i64 = row.get(0)?;
            let position: i64 = row.get(1)?;
            let value: i64 = row.get(2)?;
            Ok(NoteNeedingWitness {
                id,
                position: position as u64,
                value: value as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(notes)
}

/// Stores a PIR-obtained witness for a note. The insert is conditional: it skips
/// notes that already have a witness.
pub fn insert_pir_witness(
    conn: &Connection,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_height: u64,
    anchor_root: &[u8; 32],
) -> Result<(), SqliteClientError> {
    let siblings_blob: Vec<u8> = siblings.iter().flat_map(|s| s.iter()).copied().collect();
    conn.execute(
        "INSERT INTO pir_witness_data (note_id, siblings, anchor_height, anchor_root)
         SELECT ?1, ?2, ?3, ?4
         WHERE NOT EXISTS (
             SELECT 1 FROM pir_witness_data WHERE note_id = ?1
         )",
        params![
            note_id,
            siblings_blob,
            anchor_height as i64,
            anchor_root.as_slice()
        ],
    )?;
    Ok(())
}

/// Retrieves a stored PIR witness for a specific note.
pub fn get_pir_witness(
    conn: &Connection,
    note_id: i64,
) -> Result<Option<PirWitnessRow>, SqliteClientError> {
    let mut stmt = conn.prepare(
        "SELECT note_id, siblings, anchor_height, anchor_root \
         FROM pir_witness_data WHERE note_id = ?1",
    )?;

    let result = stmt
        .query_row([note_id], |row| {
            let note_id: i64 = row.get(0)?;
            let siblings_blob: Vec<u8> = row.get(1)?;
            let anchor_height: i64 = row.get(2)?;
            let anchor_root_blob: Vec<u8> = row.get(3)?;
            Ok((
                note_id,
                siblings_blob,
                anchor_height as u64,
                anchor_root_blob,
            ))
        })
        .optional()?;

    match result {
        None => Ok(None),
        Some((note_id, siblings_blob, anchor_height, anchor_root_blob)) => {
            let siblings = parse_siblings(&siblings_blob)?;
            let anchor_root: [u8; 32] = anchor_root_blob.try_into().map_err(|_| {
                SqliteClientError::CorruptedData(
                    "pir_witness_data anchor_root is not 32 bytes".to_string(),
                )
            })?;
            Ok(Some(PirWitnessRow {
                note_id,
                siblings,
                anchor_height,
                anchor_root,
            }))
        }
    }
}

/// Returns notes that have PIR witnesses and are still unspent.
pub fn get_pir_witnessed_notes(
    conn: &Connection,
) -> Result<Vec<PirWitnessedNote>, SqliteClientError> {
    let mut stmt = conn.prepare(WITNESSED_NOTES_SQL)?;

    let notes = stmt
        .query_map([], |row| {
            let note_id: i64 = row.get(0)?;
            let value: i64 = row.get(1)?;
            let anchor_height: i64 = row.get(2)?;
            Ok(PirWitnessedNote {
                note_id,
                value: value as u64,
                anchor_height: anchor_height as u64,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(notes)
}

/// Checks whether a PIR witness exists for the given note.
pub fn has_pir_witness(conn: &Connection, note_id: i64) -> Result<bool, SqliteClientError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pir_witness_data WHERE note_id = ?1",
        [note_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
}

/// Retrieves a PIR witness for the given note and converts it into a `MerklePath`
/// suitable for the Orchard transaction builder.
///
/// Returns `Ok(None)` if no PIR witness exists for the note.
///
/// The `MerklePath` contains the same data as `ShardTree::witness_at_checkpoint_id_caching`
/// would return: 32 authentication path siblings ordered leaf-to-root, with the position
/// encoding the left/right direction at each level.
///
/// The caller is responsible for using `pir_witness.anchor_height` and
/// `pir_witness.anchor_root` to set the transaction's Orchard anchor — the PIR anchor
/// may differ from the proposal's computed anchor.
#[cfg(feature = "orchard")]
pub fn get_pir_merkle_path(
    conn: &Connection,
    note_id: i64,
    position: Position,
) -> PirWitnessResult {
    let witness = get_pir_witness(conn, note_id)?;
    match witness {
        None => Ok(None),
        Some(row) => {
            let path: Vec<MerkleHashOrchard> = row
                .siblings
                .iter()
                .map(|bytes| {
                    Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or_else(|| {
                        SqliteClientError::CorruptedData(
                            "invalid MerkleHashOrchard in pir_witness_data".to_string(),
                        )
                    })
                })
                .collect::<Result<_, _>>()?;

            let merkle_path = MerklePath::from_parts(path, position).map_err(|_| {
                SqliteClientError::CorruptedData(
                    "failed to construct MerklePath from PIR witness".to_string(),
                )
            })?;

            Ok(Some((merkle_path, row.anchor_height, row.anchor_root)))
        }
    }
}

/// Retrieves a PIR Merkle path by the note's commitment tree position.
///
/// Joins through `orchard_received_notes` to find the matching `note_id`, then
/// delegates to [`get_pir_merkle_path`].
#[cfg(feature = "orchard")]
pub fn get_pir_merkle_path_by_position(conn: &Connection, position: Position) -> PirWitnessResult {
    let note_id: Option<i64> = conn
        .query_row(
            "SELECT rn.id FROM orchard_received_notes rn \
             INNER JOIN pir_witness_data pw ON pw.note_id = rn.id \
             WHERE rn.commitment_tree_position = ?1",
            [u64::from(position) as i64],
            |row| row.get(0),
        )
        .optional()?;

    match note_id {
        Some(id) => get_pir_merkle_path(conn, id, position),
        None => Ok(None),
    }
}

fn parse_siblings(blob: &[u8]) -> Result<[[u8; 32]; 32], SqliteClientError> {
    if blob.len() != 1024 {
        return Err(SqliteClientError::CorruptedData(format!(
            "pir_witness_data siblings blob is {} bytes, expected 1024",
            blob.len()
        )));
    }
    let mut siblings = [[0u8; 32]; 32];
    for (i, chunk) in blob.chunks_exact(32).enumerate() {
        siblings[i].copy_from_slice(chunk);
    }
    Ok(siblings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{PirWitnessTestDb, insert_test_note, insert_test_note_with_position};

    fn make_nf(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn make_siblings(seed: u8) -> [[u8; 32]; 32] {
        let mut siblings = [[0u8; 32]; 32];
        for (i, sibling) in siblings.iter_mut().enumerate() {
            sibling.fill(seed.wrapping_add(i as u8));
        }
        siblings
    }

    fn make_root(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn mark_spent(conn: &Connection, note_id: i64) {
        conn.execute(
            "INSERT INTO orchard_received_note_spends (orchard_received_note_id, transaction_id) \
             VALUES (?1, 100)",
            [note_id],
        )
        .unwrap();
    }

    fn mark_pir_spent(conn: &Connection, note_id: i64) {
        conn.execute(
            "INSERT INTO pir_spent_notes (note_id) VALUES (?1)",
            [note_id],
        )
        .unwrap();
    }

    // =========================================================================
    // Notes needing witness
    // =========================================================================

    #[test]
    fn empty_table_returns_no_notes() {
        let db = PirWitnessTestDb::new();
        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn returns_notes_with_position_and_unscanned_shard() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].id, 1);
        assert_eq!(notes[0].position, 1000);
        assert_eq!(notes[0].value, 50_000);
    }

    #[test]
    fn excludes_notes_without_position() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note(db.conn(), 2, 75_000, Some(&make_nf(0xBB)));

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_notes_without_nullifier() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, None, Some(2000));

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_spent_notes() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        mark_spent(db.conn(), 2);

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_pir_spent_notes() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        mark_pir_spent(db.conn(), 2);

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_notes_already_witnessed() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        insert_pir_witness(db.conn(), 2, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    // =========================================================================
    // Insert witness
    // =========================================================================

    #[test]
    fn insert_basic() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_idempotent() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 1, &make_siblings(0x20), 200, &make_root(0xEE)).unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    // =========================================================================
    // Get witness
    // =========================================================================

    #[test]
    fn get_witness_returns_none_when_absent() {
        let db = PirWitnessTestDb::new();
        let result = get_pir_witness(db.conn(), 999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_witness_returns_stored_data() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let siblings = make_siblings(0x10);
        let root = make_root(0xFF);
        insert_pir_witness(db.conn(), 1, &siblings, 100, &root).unwrap();

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.note_id, 1);
        assert_eq!(row.siblings, siblings);
        assert_eq!(row.anchor_height, 100);
        assert_eq!(row.anchor_root, root);
    }

    // =========================================================================
    // Witnessed notes
    // =========================================================================

    #[test]
    fn witnessed_notes_empty_when_no_witnesses() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let notes = get_pir_witnessed_notes(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn witnessed_notes_returns_unspent_with_witness() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 2, &make_siblings(0x20), 100, &make_root(0xFF)).unwrap();

        let notes = get_pir_witnessed_notes(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].value + notes[1].value, 125_000);
    }

    #[test]
    fn witnessed_notes_excludes_spent() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 2, &make_siblings(0x20), 100, &make_root(0xFF)).unwrap();
        mark_spent(db.conn(), 2);

        let notes = get_pir_witnessed_notes(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_id, 1);
    }

    // =========================================================================
    // has_pir_witness
    // =========================================================================

    #[test]
    fn has_witness_false_when_absent() {
        let db = PirWitnessTestDb::new();
        assert!(!has_pir_witness(db.conn(), 999).unwrap());
    }

    #[test]
    fn has_witness_true_when_present() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        assert!(has_pir_witness(db.conn(), 1).unwrap());
    }

    // =========================================================================
    // get_pir_merkle_path_by_position
    // =========================================================================

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_none_without_witness() {
        use incrementalmerkletree::Position;

        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(1000u64)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_path_with_witness() {
        use incrementalmerkletree::Position;

        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let siblings = make_siblings(0x10);
        let root = make_root(0xFF);
        insert_pir_witness(db.conn(), 1, &siblings, 200, &root).unwrap();

        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(1000u64)).unwrap();
        assert!(result.is_some());

        let (merkle_path, anchor_height, anchor_root) = result.unwrap();
        assert_eq!(anchor_height, 200);
        assert_eq!(anchor_root, root);
        assert_eq!(u64::from(merkle_path.position()), 1000);
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_no_match_for_wrong_position() {
        use incrementalmerkletree::Position;

        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 200, &make_root(0xFF)).unwrap();

        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(9999u64)).unwrap();
        assert!(result.is_none());
    }

    // =========================================================================
    // FK cascade
    // =========================================================================

    #[test]
    fn fk_cascade_on_note_delete() {
        let db = PirWitnessTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        db.conn()
            .execute("DELETE FROM orchard_received_notes WHERE id = 1", [])
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_witness_data", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
