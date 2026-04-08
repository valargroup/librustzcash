//! PIR (Private Information Retrieval) note lifecycle storage.
//!
//! All PIR state lives in the single `pir_notes` table, created unconditionally by
//! migration so the schema is identical across builds. When the `spendability-pir`
//! feature is off, the table is empty and unused.
//!
//! A row tracks one Orchard note through three overlapping concerns:
//!
//! - **Spend detection** — nullifier PIR discovers that a canonical note has been
//!   spent on-chain before the scanner confirms it (`is_spent = 1`).
//!
//! - **Witness storage** — witness PIR fetches the Merkle authentication path from
//!   a server, enabling a note to be spent before its shard is fully scanned
//!   (`witness_siblings IS NOT NULL`).
//!
//! - **Provisional notes** — when nullifier PIR detects a spend, trial decryption
//!   discovers the resulting change notes. These "provisional" rows have
//!   `canonical_note_id = NULL` until the scanner catches up and reconciles them.

use rusqlite::{Connection, OptionalExtension, named_params, params};

use crate::error::SqliteClientError;

#[cfg(feature = "orchard")]
use {
    incrementalmerkletree::{MerklePath, Position},
    orchard::{note::ExtractedNoteCommitment, tree::MerkleHashOrchard},
    zcash_client_backend::wallet::ReceivedNote,
    zcash_protocol::consensus,
};

// =========================================================================
// Test infrastructure
// =========================================================================

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing {
    use rusqlite::Connection;

    use secrecy::SecretVec;
    use zcash_protocol::consensus::Network;

    use crate::{WalletDb, wallet::init::WalletMigrator};

    /// Runs the full wallet migration on `path`, then reopens a plain
    /// [`Connection`] with FK enforcement and prerequisite rows for PIR tests.
    fn migrate_and_setup(path: impl AsRef<std::path::Path>) -> Connection {
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
                 'test-uivk-for-pir', 1, 1
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

    /// A migrated wallet database for PIR tests. Holds the temp file so the
    /// on-disk database is not cleaned up while tests are running.
    #[cfg(test)]
    pub struct PirTestDb {
        conn: Connection,
        _data_file: tempfile::NamedTempFile,
    }

    #[cfg(test)]
    impl Default for PirTestDb {
        fn default() -> Self {
            Self::new()
        }
    }

    #[cfg(test)]
    impl PirTestDb {
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

    /// Creates an on-disk SQLite database with the full migrated wallet schema,
    /// ready for PIR tests. Caller is responsible for cleanup.
    pub fn create_pir_test_db_on_disk(suffix: &str) -> (Connection, std::path::PathBuf) {
        let db_path = std::env::temp_dir().join(format!(
            "pir_test_{}_{}_{}.db",
            std::process::id(),
            suffix,
            std::thread::current().name().unwrap_or("t")
        ));
        let conn = migrate_and_setup(&db_path);
        (conn, db_path)
    }

    /// Inserts a synthetic note row into `orchard_received_notes` for testing.
    ///
    /// Sets `commitment_tree_position` and `recipient_key_scope` so the note is
    /// eligible for witness queries. Use `position = None` for notes that should
    /// lack a tree position.
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

    /// Minimal note insert without `commitment_tree_position` or `recipient_key_scope`.
    pub fn insert_test_note(conn: &Connection, id: i64, value: i64, nf: Option<&[u8]>) {
        conn.execute(
            "INSERT INTO orchard_received_notes \
             (id, transaction_id, action_index, account_id, diversifier, value, \
              rho, rseed, nf, is_change) \
             VALUES (?1, 100, ?1, 1, X'00', ?2, X'00', X'00', ?3, 0)",
            rusqlite::params![id, value, nf],
        )
        .unwrap();
    }
}

// =========================================================================
// Types
// =========================================================================

/// An unspent Orchard note with its nullifier, for PIR spend-checking.
pub struct UnspentOrchardNote {
    pub id: i64,
    pub nf: [u8; 32],
    pub value: u64,
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

#[cfg(feature = "orchard")]
type PirWitnessResult =
    Result<Option<(MerklePath<MerkleHashOrchard, 32>, u64, [u8; 32])>, SqliteClientError>;

#[cfg(feature = "orchard")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PirWitnessValidation {
    pub provided_anchor_root: [u8; 32],
    pub computed_root: [u8; 32],
}

#[cfg(feature = "orchard")]
impl PirWitnessValidation {
    pub fn witness_root_matches_anchor(&self) -> bool {
        self.computed_root == self.provided_anchor_root
    }
}

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

/// A PIR-derived transaction entry for the activity view.
///
/// Aggregates co-spent canonical notes by `spending_tx_hash` and computes
/// the net spend as `gross_value - change_value`.
pub struct PirActivityEntry {
    pub tx_hash: [u8; 32],
    pub block_time: u32,
    pub fee: Option<u64>,
    pub height: u32,
    pub gross_value: u64,
    pub change_value: u64,
}

impl PirActivityEntry {
    pub fn net_value(&self) -> u64 {
        self.gross_value.saturating_sub(self.change_value)
    }
}

// =========================================================================
// Spend tracking
// =========================================================================

const UNSPENT_ORCHARD_NOTES_SQL: &str = "\
    SELECT rn.id, rn.nf, rn.value FROM orchard_received_notes rn \
    WHERE rn.nf IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = rn.id \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM pir_notes pn \
        WHERE pn.canonical_note_id = rn.id AND pn.is_spent = 1 \
    )";

/// Returns unspent Orchard notes that have nullifiers, excluding both
/// scan-confirmed spends and PIR-detected spends. Used by the PIR FFI
/// to determine which nullifiers to check against the PIR server.
pub fn get_unspent_orchard_notes_for_pir(
    conn: &Connection,
) -> Result<Vec<UnspentOrchardNote>, SqliteClientError> {
    let mut stmt = conn.prepare(UNSPENT_ORCHARD_NOTES_SQL)?;

    let notes = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let nf_blob: Vec<u8> = row.get(1)?;
            let value: i64 = row.get(2)?;
            Ok((id, nf_blob, value as u64))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    notes
        .into_iter()
        .map(|(id, nf_blob, value)| {
            let nf: [u8; 32] = nf_blob.try_into().map_err(|_| {
                SqliteClientError::CorruptedData(
                    "orchard nullifier is not 32 bytes".to_string(),
                )
            })?;
            Ok(UnspentOrchardNote { id, nf, value })
        })
        .collect()
}

/// Records a canonical note as PIR-spent by upserting into `pir_notes`.
///
/// If a row already exists for this canonical note (e.g. from a witness insert),
/// sets `is_spent = 1`. Otherwise inserts a new row pulling position/value/account
/// from `orchard_received_notes`.
///
/// Skips notes that are already scan-confirmed spent.
pub fn insert_pir_spent_note(conn: &Connection, note_id: i64) -> Result<(), SqliteClientError> {
    conn.execute(
        "INSERT INTO pir_notes (canonical_note_id, account_id, position, value, is_spent)
         SELECT rn.id, rn.account_id, rn.commitment_tree_position, rn.value, 1
         FROM orchard_received_notes rn
         WHERE rn.id = ?1
         AND rn.commitment_tree_position IS NOT NULL
         AND NOT EXISTS (
             SELECT 1 FROM orchard_received_note_spends
             WHERE orchard_received_note_id = ?1
         )
         ON CONFLICT(canonical_note_id) DO UPDATE SET
             is_spent = 1",
        [note_id],
    )?;
    Ok(())
}

// =========================================================================
// Activity entries (PIR-derived transaction data for the UI)
// =========================================================================

/// Returns the `pir_notes.id` for a given canonical note ID, if one exists.
pub fn get_pir_note_id_for_canonical(
    conn: &Connection,
    canonical_note_id: i64,
) -> Result<Option<i64>, SqliteClientError> {
    let id = conn
        .query_row(
            "SELECT id FROM pir_notes WHERE canonical_note_id = ?1",
            [canonical_note_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(id)
}

/// Sets spending transaction metadata on a `pir_notes` row after change discovery.
pub fn set_pir_spending_tx_metadata(
    conn: &Connection,
    pir_note_id: i64,
    tx_hash: &[u8; 32],
    block_time: u32,
    fee: Option<u64>,
    spend_height: Option<u32>,
) -> Result<(), SqliteClientError> {
    conn.execute(
        "UPDATE pir_notes
         SET spending_tx_hash = :tx_hash,
             spending_block_time = :block_time,
             spending_fee = :fee,
             spend_height = COALESCE(:spend_height, spend_height)
         WHERE id = :id",
        named_params! {
            ":id": pir_note_id,
            ":tx_hash": &tx_hash[..],
            ":block_time": block_time,
            ":fee": fee.map(|f| f as i64),
            ":spend_height": spend_height,
        },
    )?;
    Ok(())
}

const PIR_ACTIVITY_ENTRIES_SQL: &str = "\
    WITH RECURSIVE pending_roots AS ( \
        SELECT pn.id, pn.spending_tx_hash, pn.spending_block_time, pn.spending_fee, \
               pn.spend_height, rn.value AS gross_value \
        FROM pir_notes pn \
        JOIN orchard_received_notes rn ON pn.canonical_note_id = rn.id \
        WHERE pn.is_spent = 1 \
          AND pn.spending_tx_hash IS NOT NULL \
          AND NOT EXISTS ( \
              SELECT 1 FROM orchard_received_note_spends sp \
              WHERE sp.orchard_received_note_id = pn.canonical_note_id \
          ) \
    ), \
    tree(node_id, tx_hash) AS ( \
        SELECT id, spending_tx_hash FROM pending_roots \
        UNION ALL \
        SELECT child.id, tree.tx_hash \
        FROM pir_notes child \
        JOIN tree ON child.parent_id = tree.node_id \
    ) \
    SELECT \
        pr.spending_tx_hash AS tx_hash, \
        MAX(pr.spending_block_time) AS block_time, \
        MAX(pr.spending_fee) AS fee, \
        MAX(pr.spend_height) AS height, \
        SUM(pr.gross_value) AS gross_value, \
        COALESCE(( \
            SELECT SUM(leaf.value) \
            FROM tree t \
            JOIN pir_notes leaf ON leaf.id = t.node_id \
            WHERE t.tx_hash = pr.spending_tx_hash \
              AND leaf.is_spent = 0 \
              AND leaf.canonical_note_id IS NULL \
              AND leaf.id NOT IN (SELECT id FROM pending_roots) \
        ), 0) AS change_value \
    FROM pending_roots pr \
    GROUP BY pr.spending_tx_hash";

/// Returns PIR-derived transaction entries for the activity view.
///
/// Each entry represents a spending transaction detected via PIR that the
/// scanner has not yet confirmed. Co-spent canonical notes are grouped by
/// `spending_tx_hash`. The `change_value` is the sum of unspent descendant
/// provisional leaves, giving `net_value = gross_value - change_value`.
pub fn get_pir_activity_entries(
    conn: &Connection,
) -> Result<Vec<PirActivityEntry>, SqliteClientError> {
    let mut stmt = conn.prepare(PIR_ACTIVITY_ENTRIES_SQL)?;

    let entries = stmt
        .query_map([], |row| {
            let tx_hash_blob: Vec<u8> = row.get("tx_hash")?;
            let block_time: i64 = row.get("block_time")?;
            let fee: Option<i64> = row.get("fee")?;
            let height: i64 = row.get("height")?;
            let gross_value: i64 = row.get("gross_value")?;
            let change_value: i64 = row.get("change_value")?;
            Ok((tx_hash_blob, block_time, fee, height, gross_value, change_value))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    entries
        .into_iter()
        .map(|(tx_hash_blob, block_time, fee, height, gross_value, change_value)| {
            let tx_hash: [u8; 32] = tx_hash_blob.try_into().map_err(|_| {
                SqliteClientError::CorruptedData(
                    "pir_notes spending_tx_hash is not 32 bytes".to_string(),
                )
            })?;
            Ok(PirActivityEntry {
                tx_hash,
                block_time: block_time as u32,
                fee: fee.map(|f| f as u64),
                height: height as u32,
                gross_value: gross_value as u64,
                change_value: change_value as u64,
            })
        })
        .collect()
}

// =========================================================================
// Witness storage
// =========================================================================

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
        SELECT 1 FROM pir_notes pn \
        WHERE pn.canonical_note_id = rn.id AND pn.is_spent = 1 \
    ) \
    AND NOT EXISTS ( \
        SELECT 1 FROM pir_notes pn \
        WHERE pn.canonical_note_id = rn.id AND pn.witness_siblings IS NOT NULL \
    ) \
    AND (scan_state.max_priority IS NULL \
         OR scan_state.max_priority > ?1)";

const WITNESSED_NOTES_SQL: &str = "\
    SELECT pn.canonical_note_id AS note_id, rn.value, pn.witness_anchor_height AS anchor_height \
    FROM pir_notes pn \
    JOIN orchard_received_notes rn ON pn.canonical_note_id = rn.id \
    WHERE pn.witness_siblings IS NOT NULL \
    AND NOT EXISTS ( \
        SELECT 1 FROM orchard_received_note_spends sp \
        WHERE sp.orchard_received_note_id = pn.canonical_note_id \
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

/// Stores a PIR-obtained witness for a canonical note by upserting into `pir_notes`.
///
/// If a row already exists for this canonical note (e.g. from a spent-note insert),
/// the witness columns are updated. Otherwise a new row is inserted pulling
/// position/value/account from `orchard_received_notes`.
///
/// Existing witnesses are refreshed only when the incoming snapshot is at least
/// as new as the stored anchor height.
pub fn insert_pir_witness(
    conn: &Connection,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_height: u64,
    anchor_root: &[u8; 32],
) -> Result<(), SqliteClientError> {
    let siblings_blob: Vec<u8> = siblings.iter().flat_map(|s| s.iter()).copied().collect();
    conn.execute(
        "INSERT INTO pir_notes (canonical_note_id, account_id, position, value,
                                witness_siblings, witness_anchor_height, witness_anchor_root)
         SELECT rn.id, rn.account_id, rn.commitment_tree_position, rn.value,
                ?2, ?3, ?4
         FROM orchard_received_notes rn
         WHERE rn.id = ?1
         AND rn.commitment_tree_position IS NOT NULL
         ON CONFLICT(canonical_note_id) DO UPDATE SET
             witness_siblings = excluded.witness_siblings,
             witness_anchor_height = excluded.witness_anchor_height,
             witness_anchor_root = excluded.witness_anchor_root
         WHERE excluded.witness_anchor_height >= IFNULL(pir_notes.witness_anchor_height, 0)",
        params![
            note_id,
            siblings_blob,
            anchor_height as i64,
            anchor_root.as_slice()
        ],
    )?;
    Ok(())
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

/// Retrieves a stored PIR witness for a specific canonical note.
pub fn get_pir_witness(
    conn: &Connection,
    note_id: i64,
) -> Result<Option<PirWitnessRow>, SqliteClientError> {
    let result = conn
        .query_row(
            "SELECT canonical_note_id, witness_siblings, witness_anchor_height, witness_anchor_root \
             FROM pir_notes WHERE canonical_note_id = ?1 AND witness_siblings IS NOT NULL",
            [note_id],
            |row| {
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
            },
        )
        .optional()?;

    match result {
        None => Ok(None),
        Some((note_id, siblings_blob, anchor_height, anchor_root_blob)) => {
            let siblings = parse_siblings(&siblings_blob)?;
            let anchor_root: [u8; 32] = anchor_root_blob.try_into().map_err(|_| {
                SqliteClientError::CorruptedData(
                    "pir_notes witness_anchor_root is not 32 bytes".to_string(),
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

/// Checks whether a PIR witness exists for the given canonical note.
pub fn has_pir_witness(conn: &Connection, note_id: i64) -> Result<bool, SqliteClientError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = ?1 AND witness_siblings IS NOT NULL",
        [note_id],
        |row| row.get(0),
    )?;
    Ok(count > 0)
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

// =========================================================================
// Merkle path construction
// =========================================================================

/// Retrieves a PIR witness for the given note and converts it into a `MerklePath`
/// suitable for the Orchard transaction builder.
///
/// Returns `Ok(None)` if no PIR witness exists for the note.
///
/// The `MerklePath` contains the same data as `ShardTree::witness_at_checkpoint_id_caching`
/// would return: 32 authentication path siblings ordered leaf-to-root, with the position
/// encoding the left/right direction at each level.
///
/// The caller is responsible for using the returned anchor height and root to set the
/// transaction's Orchard anchor — the PIR anchor may differ from the proposal's computed
/// anchor.
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
                            "invalid MerkleHashOrchard in pir_notes".to_string(),
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
             INNER JOIN pir_notes pn ON pn.canonical_note_id = rn.id \
             WHERE rn.commitment_tree_position = ?1 \
             AND pn.witness_siblings IS NOT NULL",
            [u64::from(position) as i64],
            |row| row.get(0),
        )
        .optional()?;

    match note_id {
        Some(id) => get_pir_merkle_path(conn, id, position),
        None => Ok(None),
    }
}

/// Validates a PIR-obtained Merkle witness against the note's commitment.
///
/// Reconstructs the Orchard `MerklePath` from the supplied siblings and computes
/// the root from the note's extracted commitment (`cmx`). Returns a
/// [`PirWitnessValidation`] containing both the provided and computed roots so
/// the caller can check whether they match.
///
/// This is used for server-trust verification: the PIR server supplies (siblings,
/// anchor_root), and we independently compute the root from the note + siblings to
/// confirm the path is authentic.
#[cfg(feature = "orchard")]
pub fn validate_orchard_witness<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    note_id: i64,
    siblings: &[[u8; 32]; 32],
    anchor_height: u64,
    anchor_root: &[u8; 32],
) -> Result<PirWitnessValidation, SqliteClientError> {
    let received_note = get_orchard_received_note(conn, params, note_id)?;
    let txid = hex::encode(received_note.txid().as_ref());
    let action_index = received_note.output_index();
    let position = received_note.note_commitment_tree_position();
    let value = received_note.note().value().inner();
    let mined_height = received_note.mined_height().map(u32::from);

    let path: Vec<MerkleHashOrchard> = siblings
        .iter()
        .map(|bytes| {
            Option::from(MerkleHashOrchard::from_bytes(bytes)).ok_or_else(|| {
                SqliteClientError::CorruptedData(
                    "invalid MerkleHashOrchard in PIR witness validation input".to_string(),
                )
            })
        })
        .collect::<Result<_, _>>()?;

    let merkle_path: MerklePath<MerkleHashOrchard, 32> = MerklePath::from_parts(path, position)
        .map_err(|_| {
            SqliteClientError::CorruptedData(
                "failed to construct MerklePath from PIR witness validation input".to_string(),
            )
        })?;
    let note = received_note.note();
    let ecmx: ExtractedNoteCommitment = note.commitment().into();
    let cmx = MerkleHashOrchard::from_cmx(&ecmx);
    let computed_root = merkle_path.root(cmx).to_bytes();
    let witness_root_matches_anchor = computed_root == *anchor_root;

    if !witness_root_matches_anchor {
        tracing::warn!(
            note_id,
            txid = %txid,
            action_index,
            position = u64::from(position),
            value,
            mined_height,
            anchor_height,
            "wallet PIR witness validation root mismatch",
        );
    }

    Ok(PirWitnessValidation {
        provided_anchor_root: *anchor_root,
        computed_root,
    })
}

// =========================================================================
// Provisional note lifecycle
// =========================================================================

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

// =========================================================================
// Internal helpers
// =========================================================================

/// Loads an Orchard `ReceivedNote` from the database for witness validation.
///
/// The note must have a UFVK, recipient key scope, and commitment tree position.
/// Returns a `CorruptedData` error if the note cannot be found or reconstructed.
#[cfg(feature = "orchard")]
fn get_orchard_received_note<P: consensus::Parameters>(
    conn: &Connection,
    params: &P,
    note_id: i64,
) -> Result<ReceivedNote<crate::ReceivedNoteId, orchard::note::Note>, SqliteClientError> {
    let result = conn.query_row_and_then(
        "SELECT
             rn.id,
             t.txid,
             rn.action_index,
             rn.diversifier,
             rn.value,
             rn.rho,
             rn.rseed,
             rn.commitment_tree_position,
             accounts.ufvk,
             rn.recipient_key_scope,
             t.mined_height,
             NULL AS max_shielding_input_height
         FROM orchard_received_notes rn
         INNER JOIN accounts ON accounts.id = rn.account_id
         INNER JOIN transactions t ON t.id_tx = rn.transaction_id
         WHERE rn.id = ?1
         AND accounts.ufvk IS NOT NULL
         AND rn.recipient_key_scope IS NOT NULL
         AND rn.commitment_tree_position IS NOT NULL",
        [note_id],
        |row| super::orchard::to_received_note(params, row),
    );

    match result {
        Ok(Some(note)) => Ok(note),
        Ok(None) => Err(SqliteClientError::CorruptedData(format!(
            "failed to reconstruct Orchard note {note_id} for PIR witness validation"
        ))),
        Err(SqliteClientError::DbError(rusqlite::Error::QueryReturnedNoRows)) => {
            Err(SqliteClientError::CorruptedData(format!(
                "Orchard note {note_id} not found for PIR witness validation"
            )))
        }
        Err(e) => Err(e),
    }
}

/// Parses a 1024-byte blob into 32 Merkle siblings (32 bytes each).
fn parse_siblings(blob: &[u8]) -> Result<[[u8; 32]; 32], SqliteClientError> {
    if blob.len() != 1024 {
        return Err(SqliteClientError::CorruptedData(format!(
            "pir_notes witness_siblings blob is {} bytes, expected 1024",
            blob.len()
        )));
    }
    let mut siblings = [[0u8; 32]; 32];
    for (i, chunk) in blob.chunks_exact(32).enumerate() {
        siblings[i].copy_from_slice(chunk);
    }
    Ok(siblings)
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use testing::{PirTestDb, insert_test_note, insert_test_note_with_position};

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
        insert_pir_spent_note(conn, note_id).unwrap();
    }

    fn insert_canonical_note(conn: &Connection, id: i64, position: i64, value: i64) {
        insert_test_note_with_position(
            conn,
            id,
            value,
            Some(&[id as u8; 32]),
            Some(position),
        );
    }

    fn insert_test_provisional(conn: &Connection, position: u64, value: u64) -> i64 {
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
            1,
            None,
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

    #[cfg(feature = "orchard")]
    macro_rules! real_orchard_witness_fixture {
        () => {{
            use zcash_client_backend::data_api::WalletCommitmentTrees;
            use zcash_client_backend::data_api::testing::{
                AddressType, TestBuilder, orchard::OrchardPoolTester, pool::ShieldedPoolTester,
            };
            use zcash_primitives::block::BlockHash;
            use zcash_protocol::value::Zatoshis;

            use crate::{
                testing::{BlockCache, db::TestDbFactory},
                wallet::commitment_tree,
            };

            let mut st = TestBuilder::new()
                .with_data_store_factory(TestDbFactory::default())
                .with_block_cache(BlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32]))
                .build();

            let dfvk = OrchardPoolTester::test_account_fvk(&st);
            let value = Zatoshis::const_from_u64(60_000);
            let (h, _, _) = st.generate_next_block(&dfvk, AddressType::DefaultExternal, value);
            st.scan_cached_blocks(h, 1);

            let (note_id, note_position): (i64, i64) = st
                .wallet()
                .conn()
                .query_row(
                    "SELECT id, commitment_tree_position FROM orchard_received_notes LIMIT 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();

            let position = incrementalmerkletree::Position::from(note_position as u64);
            let (siblings, anchor_root) = st
                .wallet_mut()
                .with_orchard_tree_mut::<
                    _,
                    _,
                    shardtree::error::ShardTreeError<commitment_tree::Error>,
                >(|orchard_tree| {
                    let root = orchard_tree
                        .root_at_checkpoint_id(&h)?
                        .expect("root exists at scanned height");
                    let merkle_path = orchard_tree
                        .witness_at_checkpoint_id_caching(position, &h)?
                        .expect("witness exists for scanned note");

                    let mut siblings = [[0u8; 32]; 32];
                    for (i, elem) in merkle_path.path_elems().iter().enumerate() {
                        siblings[i] = elem.to_bytes();
                    }

                    Ok((siblings, root.to_bytes()))
                })
                .unwrap();

            (st, note_id, note_position, siblings, anchor_root, u32::from(h) as u64)
        }};
    }

    // =====================================================================
    // Spend tracking — unspent notes query
    // =====================================================================

    #[test]
    fn spend_empty_table_returns_no_notes() {
        let db = PirTestDb::new();
        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn returns_unspent_notes_with_nullifiers() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        let nf2 = make_nf(0xBB);
        insert_test_note(db.conn(), 1, 50_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 75_000, Some(&nf2));

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].id, 1);
        assert_eq!(notes[0].value, 50_000);
        assert_eq!(notes[0].nf, [0xAA; 32]);
        assert_eq!(notes[1].id, 2);
        assert_eq!(notes[1].value, 75_000);
    }

    #[test]
    fn spend_excludes_notes_without_nullifier() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        insert_test_note(db.conn(), 1, 50_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 75_000, None);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn spend_excludes_spent_notes() {
        let db = PirTestDb::new();
        let nf1 = make_nf(0xAA);
        let nf2 = make_nf(0xBB);
        let nf3 = make_nf(0xCC);
        insert_test_note(db.conn(), 1, 10_000, Some(&nf1));
        insert_test_note(db.conn(), 2, 20_000, Some(&nf2));
        insert_test_note(db.conn(), 3, 30_000, Some(&nf3));

        mark_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        let ids: Vec<i64> = notes.iter().map(|n| n.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn spend_excludes_pir_spent_notes() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 20_000, Some(&make_nf(0x02)), Some(2000));
        insert_test_note_with_position(db.conn(), 3, 30_000, Some(&make_nf(0x03)), Some(3000));

        mark_pir_spent(db.conn(), 2);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        let ids: Vec<i64> = notes.iter().map(|n| n.id).collect();
        assert!(ids.contains(&1));
        assert!(ids.contains(&3));
        assert!(!ids.contains(&2));
    }

    #[test]
    fn excludes_both_pir_and_real_spent() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 20_000, Some(&make_nf(0x02)), Some(2000));
        insert_test_note_with_position(db.conn(), 3, 30_000, Some(&make_nf(0x03)), Some(3000));

        mark_spent(db.conn(), 2);
        mark_pir_spent(db.conn(), 3);

        let notes = get_unspent_orchard_notes_for_pir(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn insert_pir_basic() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));

        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1 AND is_spent = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_pir_skips_real_spent() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));

        mark_spent(db.conn(), 1);
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn insert_pir_idempotent() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));

        insert_pir_spent_note(db.conn(), 1).unwrap();
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_pir_fk_cascade() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 10_000, Some(&make_nf(0x01)), Some(1000));

        mark_pir_spent(db.conn(), 1);

        db.conn()
            .execute("DELETE FROM orchard_received_notes WHERE id = 1", [])
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // =====================================================================
    // Witness — notes needing witness
    // =====================================================================

    #[test]
    fn witness_empty_table_returns_no_notes() {
        let db = PirTestDb::new();
        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn returns_notes_with_position_and_unscanned_shard() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 2);
        assert_eq!(notes[0].id, 1);
        assert_eq!(notes[0].position, 1000);
        assert_eq!(notes[0].value, 50_000);
    }

    #[test]
    fn witness_excludes_notes_without_position() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), None);

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn witness_excludes_notes_without_nullifier() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, None, Some(2000));

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn witness_excludes_spent_notes() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        mark_spent(db.conn(), 2);

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn witness_excludes_pir_spent_notes() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        mark_pir_spent(db.conn(), 2);

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    #[test]
    fn excludes_notes_already_witnessed() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        insert_pir_witness(db.conn(), 2, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let notes = get_notes_needing_pir_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].id, 1);
    }

    // =====================================================================
    // Witness — insert / get / has
    // =====================================================================

    #[test]
    fn insert_witness_basic() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1 AND witness_siblings IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn insert_replaces_existing_witness() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 1, &make_siblings(0x20), 200, &make_root(0xEE)).unwrap();

        let count: i64 = db
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.anchor_height, 200);
        assert_eq!(row.anchor_root, make_root(0xEE));
    }

    #[test]
    fn insert_does_not_replace_newer_witness_with_older_snapshot() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let newer_siblings = make_siblings(0x20);
        let newer_root = make_root(0xEE);
        insert_pir_witness(db.conn(), 1, &newer_siblings, 200, &newer_root).unwrap();

        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        let row = get_pir_witness(db.conn(), 1).unwrap().unwrap();
        assert_eq!(row.siblings, newer_siblings);
        assert_eq!(row.anchor_height, 200);
        assert_eq!(row.anchor_root, newer_root);
    }

    #[test]
    fn get_witness_returns_none_when_absent() {
        let db = PirTestDb::new();
        let result = get_pir_witness(db.conn(), 999).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_witness_returns_stored_data() {
        let db = PirTestDb::new();
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

    // =====================================================================
    // Witness — witnessed notes query
    // =====================================================================

    #[test]
    fn witnessed_notes_empty_when_no_witnesses() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));

        let notes = get_pir_witnessed_notes(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn witnessed_notes_returns_unspent_with_witness() {
        let db = PirTestDb::new();
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
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 75_000, Some(&make_nf(0xBB)), Some(2000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        insert_pir_witness(db.conn(), 2, &make_siblings(0x20), 100, &make_root(0xFF)).unwrap();
        mark_spent(db.conn(), 2);

        let notes = get_pir_witnessed_notes(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].note_id, 1);
    }

    // =====================================================================
    // Witness — has_pir_witness
    // =====================================================================

    #[test]
    fn has_witness_false_when_absent() {
        let db = PirTestDb::new();
        assert!(!has_pir_witness(db.conn(), 999).unwrap());
    }

    #[test]
    fn has_witness_true_when_present() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();
        assert!(has_pir_witness(db.conn(), 1).unwrap());
    }

    // =====================================================================
    // Witness — FK cascade
    // =====================================================================

    #[test]
    fn witness_fk_cascade_on_note_delete() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 100, &make_root(0xFF)).unwrap();

        db.conn()
            .execute("DELETE FROM orchard_received_notes WHERE id = 1", [])
            .unwrap();

        let count: i64 = db
            .conn()
            .query_row("SELECT COUNT(*) FROM pir_notes WHERE canonical_note_id = 1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    // =====================================================================
    // Merkle path construction
    // =====================================================================

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_none_without_witness() {
        use incrementalmerkletree::Position;

        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(1000u64)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn merkle_path_by_position_returns_path_with_witness() {
        use incrementalmerkletree::Position;

        let db = PirTestDb::new();
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

        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0xAA)), Some(1000));
        insert_pir_witness(db.conn(), 1, &make_siblings(0x10), 200, &make_root(0xFF)).unwrap();

        let result = get_pir_merkle_path_by_position(db.conn(), Position::from(9999u64)).unwrap();
        assert!(result.is_none());
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn validate_orchard_witness_accepts_real_merkle_path() {
        let (st, note_id, _note_position, siblings, anchor_root, anchor_height) =
            real_orchard_witness_fixture!();

        let validation = validate_orchard_witness(
            st.wallet().conn(),
            st.network(),
            note_id,
            &siblings,
            anchor_height,
            &anchor_root,
        )
        .expect("real Orchard witness should validate");

        assert_eq!(validation.provided_anchor_root, anchor_root);
        assert_eq!(validation.computed_root, anchor_root);
        assert!(
            validation.witness_root_matches_anchor(),
            "real Orchard witness should hash back to the provided anchor"
        );
    }

    #[cfg(feature = "orchard")]
    #[test]
    fn validate_orchard_witness_rejects_tampered_real_merkle_path() {
        let (st, note_id, _note_position, mut siblings, anchor_root, anchor_height) =
            real_orchard_witness_fixture!();

        siblings.swap(0, 1);
        let validation = validate_orchard_witness(
            st.wallet().conn(),
            st.network(),
            note_id,
            &siblings,
            anchor_height,
            &anchor_root,
        )
        .expect("tampered Orchard witness should still produce a validation result");

        assert!(
            !validation.witness_root_matches_anchor(),
            "tampered siblings should fail the note commitment -> anchor recomputation"
        );
    }

    // =====================================================================
    // Provisional — insert / retrieve
    // =====================================================================

    #[test]
    fn provisional_insert_and_retrieve() {
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
    fn provisional_insert_idempotent_by_position() {
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

    // =====================================================================
    // Provisional — witness
    // =====================================================================

    #[test]
    fn provisional_mark_witnessed() {
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
    fn provisional_mark_witnessed_nonexistent() {
        let db = PirTestDb::new();
        let siblings = [[0x10u8; 32]; 32];
        let updated = mark_provisional_note_witnessed(db.conn(), 9999, &siblings, 100, &[0xFF; 32]).unwrap();
        assert!(!updated);
    }

    #[test]
    fn provisional_needing_witness_returns_unwitnessed() {
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
    fn provisional_needing_witness_excludes_witnessed() {
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
    fn provisional_needing_witness_excludes_spent() {
        let db = PirTestDb::new();
        let id = insert_test_provisional(db.conn(), 1000, 50_000);
        insert_test_provisional(db.conn(), 2000, 75_000);

        mark_provisional_pir_result(db.conn(), id, true).unwrap();

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].position, 2000);
    }

    #[test]
    fn provisional_needing_witness_excludes_scanner_reconciled() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_canonical_note(db.conn(), 42, 1000, 50_000);
        reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();

        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    #[test]
    fn provisional_needing_witness_empty_table() {
        let db = PirTestDb::new();
        let notes = get_provisional_notes_needing_witness(db.conn()).unwrap();
        assert!(notes.is_empty());
    }

    // =====================================================================
    // Provisional — PIR check
    // =====================================================================

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

    // =====================================================================
    // Provisional — reconciliation
    // =====================================================================

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
    fn reconcile_idempotent() {
        let db = PirTestDb::new();
        insert_test_provisional(db.conn(), 1000, 50_000);
        insert_canonical_note(db.conn(), 42, 1000, 50_000);

        let r1 = reconcile_provisional_for_position(db.conn(), 1000, 42).unwrap();
        assert!(r1);

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

    // =====================================================================
    // Provisional — recursive chains
    // =====================================================================

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
        insert_pir_spent_note(db.conn(), 42).unwrap();

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
        assert_eq!(total, 1);

        let notes = get_provisional_notes_for_pir_check(db.conn()).unwrap();
        assert_eq!(notes.len(), 1);
        assert_eq!(notes[0].value, 40_000);
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

    // =====================================================================
    // Activity entries
    // =====================================================================

    fn make_tx_hash(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn setup_spent_with_change(
        conn: &Connection,
        note_id: i64,
        note_value: i64,
        position: i64,
        change_position: u64,
        change_value: u64,
        tx_hash: &[u8; 32],
    ) -> i64 {
        insert_test_note_with_position(conn, note_id, note_value, Some(&[note_id as u8; 32]), Some(position));
        insert_pir_spent_note(conn, note_id).unwrap();

        let pir_id: i64 = conn
            .query_row(
                "SELECT id FROM pir_notes WHERE canonical_note_id = ?1",
                [note_id],
                |r| r.get(0),
            )
            .unwrap();

        set_pir_spending_tx_metadata(conn, pir_id, tx_hash, 1700000000, Some(10_000), Some(3_200_000)).unwrap();

        insert_pir_provisional_note(
            conn, 1, change_value, change_position,
            &[0u8; 11], &[0u8; 32], &[0u8; 32],
            &[change_position as u8; 32], &[0u8; 32],
            3_200_000, 1, Some(pir_id),
        ).unwrap();

        pir_id
    }

    #[test]
    fn activity_empty_when_no_spends() {
        let db = PirTestDb::new();
        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn activity_single_spend_with_change() {
        let db = PirTestDb::new();
        let tx_hash = make_tx_hash(0xAA);
        setup_spent_with_change(db.conn(), 1, 100_000, 1000, 2000, 70_000, &tx_hash);

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_hash, tx_hash);
        assert_eq!(entries[0].gross_value, 100_000);
        assert_eq!(entries[0].change_value, 70_000);
        assert_eq!(entries[0].net_value(), 30_000);
        assert_eq!(entries[0].fee, Some(10_000));
        assert_eq!(entries[0].block_time, 1700000000);
    }

    #[test]
    fn activity_no_change_shows_full_amount() {
        let db = PirTestDb::new();
        let tx_hash = make_tx_hash(0xBB);
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0x01)), Some(1000));
        insert_pir_spent_note(db.conn(), 1).unwrap();
        let pir_id: i64 = db.conn()
            .query_row("SELECT id FROM pir_notes WHERE canonical_note_id = 1", [], |r| r.get(0))
            .unwrap();
        set_pir_spending_tx_metadata(db.conn(), pir_id, &tx_hash, 1700000000, None, Some(3_200_000)).unwrap();

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].gross_value, 50_000);
        assert_eq!(entries[0].change_value, 0);
        assert_eq!(entries[0].net_value(), 50_000);
        assert!(entries[0].fee.is_none());
    }

    #[test]
    fn activity_multi_hop_chain() {
        let db = PirTestDb::new();
        let tx_hash_a = make_tx_hash(0xAA);
        let pir_a = setup_spent_with_change(db.conn(), 1, 100_000, 1000, 2000, 70_000, &tx_hash_a);

        let change_b_id: i64 = db.conn()
            .query_row("SELECT id FROM pir_notes WHERE parent_id = ?1", [pir_a], |r| r.get(0))
            .unwrap();
        mark_provisional_pir_result(db.conn(), change_b_id, true).unwrap();

        let tx_hash_b = make_tx_hash(0xBB);
        set_pir_spending_tx_metadata(db.conn(), change_b_id, &tx_hash_b, 1700001000, Some(10_000), Some(3_200_001)).unwrap();
        insert_pir_provisional_note(
            db.conn(), 1, 50_000, 3000,
            &[0u8; 11], &[0u8; 32], &[0u8; 32],
            &[3u8; 32], &[0u8; 32],
            3_200_001, 2, Some(change_b_id),
        ).unwrap();

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_hash, tx_hash_a);
        assert_eq!(entries[0].gross_value, 100_000);
        assert_eq!(entries[0].change_value, 50_000);
        assert_eq!(entries[0].net_value(), 50_000);
    }

    #[test]
    fn activity_co_spent_notes_same_tx() {
        let db = PirTestDb::new();
        let tx_hash = make_tx_hash(0xCC);

        insert_test_note_with_position(db.conn(), 1, 60_000, Some(&make_nf(0x01)), Some(1000));
        insert_test_note_with_position(db.conn(), 2, 40_000, Some(&make_nf(0x02)), Some(1001));
        insert_pir_spent_note(db.conn(), 1).unwrap();
        insert_pir_spent_note(db.conn(), 2).unwrap();

        let pir1: i64 = db.conn()
            .query_row("SELECT id FROM pir_notes WHERE canonical_note_id = 1", [], |r| r.get(0))
            .unwrap();
        let pir2: i64 = db.conn()
            .query_row("SELECT id FROM pir_notes WHERE canonical_note_id = 2", [], |r| r.get(0))
            .unwrap();

        set_pir_spending_tx_metadata(db.conn(), pir1, &tx_hash, 1700000000, Some(10_000), Some(3_200_000)).unwrap();
        set_pir_spending_tx_metadata(db.conn(), pir2, &tx_hash, 1700000000, Some(10_000), Some(3_200_000)).unwrap();

        insert_pir_provisional_note(
            db.conn(), 1, 80_000, 2000,
            &[0u8; 11], &[0u8; 32], &[0u8; 32],
            &[2u8; 32], &[0u8; 32],
            3_200_000, 1, Some(pir1),
        ).unwrap();

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].gross_value, 100_000);
        assert_eq!(entries[0].change_value, 80_000);
        assert_eq!(entries[0].net_value(), 20_000);
    }

    #[test]
    fn activity_scanner_confirmation_removes_entry() {
        let db = PirTestDb::new();
        let tx_hash = make_tx_hash(0xDD);
        setup_spent_with_change(db.conn(), 1, 100_000, 1000, 2000, 70_000, &tx_hash);

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert_eq!(entries.len(), 1);

        mark_spent(db.conn(), 1);

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn activity_excludes_entries_without_tx_metadata() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0x01)), Some(1000));
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn set_tx_metadata_basic() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0x01)), Some(1000));
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let pir_id = get_pir_note_id_for_canonical(db.conn(), 1).unwrap().unwrap();
        let tx_hash = make_tx_hash(0xEE);
        set_pir_spending_tx_metadata(db.conn(), pir_id, &tx_hash, 1700000000, Some(10_000), Some(3_200_000)).unwrap();

        let (stored_hash, stored_time, stored_fee): (Vec<u8>, i64, Option<i64>) = db.conn()
            .query_row(
                "SELECT spending_tx_hash, spending_block_time, spending_fee FROM pir_notes WHERE id = ?1",
                [pir_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored_hash, tx_hash.to_vec());
        assert_eq!(stored_time, 1700000000);
        assert_eq!(stored_fee, Some(10_000));
    }

    #[test]
    fn get_pir_note_id_for_canonical_basic() {
        let db = PirTestDb::new();
        insert_test_note_with_position(db.conn(), 1, 50_000, Some(&make_nf(0x01)), Some(1000));
        insert_pir_spent_note(db.conn(), 1).unwrap();

        let id = get_pir_note_id_for_canonical(db.conn(), 1).unwrap();
        assert!(id.is_some());

        let id_none = get_pir_note_id_for_canonical(db.conn(), 999).unwrap();
        assert!(id_none.is_none());
    }

    #[test]
    fn activity_multi_hop_intermediate_without_tx_metadata() {
        let db = PirTestDb::new();
        let tx_hash_a = make_tx_hash(0xAA);
        let pir_a = setup_spent_with_change(db.conn(), 1, 100_000, 1000, 2000, 70_000, &tx_hash_a);

        let change_b_id: i64 = db.conn()
            .query_row("SELECT id FROM pir_notes WHERE parent_id = ?1", [pir_a], |r| r.get(0))
            .unwrap();
        // Mark B as spent via PIR but don't set spending_tx_hash yet
        // (simulates nullifier detected but change discovery not yet run)
        mark_provisional_pir_result(db.conn(), change_b_id, true).unwrap();

        let entries = get_pir_activity_entries(db.conn()).unwrap();
        // A should still appear; its change_value should be 0 because B is spent
        // (no unspent leaves in the subtree — B is spent and has no children)
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].tx_hash, tx_hash_a);
        assert_eq!(entries[0].gross_value, 100_000);
        assert_eq!(entries[0].change_value, 0);
        assert_eq!(entries[0].net_value(), 100_000);
    }
}
