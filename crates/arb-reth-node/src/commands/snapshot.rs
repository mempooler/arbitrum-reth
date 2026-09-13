//! `arb-reth snapshot import` / `arb-reth snapshot read`.
//!
//! ## `import`: import a Nitro state stream into reth MDBX.
//!
//! Reads a line-oriented state export produced by Nitro's state-dumper and writes
//! the accounts/bytecodes/storage directly into reth's `HashedAccounts`,
//! `HashedStorages`, and `Bytecodes` tables, then drives reth's state-root trie
//! computation to verify parity.
//!
//! ### Stream format
//!
//! ```text
//! A <accountHash:64hex> <nonce:dec> <balance:hex> <codeHash:64hex> <storageRoot:64hex>
//! C <codeHash:64hex> <code:hex>
//! S <slotHash:64hex> <value:hex>
//! ```
//!
//! - `A` lines start a new account; subsequent `S` lines belong to it.
//! - `C` lines appear anywhere and declare bytecode by its keccak hash.
//! - All hashes are 64-hex pre-keccak'ed keys (already the hashed representation).
//! - balance/value may be odd-length hex; parse with `U256::from_str_radix(tok, 16)`.
//!
//! ### Usage
//!
//! ```text
//! arb-reth snapshot import \
//!   --state /tmp/arb1_genesis_state.stream \
//!   --blocks /tmp/arb1_head_block.stream \
//!   --out   /tmp/arbreth-mdbx \
//!   --expect 0x7f2bfc4481d02bfcfc606ebb949384ef78d03a0f30a2dc9cccd652eb80926ae1
//! ```
//!
//! ## `read`: read hashed-state from a converted Arbitrum reth MDBX.
//!
//! Opens a read-only MDBX database (same layout as produced by `snapshot import`)
//! and, given an Ethereum address, prints account information read directly from the
//! hashed tables (`HashedAccounts`, `HashedStorages`, `Bytecodes`).
//!
//! ### Usage
//!
//! ```text
//! arb-reth snapshot read --db /tmp/arbreth-verify --addr 0xf124579b4d0a56cf720d601283f45d6ce4198279
//! arb-reth snapshot read --db /tmp/arbreth-verify --addr 0x0000000000000000000000000000000000000065
//! arb-reth snapshot read --db /tmp/arbreth-verify \
//!     --addr 0xe66092c38c2a56e63009946550407902934376da \
//!     --slot 0x0000000000000000000000000000000000000000000000000000000000000000
//! arb-reth snapshot read --db /tmp/arbreth-verify \
//!     --addr 0xe66092c38c2a56e63009946550407902934376da \
//!     --list-storage
//! ```

use std::{
    collections::HashSet,
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_genesis::{ChainConfig, Genesis};
use alloy_primitives::{Address, B256, Bytes, U256, hex, keccak256};
use clap::Parser;
use reth_chainspec::ChainSpec;
#[cfg(test)]
use reth_chainspec::MAINNET;
use reth_db::{ClientVersion, init_db, mdbx::DatabaseArguments, open_db_read_only};
use reth_db_api::models::StorageSettings;
use reth_db_api::{
    cursor::{DbCursorRW, DbDupCursorRO},
    database::Database as RethDatabase,
    tables,
    transaction::{DbTx, DbTxMut},
};
use reth_node_types::NodeTypesWithDBAdapter;
use reth_primitives_traits::StorageEntry;
use reth_primitives_traits::{Account, Bytecode, SealedHeader};
use reth_provider::{
    DBProvider, MetadataWriter, ProviderFactory, StorageSettingsCache, TrieWriter,
    providers::{RocksDBProvider, StaticFileProvider},
};
use reth_prune_types::{PruneCheckpoint, PruneMode, PruneSegment};
use reth_tasks::Runtime;
use reth_trie::{IntermediateStateRootState, StateRoot as StateRootComputer, StateRootProgress};
use reth_trie_db::{
    DatabaseHashedCursorFactory, DatabaseStateRoot, DatabaseTrieCursorFactory, PackedKeyAdapter,
};

// Boot-wiring: write head header + checkpoints so ProviderFactory opens at the block.
use alloy_consensus::Header;
use alloy_rlp::Decodable;
use arb_reth_sync::resume::RESUME_FILE_NAME;
use arb_revm::ArbSpecId;
use arbitrum_alloy_consensus::header::ArbHeaderInfo;
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, StageCheckpointWriter, StaticFileProviderFactory,
    StaticFileWriter,
};
use reth_stages::stages::slot_preimages::{SlotPreimages, SlotPreimagesReader};
use reth_stages_types::{StageCheckpoint, StageId};
use reth_static_file_types::StaticFileSegment;
use reth_storage_api::{HeaderProvider, PruneCheckpointReader, PruneCheckpointWriter};

use arb_reth_genesis::preimages::{MANIFEST_FILE, SlotPreimageManifest};

use crate::hashed_db::{
    KECCAK_EMPTY as HASHED_KECCAK_EMPTY, account_by_address, code_of, storage_at,
};

// The whole-chain path writes blocks with the same batching and the same per-block checks as the
// binary `import-full` stream, so a datadir built from either is identical.
use super::snapshot_full::{
    BLOCK_BATCH, BlockSectionStats, PendingBlock, SnapshotDb, TX_BATCH, expect_pending,
    flush_blocks, open_factory, rename_changeset_files_to_header, run_stage,
};
use reth_stages::stages::{SenderRecoveryStage, TransactionLookupStage};
use reth_storage_api::BlockBodyIndicesProvider;

// Storage v2 keys trie nodes with `PackedKeyAdapter` (v1 used `LegacyKeyAdapter`). The state root
// is adapter-independent (the MPT hash of key→value), so the genesis root still validates; only the
// on-disk trie-node key encoding changes. The v2 flag must be cached on the factory *before* this
// runs, so `write_trie_updates` (which follows the cached settings) writes packed keys too.
type DbStateRoot<'a, TX> = StateRootComputer<
    DatabaseTrieCursorFactory<&'a TX, PackedKeyAdapter>,
    DatabaseHashedCursorFactory<&'a TX>,
>;

/// Number of storage writes (accounts + slots) to accumulate before committing
/// the MDBX transaction and opening a fresh one.  Bounds dirty-page growth on a
/// 2.6 GB stream.
const COMMIT_THRESHOLD: usize = 100_000;

/// Number of trie-update entries before we flush and restart with the saved
/// intermediate state (mirrors init.rs's STATE_ROOT_COMMIT_THRESHOLD).
const TRIE_COMMIT_THRESHOLD: u64 = 25_000;

/// keccak256 of the empty byte string.
/// If an account's codeHash equals this, bytecode_hash must be None.
const KECCAK_EMPTY: [u8; 32] =
    hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");

use crate::ArbNode;
type ArbNodeTypesWithDB = NodeTypesWithDBAdapter<ArbNode, reth_db::DatabaseEnv>;

/// Number of preimages sorted and inserted in one auxiliary MDBX transaction.
const PREIMAGE_BATCH_SIZE: usize = 250_000;

pub(crate) const SNAPSHOT_IMPORT_MANIFEST_FILE: &str = "snapshot-import.json";
const SNAPSHOT_IMPORT_MANIFEST_VERSION: u64 = 1;

#[derive(Clone, Copy, Debug, serde::Deserialize, serde::Serialize)]
struct SnapshotImportManifest {
    version: u64,
    block_number: u64,
    block_hash: B256,
    state_root: B256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SnapshotPreimagePolicy {
    /// Legacy destructive storage wipes are still possible. The current importer can prove a
    /// complete preimage set only for the canonical Arbitrum One Nitro genesis.
    CanonicalGenesisRequired,
    /// ArbOS 20 enables non-destructive selfdestruct semantics, so a forward sync cannot wipe
    /// storage that was inherited from the imported snapshot.
    NotRequired,
}

impl SnapshotPreimagePolicy {
    const fn requires_preimages(self) -> bool {
        matches!(self, Self::CanonicalGenesisRequired)
    }
}

/// Build Reth's native plaintext storage-slot preimage sidecar from a Nitro Classic export.
#[derive(Debug, Parser)]
#[command(
    name = "arb-snapshot-build-preimages",
    about = "Build the Storage V2 slot-preimage sidecar from a Nitro Classic state export"
)]
pub struct SnapshotBuildPreimagesArgs {
    /// Classic state export directory containing index.json and its referenced JSON files.
    #[arg(long, value_name = "DIR")]
    classic_state: PathBuf,

    /// Target reth datadir. The sidecar is written to `<out>/db/preimage`.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,
}

/// Import a Nitro state stream into reth MDBX and verify the state root.
#[derive(Debug, Parser)]
#[command(
    name = "arb-snapshot-import",
    about = "Import a Nitro state stream into reth MDBX and verify the state root"
)]
pub struct SnapshotImportArgs {
    /// Path to the Nitro state stream file.
    #[arg(long, value_name = "FILE")]
    state: PathBuf,

    /// Output datadir (will be created if absent; `<out>/db`, `<out>/static_files`,
    /// `<out>/rocksdb` sub-directories are created automatically).
    #[arg(long, value_name = "DIR")]
    out: PathBuf,

    /// Expected state root (hex, with or without 0x prefix).
    #[arg(long, value_name = "HEX")]
    expect: String,

    /// Blocks stream (`H <num> <hash> <headerRLP>` records) containing the canonical snapshot
    /// head. Its block number and state root must match the Classic export and `--expect`.
    ///
    /// A stream carrying only the head yields a head-state datadir. A stream covering `[0, P]`
    /// (`reth-export --mode blocks --from 0 --to P`) additionally imports every block's bodies and
    /// receipts, and then requires `--chain-info` and `--genesis`.
    #[arg(long, value_name = "FILE")]
    blocks: PathBuf,

    /// Nitro `chaininfo.json` for the chain the snapshot came from.
    ///
    /// Required when `--blocks` covers more than the head: the datadir then has a real genesis at
    /// block 0, so the chain spec has to be the chain's own rather than the head header standing in
    /// for one.
    #[arg(long = "chain-info", value_name = "PATH", requires = "genesis_json")]
    chain_info: Option<PathBuf>,

    /// Nitro `genesis.json` for the same chain. Required alongside `--chain-info`.
    #[arg(long = "genesis", value_name = "PATH", requires = "chain_info")]
    genesis_json: Option<PathBuf>,
}

/// Append a range of blocks to a whole-chain snapshot datadir.
#[derive(Debug, Parser)]
#[command(
    name = "arb-snapshot-import-blocks",
    about = "Append a range of blocks to a whole-chain snapshot datadir"
)]
pub struct SnapshotImportBlocksArgs {
    /// Blocks stream (`H`/`B`/`R` records) for one contiguous range.
    ///
    /// The first chunk must start at block 0; each later one must start where the datadir left off.
    /// Re-running a chunk the datadir already holds is a no-op, so an interrupted run can simply be
    /// repeated.
    #[arg(long, value_name = "FILE")]
    blocks: PathBuf,

    /// Datadir to create or append to.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,

    /// Nitro `chaininfo.json` for the chain the snapshot came from.
    #[arg(long = "chain-info", value_name = "PATH")]
    chain_info: PathBuf,

    /// Nitro `genesis.json` for the same chain.
    #[arg(long = "genesis", value_name = "PATH")]
    genesis_json: PathBuf,
}

/// Import the state into a datadir whose blocks are already in place, and finish it.
#[derive(Debug, Parser)]
#[command(
    name = "arb-snapshot-import-state",
    about = "Import the state into a block-complete datadir and finish the conversion"
)]
pub struct SnapshotImportStateArgs {
    /// Nitro state stream (`A`/`C`/`S` records) at the datadir's head block.
    #[arg(long, value_name = "FILE")]
    state: PathBuf,

    /// Datadir previously filled by `snapshot import-blocks`.
    #[arg(long, value_name = "DIR")]
    out: PathBuf,

    /// Expected state root (hex, with or without 0x prefix). Must match the head block's.
    #[arg(long, value_name = "HEX")]
    expect: String,

    /// Nitro `chaininfo.json` for the chain the snapshot came from.
    #[arg(long = "chain-info", value_name = "PATH")]
    chain_info: PathBuf,

    /// Nitro `genesis.json` for the same chain.
    #[arg(long = "genesis", value_name = "PATH")]
    genesis_json: PathBuf,
}

/// Read hashed state from a converted Arbitrum reth MDBX snapshot.
#[derive(Debug, Parser)]
#[command(
    name = "arb-snapshot-read",
    about = "Read hashed-state from a converted Arbitrum reth MDBX snapshot"
)]
pub struct SnapshotReadArgs {
    /// Path to the datadir (the directory that contains a `db/` sub-directory).
    #[arg(long, value_name = "DIR")]
    db: PathBuf,

    /// Ethereum address to look up (hex, with or without 0x prefix).
    #[arg(long, value_name = "ADDR")]
    addr: String,

    /// Optional storage slot to query (32-byte hex, with or without 0x prefix).
    #[arg(long, value_name = "SLOT")]
    slot: Option<String>,

    /// Enumerate all non-zero storage slots for this address and print their count.
    #[arg(long)]
    list_storage: bool,
}

/// Add missing history-boundary metadata to an existing snapshot-imported datadir.
#[derive(Debug, Parser)]
#[command(
    name = "repair-history",
    about = "Record the unavailable history prefix in a snapshot-imported datadir"
)]
pub struct SnapshotRepairHistoryArgs {
    /// Snapshot-imported datadir containing `db`, `static_files`, and `rocksdb`.
    #[arg(long, value_name = "DIR")]
    db: PathBuf,

    /// Blocks stream whose highest header is the imported snapshot head.
    #[arg(long, value_name = "FILE")]
    snapshot_head: PathBuf,
}

/// Construct the native `keccak256(slot) -> plain slot` sidecar used by Storage V2.
pub fn build_preimages(args: SnapshotBuildPreimagesArgs) -> eyre::Result<()> {
    let preimage_path = args.out.join("db").join("preimage");
    if preimage_path.exists() {
        eyre::bail!(
            "refusing to replace existing slot-preimage sidecar at {}",
            preimage_path.display()
        );
    }

    let db_path = args.out.join("db");
    std::fs::create_dir_all(&db_path)?;
    if let Some(stale) = find_staging_preimage_dir(&db_path)? {
        eyre::bail!(
            "incomplete slot-preimage build exists at {}; remove it after confirming no build is running",
            stale.display()
        );
    }
    let staging_path = db_path.join(".preimage.tmp");
    std::fs::create_dir(&staging_path)?;

    let build_result = (|| -> eyre::Result<_> {
        let store = SlotPreimages::open(&staging_path)?;
        let mut batch = Vec::with_capacity(PREIMAGE_BATCH_SIZE);
        let mut unique_mappings = 0u64;

        let stats = arb_reth_genesis::preimages::visit_arbitrum_one_slot_preimages(
            &args.classic_state,
            |hashed_slot, plain_slot| {
                batch.push((hashed_slot, plain_slot));
                if batch.len() == PREIMAGE_BATCH_SIZE {
                    unique_mappings += flush_preimage_batch(&store, &mut batch)? as u64;
                    tracing::info!(unique_mappings, "building slot-preimage sidecar");
                }
                Ok(())
            },
        )?;
        unique_mappings += flush_preimage_batch(&store, &mut batch)? as u64;

        let manifest = SlotPreimageManifest::new(stats, unique_mappings)?;
        drop(store);
        write_preimage_manifest(&staging_path, manifest)?;
        sync_directory(&staging_path)?;
        Ok((stats, unique_mappings))
    })();

    let (stats, unique_mappings) = match build_result {
        Ok(result) => result,
        Err(error) => {
            let _ = std::fs::remove_dir_all(&staging_path);
            return Err(error);
        }
    };

    if let Err(error) = std::fs::rename(&staging_path, &preimage_path) {
        let _ = std::fs::remove_dir_all(&staging_path);
        return Err(error.into());
    }
    sync_directory(&db_path)?;

    println!("preimage store       = {}", preimage_path.display());
    println!("next block           = {}", stats.next_block_number);
    println!("classic accounts     = {}", stats.classic_accounts);
    println!("classic storage slots= {}", stats.classic_slots);
    println!("address table entries= {}", stats.address_table_entries);
    println!("retryables           = {}", stats.retryables);
    println!("ArbOS accounts       = {}", stats.arbos_accounts);
    println!("ArbOS storage slots  = {}", stats.arbos_slots);
    println!("source slot mappings = {}", stats.total_slots());
    println!("unique slot mappings = {unique_mappings}");
    Ok(())
}

fn write_preimage_manifest(
    preimage_path: &Path,
    manifest: SlotPreimageManifest,
) -> eyre::Result<()> {
    let manifest_path = preimage_path.join(MANIFEST_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn read_preimage_manifest(preimage_path: &Path) -> eyre::Result<SlotPreimageManifest> {
    let manifest_path = preimage_path.join(MANIFEST_FILE);
    let manifest: SlotPreimageManifest =
        serde_json::from_reader(File::open(&manifest_path).map_err(|error| {
            eyre::eyre!(
                "slot-preimage completion manifest is missing at {}: {error}",
                manifest_path.display()
            )
        })?)?;
    manifest.validate()?;
    Ok(manifest)
}

fn sync_directory(path: &Path) -> eyre::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn find_staging_preimage_dir(db_path: &Path) -> eyre::Result<Option<PathBuf>> {
    for entry in std::fs::read_dir(db_path)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_string_lossy()
            .starts_with(".preimage.tmp")
        {
            return Ok(Some(entry.path()));
        }
    }
    Ok(None)
}

fn flush_preimage_batch(
    store: &SlotPreimages,
    batch: &mut Vec<(B256, B256)>,
) -> eyre::Result<usize> {
    if batch.is_empty() {
        return Ok(0);
    }

    batch.sort_unstable_by_key(|(hashed_slot, _)| *hashed_slot);
    for pair in batch.windows(2) {
        if pair[0].0 == pair[1].0 && pair[0].1 != pair[1].1 {
            eyre::bail!(
                "conflicting slot preimages in batch for {:#x}: first={:#x}, second={:#x}",
                pair[0].0,
                pair[0].1,
                pair[1].1
            );
        }
    }
    batch.dedup_by_key(|(hashed_slot, _)| *hashed_slot);
    let reader = store.reader()?;
    let mut missing = Vec::with_capacity(batch.len());
    for &(hashed_slot, plain_slot) in batch.iter() {
        let actual_hash = keccak256(plain_slot);
        if actual_hash != hashed_slot {
            eyre::bail!(
                "invalid slot-preimage mapping: key={hashed_slot:#x}, plain={plain_slot:#x}, hash={actual_hash:#x}"
            );
        }
        match reader.get(&hashed_slot)? {
            Some(existing) if existing == plain_slot => {}
            Some(existing) => {
                eyre::bail!(
                    "conflicting slot preimage for {hashed_slot:#x}: existing={existing:#x}, new={plain_slot:#x}"
                );
            }
            None => missing.push((hashed_slot, plain_slot)),
        }
    }
    drop(reader);
    store.insert_preimages(&missing)?;
    let inserted = missing.len();
    batch.clear();
    Ok(inserted)
}

pub fn import(args: SnapshotImportArgs) -> eyre::Result<()> {
    let expected = parse_b256(&args.expect)
        .map_err(|error| eyre::eyre!("invalid --expect state root: {error}"))?;

    ensure_fresh_import_target(&args.out)?;

    // Whole-chain mode is selected by supplying the chain's own spec. clap keeps the two flags
    // together, so either both are present or neither is.
    if let (Some(chain_info), Some(genesis_json)) = (&args.chain_info, &args.genesis_json) {
        return import_whole_chain(&args, expected, chain_info, genesis_json);
    }
    import_head_only(&args, expected)
}

/// The original import: one head block wired in as though it were genesis, plus its state.
///
/// The datadir this produces has no block bodies, no receipts and no history; the node syncs
/// forward from the head. `--blocks` must carry exactly that one block.
fn import_head_only(args: &SnapshotImportArgs, expected: B256) -> eyre::Result<()> {
    let db_path = args.out.join("db");
    let static_files_path = args.out.join("static_files");
    let rocksdb_path = args.out.join("rocksdb");
    let preimage_path = db_path.join("preimage");

    let (head, blocks) = scan_head_header(&args.blocks)?;
    if blocks > 1 {
        eyre::bail!(
            "--blocks carries {blocks} blocks, but no chain spec was supplied. Importing a whole \
             chain needs --chain-info and --genesis, because the datadir then has a real genesis \
             at block 0 rather than the head standing in for one."
        );
    }
    let preimage_policy = validate_snapshot_identity(expected, &head)?;
    let preimage_manifest = if preimage_policy.requires_preimages() {
        if !preimage_path.join("mdbx.dat").is_file() {
            eyre::bail!(
                "slot-preimage sidecar is missing at {}; run `arb-reth snapshot build-preimages` first",
                preimage_path.display()
            );
        }
        Some(read_preimage_manifest(&preimage_path)?)
    } else {
        None
    };
    let preimages = preimage_policy
        .requires_preimages()
        .then(|| SlotPreimages::open(&preimage_path))
        .transpose()?;
    let preimage_reader = preimages.as_ref().map(SlotPreimages::reader).transpose()?;

    tracing::info!(path = ?args.state, "validating state stream before database creation");
    let state_stats = preflight_state_stream(&args.state, preimage_reader.as_ref())?;
    tracing::info!(
        accounts = state_stats.accounts,
        slots = state_stats.slots,
        bytecodes = state_stats.bytecodes,
        unique_slot_preimages = preimage_manifest.map(|manifest| manifest.unique_mappings),
        "state stream preflight complete"
    );

    std::fs::create_dir_all(&static_files_path)?;
    std::fs::create_dir_all(&rocksdb_path)?;

    tracing::info!(path = ?db_path, "opening MDBX");
    let db = init_db(&db_path, DatabaseArguments::new(ClientVersion::default()))?;

    // Inject the snapshot's real head header so genesis_hash() matches the DB and reth's launch
    // genesis-check passes.
    let chain_spec: Arc<ChainSpec> =
        arb_chain_spec_with_header(ARB_ONE_CHAIN_ID, head.2.clone(), head.1);

    let static_file_provider = StaticFileProvider::read_write(static_files_path.clone())?;
    let rocksdb_provider = RocksDBProvider::builder(&rocksdb_path)
        .with_default_tables()
        .build()
        .map_err(|e| eyre::eyre!("RocksDB open error: {e}"))?;
    let runtime = Runtime::test();

    let factory: ProviderFactory<ArbNodeTypesWithDB> = ProviderFactory::new(
        db,
        chain_spec,
        static_file_provider,
        rocksdb_provider,
        runtime,
    )
    .map_err(|e| eyre::eyre!("ProviderFactory::new: {e}"))?;

    // Emit a storage-v2 database (reth's default going forward; also the more natural fit for our
    // hashed-only import, since v2 treats the hashed-state tables as canonical). Cache the flag so
    // every provider (and `write_trie_updates`' `with_adapter!`) uses `PackedKeyAdapter`, and
    // persist it to metadata so the node reads v2 on boot (an unset flag defaults to v1).
    factory.set_storage_settings_cache(StorageSettings::v2());
    {
        let provider_rw = factory.database_provider_rw()?;
        provider_rw.write_storage_settings(StorageSettings::v2())?;
        provider_rw
            .commit()
            .map_err(|e| eyre::eyre!("persist storage settings: {e}"))?;
    }

    tracing::info!(path = ?args.state, "streaming state import (storage v2)");
    stream_import(&factory, &args.state, preimage_reader.as_ref())?;

    tracing::info!("computing state root (may take several minutes for large states)");
    let computed = compute_state_root_chunked(&factory)?;

    println!("computed  = {computed:#x}");
    println!("expected  = {expected:#x}");
    if computed != expected {
        eyre::bail!("state root mismatch: computed={computed:#x}, expected={expected:#x}");
    }
    println!("MATCH");

    tracing::info!(path = ?args.blocks, "writing head header + checkpoints");
    let (head_num, head_hash) = write_head_blocks(&factory, &args.blocks)?;
    verify_head(&factory, head_num, head_hash)?;
    // The injected-header chain spec means reth's launch genesis-check accepts this DB.
    verify_launch(&factory, head_hash)?;

    // The changeset segments were created in their fixed 500k slot (`_22000000_…`) but
    // `set_expected_block_start(head)` moved their header's expected range to start at `head`.
    // reth derives the on-disk filename from the header's expected range (via the index), so the
    // file must be renamed to match or every changeset read fails with a missing-file error. Do it
    // now, at the filesystem level, after all DB work: the factory is about to be dropped and the
    // node re-scans on boot.
    drop(factory);
    rename_changeset_files_to_header(&static_files_path)?;
    for path in [&db_path, &static_files_path, &rocksdb_path] {
        sync_directory(path)?;
    }
    write_snapshot_import_manifest(&args.out, &head)?;

    Ok(())
}

/// Import a whole chain: every block's header, body and receipts from 0 to `P`, plus the state at
/// `P`.
///
/// The datadir this produces answers historical *block* queries across the whole range. It carries
/// no changesets, so historical *state* below `P` is unavailable and is marked as such; that is the
/// part a hash-scheme Nitro snapshot cannot supply, because it records no per-block state diffs.
///
/// Blocks are written before state, which is both the order the static files want and the order
/// that lets the head header come back out of the database rather than being carried around.
/// Build the chain's own spec, which is what a datadir with a real genesis at block 0 needs.
fn chain_spec_from_files(
    chain_info_path: &Path,
    genesis_path: &Path,
) -> eyre::Result<Arc<ChainSpec>> {
    let chain_info = std::fs::read(chain_info_path)
        .map_err(|error| eyre::eyre!("read {}: {error}", chain_info_path.display()))?;
    let genesis = std::fs::read(genesis_path)
        .map_err(|error| eyre::eyre!("read {}: {error}", genesis_path.display()))?;
    let (chain_spec, _init, _info) = crate::orbit_chain_from_files(&chain_info, &genesis)?;
    Ok(Arc::new(chain_spec))
}

/// Allow appending to a conversion in progress, but never to a finished one.
///
/// The strict [`ensure_fresh_import_target`] is right for the first chunk and wrong for every one
/// after it, whose whole purpose is to land in a datadir that already has blocks.
fn ensure_appendable_import_target(out: &Path) -> eyre::Result<()> {
    let manifest = out.join(SNAPSHOT_IMPORT_MANIFEST_FILE);
    if manifest.exists() {
        eyre::bail!(
            "{} is already a finished import; its completion manifest is at {}",
            out.display(),
            manifest.display()
        );
    }
    Ok(())
}

/// The gate for a datadir that may or may not already hold blocks.
fn ensure_import_target(out: &Path) -> eyre::Result<bool> {
    let resuming = out.join("static_files").exists();
    if resuming {
        ensure_appendable_import_target(out)?;
    } else {
        ensure_fresh_import_target(out)?;
    }
    Ok(resuming)
}

/// Append one chunk of blocks to a whole-chain datadir, creating it if it does not exist.
///
/// Split from the state import so a chain too large to stage on disk in one piece can be converted
/// a range at a time: export a chunk, import it, delete it, repeat. Each chunk is committed as it
/// goes, so an interrupted run resumes from the highest block already present rather than starting
/// over.
pub fn import_blocks(args: SnapshotImportBlocksArgs) -> eyre::Result<()> {
    // Cheap checks before anything is opened or created.
    check_stream_is_complete(&args.blocks)?;
    let first_block = first_block_number(&args.blocks)?;
    let resuming = ensure_import_target(&args.out)?;
    if !resuming && first_block != 0 {
        eyre::bail!(
            "--blocks starts at block {first_block}, but this datadir is empty and the first chunk \
             has to start at block 0. A stream holding only the head is what `reth-export --mode \
             blocks` writes by default; re-export with `--from 0`."
        );
    }

    let chain_spec = chain_spec_from_files(&args.chain_info, &args.genesis_json)?;
    let db_path = args.out.join("db");
    let static_files_path = args.out.join("static_files");
    let rocksdb_path = args.out.join("rocksdb");
    std::fs::create_dir_all(&static_files_path)?;
    std::fs::create_dir_all(&rocksdb_path)?;
    let factory = open_factory(&db_path, &static_files_path, &rocksdb_path, chain_spec)?;

    let stats = append_blocks(&factory, &args.blocks)?;
    drop(factory);
    for path in [&db_path, &static_files_path, &rocksdb_path] {
        sync_directory(path)?;
    }

    if stats.blocks > 0 {
        println!(
            "imported blocks {}..={} ({} transactions, {} receipts)",
            stats.first_block, stats.last_block, stats.transactions, stats.receipts
        );
    } else {
        println!("nothing to do; the datadir already holds these blocks");
    }
    Ok(())
}

/// Write one chunk into an open datadir, resuming from what it already holds.
fn append_blocks<DB: SnapshotDb>(
    factory: &ProviderFactory<NodeTypesWithDBAdapter<ArbNode, DB>>,
    blocks: &Path,
) -> eyre::Result<BlockSectionStats> {
    let resume = read_block_resume(factory)?;
    if !resume.fresh {
        tracing::info!(
            next_block = resume.next_block,
            next_tx_num = resume.next_tx_num,
            "appending to an existing datadir"
        );
    }
    tracing::info!(path = ?blocks, "importing blocks");
    let stats = write_chain_blocks(factory, blocks, resume)?;
    if stats.blocks > 0 {
        tracing::info!(
            blocks = stats.blocks,
            transactions = stats.transactions,
            receipts = stats.receipts,
            range = format!("{}..={}", stats.first_block, stats.last_block),
            "blocks imported"
        );
    }
    Ok(stats)
}

/// Import the state into a datadir whose blocks are already in place, then finish it.
///
/// This is the step that makes the datadir bootable: without its completion manifest the node
/// refuses to open one, so a conversion interrupted between chunks cannot be mistaken for a
/// finished database.
pub fn import_state(args: SnapshotImportStateArgs) -> eyre::Result<()> {
    let expected = parse_b256(&args.expect)
        .map_err(|error| eyre::eyre!("invalid --expect state root: {error}"))?;
    ensure_appendable_import_target(&args.out)?;

    let static_files_path = args.out.join("static_files");
    if !static_files_path.exists() {
        eyre::bail!(
            "{} holds no blocks yet; run `arb-reth snapshot import-blocks` first",
            args.out.display()
        );
    }

    // Before the state is written, and cheap relative to it.
    tracing::info!(path = ?args.state, "validating state stream");
    let state_stats = preflight_state_stream(&args.state, None)?;
    tracing::info!(
        accounts = state_stats.accounts,
        slots = state_stats.slots,
        bytecodes = state_stats.bytecodes,
        "state stream preflight complete"
    );

    let chain_spec = chain_spec_from_files(&args.chain_info, &args.genesis_json)?;
    let db_path = args.out.join("db");
    let rocksdb_path = args.out.join("rocksdb");
    let factory = open_factory(&db_path, &static_files_path, &rocksdb_path, chain_spec)?;

    finish_whole_chain(
        &factory,
        &args.out,
        &args.state,
        expected,
        &db_path,
        &static_files_path,
        &rocksdb_path,
    )
}

/// The state import and everything that turns a datadir full of blocks into a bootable one.
fn finish_whole_chain(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    out: &Path,
    state: &Path,
    expected: B256,
    db_path: &Path,
    static_files_path: &Path,
    rocksdb_path: &Path,
) -> eyre::Result<()> {
    // Read the head and genesis out of the datadir rather than being told them, which also proves
    // the blocks landed. The genesis hash is what reth's launch check compares against once the
    // chain spec is the chain's own.
    let (head, genesis_hash) = {
        let provider = factory.provider()?;
        let highest = provider
            .static_file_provider()
            .get_highest_static_file_block(StaticFileSegment::Headers)
            .ok_or_else(|| {
                eyre::eyre!(
                    "{} holds no blocks yet; run `arb-reth snapshot import-blocks` first",
                    out.display()
                )
            })?;
        let head = HeaderProvider::sealed_header(&provider, highest)?
            .ok_or_else(|| eyre::eyre!("block {highest} has no header"))?;
        let genesis = HeaderProvider::sealed_header(&provider, 0)?.ok_or_else(|| {
            eyre::eyre!("block 0 has no header; the chain's first chunk is missing")
        })?;
        (
            (head.number, head.hash(), head.header().clone()),
            genesis.hash(),
        )
    };
    let (head_num, head_hash) = (head.0, head.1);
    tracing::info!(head_num, %head_hash, "finishing a whole-chain datadir");

    // The head's own state root is what the state stream has to reproduce, so a blocks import that
    // stopped short of `P` is caught here rather than after the trie is built.
    let preimage_policy = validate_snapshot_identity(expected, &head)?;
    if preimage_policy.requires_preimages() {
        eyre::bail!(
            "block {head_num} predates ArbOS 20, which a whole-chain import does not support: its \
             storage wipes need a plaintext slot-preimage set for this exact snapshot"
        );
    }

    tracing::info!(path = ?state, "streaming state import (storage v2)");
    stream_import(factory, &state.to_path_buf(), None)?;

    tracing::info!("computing state root (may take several minutes for large states)");
    let computed = compute_state_root_chunked(factory)?;
    println!("computed  = {computed:#x}");
    println!("expected  = {expected:#x}");
    if computed != expected {
        eyre::bail!("state root mismatch: computed={computed:#x}, expected={expected:#x}");
    }
    println!("MATCH");

    // The transaction-derived indices are built by running reth's own stages over the bodies that
    // were imported, so they hold exactly what a forward sync would have produced.
    run_stage(
        factory,
        SenderRecoveryStage::default(),
        head_num,
        "sender recovery",
    )?;
    run_stage(
        factory,
        TransactionLookupStage::default(),
        head_num,
        "transaction lookup",
    )?;

    // No changesets anywhere, so the segments need the empty-at-head treatment, and every block up
    // to and including the head has to be marked as having no historical state.
    init_empty_changeset_segments(factory, head_num)?;
    {
        let provider_rw = factory.database_provider_rw()?;
        let checkpoint = StageCheckpoint::new(head_num);
        for stage in StageId::ALL {
            provider_rw.save_stage_checkpoint(stage, checkpoint)?;
        }
        write_snapshot_history_boundaries(&provider_rw, head_num)?;
        provider_rw
            .commit()
            .map_err(|e| eyre::eyre!("commit checkpoints: {e}"))?;
    }

    verify_head(factory, head_num, head_hash)?;
    // A real chain spec means reth's launch check compares against the true genesis, not the head.
    verify_launch(factory, genesis_hash)?;

    rename_changeset_files_to_header(static_files_path)?;
    for path in [db_path, static_files_path, rocksdb_path] {
        sync_directory(path)?;
    }
    write_snapshot_import_manifest(out, &head)?;
    Ok(())
}

/// The one-shot whole-chain import: every block and the state in a single run.
///
/// Equivalent to `import-blocks` over the whole range followed by `import-state`, and worth using
/// when the blocks stream fits on disk in one piece. When it does not, run the two separately and
/// feed the first one chunk at a time.
fn import_whole_chain(
    args: &SnapshotImportArgs,
    expected: B256,
    chain_info_path: &Path,
    genesis_path: &Path,
) -> eyre::Result<()> {
    check_stream_is_complete(&args.blocks)?;
    let first_block = first_block_number(&args.blocks)?;
    if first_block != 0 {
        eyre::bail!(
            "--blocks starts at block {first_block}, but a whole-chain import needs it to start at \
             block 0. A stream holding only the head is what `reth-export --mode blocks` writes by \
             default; re-export the whole range with `--from 0 --to {first_block}`."
        );
    }

    let chain_spec = chain_spec_from_files(chain_info_path, genesis_path)?;
    tracing::info!(
        chain = chain_spec.chain.id(),
        genesis = %chain_spec.genesis_hash(),
        "building a whole-chain datadir"
    );

    // Before the database exists, and before the blocks import that can run for hours: a state
    // stream that cannot be imported should cost minutes to find out about, not a whole run. It
    // needs no preimages here, because a whole-chain import is ArbOS 20 or newer by construction
    // (checked against the head below, once the blocks have named it).
    tracing::info!(path = ?args.state, "validating state stream before database creation");
    let state_stats = preflight_state_stream(&args.state, None)?;
    tracing::info!(
        accounts = state_stats.accounts,
        slots = state_stats.slots,
        bytecodes = state_stats.bytecodes,
        "state stream preflight complete"
    );

    let db_path = args.out.join("db");
    let static_files_path = args.out.join("static_files");
    let rocksdb_path = args.out.join("rocksdb");
    std::fs::create_dir_all(&static_files_path)?;
    std::fs::create_dir_all(&rocksdb_path)?;

    tracing::info!(path = ?db_path, "opening MDBX");
    let factory = open_factory(&db_path, &static_files_path, &rocksdb_path, chain_spec)?;

    append_blocks(&factory, &args.blocks)?;
    finish_whole_chain(
        &factory,
        &args.out,
        &args.state,
        expected,
        &db_path,
        &static_files_path,
        &rocksdb_path,
    )
}

fn validate_snapshot_identity(
    expected: B256,
    head: &(u64, B256, Header),
) -> eyre::Result<SnapshotPreimagePolicy> {
    if head.2.number != head.0 || head.2.hash_slow() != head.1 {
        eyre::bail!("snapshot head contains an invalid number or block hash");
    }
    if head.2.state_root != expected {
        eyre::bail!(
            "snapshot head state root {:#x} does not match --expect {expected:#x}",
            head.2.state_root
        );
    }

    let info = ArbHeaderInfo::decode_header(&head.2)
        .map_err(|error| eyre::eyre!("decode snapshot head ArbOS version: {error}"))?;
    let spec = ArbSpecId::from_arbos_version(info.arbos_format_version);
    if spec.is_enabled_in(ArbSpecId::ARBOS_20) {
        return Ok(SnapshotPreimagePolicy::NotRequired);
    }

    if head.0 != arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_NUMBER
        || head.1 != arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_HASH
        || expected != arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT
    {
        eyre::bail!(
            "pre-ArbOS 20 snapshot at block {} requires a complete slot-preimage set for that exact snapshot; currently only the canonical Arbitrum One Nitro genesis is supported",
            head.0
        );
    }
    Ok(SnapshotPreimagePolicy::CanonicalGenesisRequired)
}

pub(crate) fn write_snapshot_import_manifest(
    out: &Path,
    head: &(u64, B256, Header),
) -> eyre::Result<()> {
    let manifest = SnapshotImportManifest {
        version: SNAPSHOT_IMPORT_MANIFEST_VERSION,
        block_number: head.0,
        block_hash: head.1,
        state_root: head.2.state_root,
    };
    validate_snapshot_import_manifest(manifest, head)?;

    let path = out.join(SNAPSHOT_IMPORT_MANIFEST_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    serde_json::to_writer_pretty(&mut file, &manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    sync_directory(out)?;
    Ok(())
}

fn validate_snapshot_import_manifest(
    manifest: SnapshotImportManifest,
    head: &(u64, B256, Header),
) -> eyre::Result<()> {
    if manifest.version != SNAPSHOT_IMPORT_MANIFEST_VERSION {
        eyre::bail!(
            "unsupported snapshot import manifest version {}, expected {SNAPSHOT_IMPORT_MANIFEST_VERSION}",
            manifest.version,
        );
    }
    if manifest.block_number != head.0
        || manifest.block_hash != head.1
        || manifest.state_root != head.2.state_root
    {
        eyre::bail!("snapshot import manifest does not match the supplied head stream");
    }
    if head.2.number != head.0 || head.2.hash_slow() != head.1 {
        eyre::bail!("snapshot head stream contains an invalid number or block hash");
    }
    Ok(())
}

/// Refuse to launch a new-format snapshot datadir unless its import completed successfully.
pub(crate) fn validate_snapshot_import_for_launch(
    out: &Path,
    head: &(u64, B256, Header),
) -> eyre::Result<()> {
    let preimage_path = out.join("db/preimage");
    let import_manifest_path = out.join(SNAPSHOT_IMPORT_MANIFEST_FILE);
    if !import_manifest_path.is_file() && !preimage_path.join(MANIFEST_FILE).is_file() {
        // Older imports predate completion manifests. Preserve their existing launch behavior.
        return Ok(());
    }

    let manifest: SnapshotImportManifest =
        serde_json::from_reader(File::open(&import_manifest_path).map_err(|error| {
            eyre::eyre!(
                "snapshot import is incomplete: missing completion manifest at {}: {error}",
                import_manifest_path.display()
            )
        })?)?;
    validate_snapshot_import_manifest(manifest, head)?;

    let preimage_policy = validate_snapshot_identity(head.2.state_root, head)?;
    if preimage_policy.requires_preimages() {
        if !preimage_path.join("mdbx.dat").is_file() {
            eyre::bail!(
                "snapshot slot-preimage database is missing at {}",
                preimage_path.display()
            );
        }
        read_preimage_manifest(&preimage_path)?;
    }
    Ok(())
}

pub(crate) fn ensure_fresh_import_target(out: &Path) -> eyre::Result<()> {
    let resume_path = out.join(RESUME_FILE_NAME);
    for path in [resume_path.clone(), resume_path.with_extension("json.tmp")] {
        if path.exists() {
            eyre::bail!(
                "snapshot import requires a fresh target; stale L1 resume metadata exists at {}",
                path.display()
            );
        }
    }

    let import_manifest = out.join(SNAPSHOT_IMPORT_MANIFEST_FILE);
    if import_manifest.exists() {
        eyre::bail!(
            "snapshot import requires a fresh target; completion manifest already exists at {}",
            import_manifest.display()
        );
    }
    let db_path = out.join("db");
    if db_path.exists() {
        for entry in std::fs::read_dir(&db_path)? {
            let entry = entry?;
            if entry.file_name() != "preimage" {
                eyre::bail!(
                    "snapshot import requires a fresh target; unexpected path exists at {}",
                    entry.path().display()
                );
            }
        }
    }

    for path in [out.join("static_files"), out.join("rocksdb")] {
        if path.exists() {
            eyre::bail!(
                "snapshot import requires a fresh target; remove the previous import at {}",
                path.display()
            );
        }
    }
    Ok(())
}

/// Repair an older import that predates snapshot history-boundary checkpoints.
///
/// This only writes two prune-checkpoint rows. It does not modify state, blocks, trie data, or the
/// snapshot header, and is idempotent for the same snapshot head.
pub fn repair_history(args: SnapshotRepairHistoryArgs) -> eyre::Result<()> {
    let (head_num, head_hash, header) = read_head_header(&args.snapshot_head)?;
    let db = init_db(
        args.db.join("db"),
        DatabaseArguments::new(ClientVersion::default()),
    )?;
    let static_files = StaticFileProvider::read_write(args.db.join("static_files"))?;
    let rocksdb = RocksDBProvider::builder(args.db.join("rocksdb"))
        .with_default_tables()
        .build()
        .map_err(|error| eyre::eyre!("RocksDB open error: {error}"))?;
    let factory: ProviderFactory<ArbNodeTypesWithDB> = ProviderFactory::new(
        db,
        arb_chain_spec_with_header(ARB_ONE_CHAIN_ID, header, head_hash),
        static_files,
        rocksdb,
        Runtime::test(),
    )?;
    factory.set_storage_settings_cache(StorageSettings::v2());

    {
        let provider = factory.provider()?;
        let best = provider.best_block_number()?;
        if best < head_num {
            return Err(eyre::eyre!(
                "database head {best} is below snapshot head {head_num}"
            ));
        }
        let actual_hash = provider
            .sealed_header(head_num)?
            .ok_or_else(|| eyre::eyre!("snapshot header {head_num} is missing from the database"))?
            .hash();
        if actual_hash != head_hash {
            return Err(eyre::eyre!(
                "snapshot header hash mismatch at {head_num}: database={actual_hash:#x}, stream={head_hash:#x}"
            ));
        }

        for segment in [PruneSegment::AccountHistory, PruneSegment::StorageHistory] {
            if let Some(existing) = provider.get_prune_checkpoint(segment)?
                && existing.block_number.is_some_and(|block| block > head_num)
            {
                return Err(eyre::eyre!(
                    "refusing to move {segment} checkpoint backward from {:?} to {head_num}",
                    existing.block_number
                ));
            }
        }
    }

    let provider = factory.database_provider_rw()?;
    write_snapshot_history_boundaries(&provider, head_num)?;
    provider.commit()?;

    println!("snapshot history boundary = {head_num}");
    println!("account history checkpoint: OK");
    println!("storage history checkpoint: OK");
    Ok(())
}

/// Arbitrum One chain id.
const ARB_ONE_CHAIN_ID: u64 = 42161;

/// Build a `ChainSpec` whose genesis header IS the snapshot's head header (number/hash/stateRoot),
/// so `chain_spec.genesis_hash()` equals the DB's genesis block hash and reth's launch
/// genesis-validation passes. We can't use the alloc-based `from_genesis` path (we have hashed
/// state, no alloc), so we override the public `genesis_header` field directly.
fn arb_chain_spec_with_header(chain_id: u64, header: Header, hash: B256) -> Arc<ChainSpec> {
    // London-format, all pre-London forks at 0 (post-London EVM features are ArbOS-version-gated
    // via the header mixHash, not chain-spec forks). Mirrors `genesis::arb_chain_spec`.
    let config = ChainConfig {
        chain_id,
        homestead_block: Some(0),
        dao_fork_support: false,
        eip150_block: Some(0),
        eip155_block: Some(0),
        eip158_block: Some(0),
        byzantium_block: Some(0),
        constantinople_block: Some(0),
        petersburg_block: Some(0),
        istanbul_block: Some(0),
        muir_glacier_block: Some(0),
        berlin_block: Some(0),
        london_block: Some(0),
        ..Default::default()
    };
    let genesis = Genesis {
        config,
        number: Some(header.number),
        ..Default::default()
    };
    let mut spec = ChainSpec::from_genesis(genesis);
    // Override the computed (alloc-derived, wrong) genesis header with the real one.
    spec.genesis_header = SealedHeader::new(header, hash);
    Arc::new(spec)
}

/// Reject a blocks stream whose last line was never finished.
///
/// An exporter killed mid-write, or one that filled the disk, leaves a final record cut in half.
/// Parsing would find it only after importing everything before it, which on a whole chain is
/// hours; the last byte of the file answers the same question immediately. A stream cut at a record
/// boundary still ends in a newline and is not caught here, but that one leaves the head below `P`,
/// which the state-root check rejects.
fn check_stream_is_complete(path: &Path) -> eyre::Result<()> {
    use std::io::{Seek, SeekFrom};

    let mut file = File::open(path)?;
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        eyre::bail!("{path:?} is empty");
    }
    file.seek(SeekFrom::End(-1))?;
    let mut last = [0u8; 1];
    std::io::Read::read_exact(&mut file, &mut last)?;
    if last[0] != b'\n' {
        eyre::bail!(
            "{path:?} ends mid-record, so the export that wrote it did not finish. The usual cause \
             is the destination filling up: `reth-export` used to latch the write error and exit 0, \
             leaving a stream truncated at the last flush. Check free space, re-export, and confirm \
             the file ends with a newline before importing."
        );
    }
    Ok(())
}

/// The number of the first block in a blocks stream, read from its first `H` record alone.
///
/// Cheap on purpose: a whole-chain import is rejected for starting above genesis, and finding that
/// out should cost one line rather than a state-stream preflight and a created database.
fn first_block_number(path: &Path) -> eyre::Result<u64> {
    let reader = std::io::BufReader::new(File::open(path)?);
    for (line_index, line) in reader.lines().enumerate() {
        match parse_block_record(&line?, line_index + 1)? {
            Some(BlockRecord::Header { number, .. }) => return Ok(number),
            Some(_) => eyre::bail!("{path:?}: a body or receipt record precedes the first header"),
            None => continue,
        }
    }
    eyre::bail!("no H records in {path:?}")
}

/// Read the highest-numbered `H <num> <hash> <headerRLP>` record (the head/genesis header), and
/// count the blocks the stream carries so a caller can tell a head-only stream from a whole chain.
fn scan_head_header(path: &Path) -> eyre::Result<((u64, B256, Header), u64)> {
    let reader = std::io::BufReader::new(File::open(path)?);
    let mut best: Option<(u64, B256, Header)> = None;
    let mut blocks = 0u64;
    for (line_index, line) in reader.lines().enumerate() {
        let Some((num, hash, header)) = parse_header_record(&line?, line_index + 1)? else {
            continue;
        };
        blocks += 1;
        if best.as_ref().map(|(n, ..)| num >= *n).unwrap_or(true) {
            best = Some((num, hash, header));
        }
    }
    let head = best.ok_or_else(|| eyre::eyre!("no H records in {path:?}"))?;
    Ok((head, blocks))
}

/// Read the highest-numbered `H <num> <hash> <headerRLP>` record (the head/genesis header).
fn read_head_header(path: &Path) -> eyre::Result<(u64, B256, Header)> {
    Ok(scan_head_header(path)?.0)
}

/// One record of a blocks stream, still encoded.
///
/// Splitting the tokenising from the decoding lets the head-only path decode just the header it
/// needs while the whole-chain path hands the same bytes to [`PendingBlock`].
enum BlockRecord {
    Header {
        number: u64,
        hash: B256,
        rlp: Vec<u8>,
    },
    Body {
        number: u64,
        rlp: Vec<u8>,
    },
    Receipts {
        number: u64,
        rlp: Vec<u8>,
    },
}

/// Tokenise one `H`/`B`/`R` line. Blank lines yield `None`; an unknown tag is an error.
fn parse_block_record(line: &str, line_number: usize) -> eyre::Result<Option<BlockRecord>> {
    let mut parts = line.split_whitespace();
    let Some(tag) = parts.next() else {
        return Ok(None);
    };
    if matches!(tag, "B" | "R") {
        let num: u64 = parts
            .next()
            .ok_or_else(|| eyre::eyre!("{tag}: missing number at line {line_number}"))?
            .parse()
            .map_err(|error| eyre::eyre!("{tag}: bad number at line {line_number}: {error}"))?;
        let encoded = hex::decode(
            parts
                .next()
                .ok_or_else(|| eyre::eyre!("{tag}: missing RLP at line {line_number}"))?,
        )?;
        if parts.next().is_some() {
            eyre::bail!("{tag}: unexpected trailing fields at line {line_number}");
        }

        let mut input = encoded.as_slice();
        let rlp_header = alloy_rlp::Header::decode(&mut input).map_err(|error| {
            eyre::eyre!("decode {tag} record for block {num} at line {line_number}: {error}")
        })?;
        if !rlp_header.list || input.len() != rlp_header.payload_length {
            eyre::bail!("invalid {tag} RLP for block {num} at line {line_number}");
        }
        return Ok(Some(if tag == "B" {
            BlockRecord::Body {
                number: num,
                rlp: encoded,
            }
        } else {
            BlockRecord::Receipts {
                number: num,
                rlp: encoded,
            }
        }));
    }
    if tag != "H" {
        eyre::bail!("unknown block record {tag:?} at line {line_number}");
    }
    let num: u64 = parts
        .next()
        .ok_or_else(|| eyre::eyre!("H: missing number at line {line_number}"))?
        .parse()
        .map_err(|error| eyre::eyre!("H: bad number at line {line_number}: {error}"))?;
    let hash = parse_b256(
        parts
            .next()
            .ok_or_else(|| eyre::eyre!("H: missing hash at line {line_number}"))?,
    )?;
    let rlp = hex::decode(
        parts
            .next()
            .ok_or_else(|| eyre::eyre!("H: missing headerRLP at line {line_number}"))?,
    )?;
    if parts.next().is_some() {
        eyre::bail!("H: unexpected trailing fields at line {line_number}");
    }
    Ok(Some(BlockRecord::Header {
        number: num,
        hash,
        rlp,
    }))
}

/// Check a decoded header authenticates the record that carried it (ADR-004 B1).
fn check_header_identity(num: u64, hash: B256, header: &Header, at: &str) -> eyre::Result<()> {
    if header.number != num {
        eyre::bail!(
            "header number mismatch: record={num}, decoded={}",
            header.number
        );
    }
    let computed_hash = header.hash_slow();
    if computed_hash != hash {
        eyre::bail!(
            "header hash mismatch at {num} ({at}): record={hash:#x}, decoded={computed_hash:#x}"
        );
    }
    Ok(())
}

fn parse_header_record(
    line: &str,
    line_number: usize,
) -> eyre::Result<Option<(u64, B256, Header)>> {
    let Some(BlockRecord::Header { number, hash, rlp }) = parse_block_record(line, line_number)?
    else {
        return Ok(None);
    };
    let mut input = rlp.as_slice();
    let header = Header::decode(&mut input)
        .map_err(|error| eyre::eyre!("decode header {number} at line {line_number}: {error}"))?;
    if !input.is_empty() {
        eyre::bail!("trailing bytes after header RLP at line {line_number}");
    }
    check_header_identity(number, hash, &header, &format!("line {line_number}"))?;
    Ok(Some((number, hash, header)))
}

/// Launch-acceptance gate: runs `init_genesis` with validation against the converted DB.
/// With the injected-header chain spec it must find the genesis present (no GenesisHashMismatch,
/// no re-write), confirming a node would open this DB cleanly.
fn verify_launch(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    head_hash: B256,
) -> eyre::Result<()> {
    use reth_db_common::init::init_genesis_with_settings_and_validate;
    let got = init_genesis_with_settings_and_validate(factory, StorageSettings::v2(), true)
        .map_err(|e| eyre::eyre!("init_genesis (launch genesis check) rejected the DB: {e}"))?;
    println!("init_genesis (validate=true) = {got:#x}");
    if got == head_hash {
        println!("LAUNCH OK");
        Ok(())
    } else {
        Err(eyre::eyre!(
            "init_genesis returned {got:#x}, expected {head_hash:#x}"
        ))
    }
}

/// Read-ahead over a whole-chain blocks stream, whose receipt lines are long.
const BLOCK_STREAM_BUFFER: usize = 16 * 1024 * 1024;

/// Import a blocks stream covering `[0, P]`: headers, bodies and receipts for every block.
///
/// Unlike [`write_head_blocks`], which wires a single head block in as though it were genesis, this
/// builds a datadir with real block history. Each block is checked against its own header before it
/// is written, and the writing itself is [`flush_blocks`], the same batching the binary
/// `import-full` path uses, so both streams produce a byte-identical datadir from the same blocks.
///
/// Returns what was written; the caller reads the head header back out of the database.
/// Where an append picks up: what the datadir already holds, read back out of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockResume {
    /// The block the next chunk must start at. Zero for an untouched datadir.
    next_block: u64,
    /// The transaction number the next block's first transaction takes. Static-file receipts and
    /// recovered senders are keyed by it, so continuing from the wrong value misfiles every one.
    next_tx_num: u64,
    /// Whether the headers segment still needs its block range seeded, which is true only for a
    /// datadir with no headers at all.
    fresh: bool,
}

impl BlockResume {
    const fn beginning() -> Self {
        Self {
            next_block: 0,
            next_tx_num: 0,
            fresh: true,
        }
    }
}

/// Read what a datadir already holds, so a chunked import can continue where it stopped.
///
/// Blocks are committed in batches, so an interrupted chunk leaves a prefix of itself behind. The
/// highest header is therefore the authority on where to resume, and re-running the same chunk is
/// safe: everything at or below it is skipped.
fn read_block_resume<DB: SnapshotDb>(
    factory: &ProviderFactory<NodeTypesWithDBAdapter<ArbNode, DB>>,
) -> eyre::Result<BlockResume> {
    let provider = factory.provider()?;
    let Some(highest) = provider
        .static_file_provider()
        .get_highest_static_file_block(StaticFileSegment::Headers)
    else {
        return Ok(BlockResume::beginning());
    };
    let indices = provider.block_body_indices(highest)?.ok_or_else(|| {
        eyre::eyre!("block {highest} has a header but no body indices; the datadir is inconsistent")
    })?;
    Ok(BlockResume {
        next_block: highest + 1,
        next_tx_num: indices.next_tx_num(),
        fresh: false,
    })
}

/// Import one contiguous run of blocks, appending to whatever the datadir already holds.
///
/// Unlike [`write_head_blocks`], which wires a single head block in as though it were genesis, this
/// builds real block history. Each block is checked against its own header before it is written, and
/// the writing itself is [`flush_blocks`], the same batching the binary `import-full` path uses, so
/// both streams produce an identical datadir from the same blocks.
///
/// Blocks at or below `resume.next_block` are skipped rather than rejected, which is what makes
/// re-running an interrupted chunk safe. The first block actually written must be exactly
/// `resume.next_block`: the static-file segments are indexed by offset from their start, so a gap
/// would misalign them silently instead of failing.
fn write_chain_blocks<DB: SnapshotDb>(
    factory: &ProviderFactory<NodeTypesWithDBAdapter<ArbNode, DB>>,
    path: &Path,
    resume: BlockResume,
) -> eyre::Result<BlockSectionStats> {
    let reader = BufReader::with_capacity(BLOCK_STREAM_BUFFER, File::open(path)?);
    let mut stats = BlockSectionStats::default();
    let mut batch: Vec<PendingBlock> = Vec::with_capacity(BLOCK_BATCH);
    let mut pending: Option<PendingBlock> = None;
    let mut batch_txs = 0usize;
    let mut next_tx_num = resume.next_tx_num;
    let mut first = resume.fresh;
    let mut previous: Option<u64> = None;
    let mut already_present = 0u64;
    let mut skipping = false;

    for (line_index, line) in reader.lines().enumerate() {
        let line_number = line_index + 1;
        let Some(record) = parse_block_record(&line?, line_number)? else {
            continue;
        };
        match record {
            BlockRecord::Header { number, hash, rlp } => {
                if number < resume.next_block {
                    // Already in the datadir, from a previous chunk or an interrupted run.
                    already_present += 1;
                    skipping = true;
                    continue;
                }
                skipping = false;
                match previous {
                    None if number != resume.next_block => eyre::bail!(
                        "blocks stream starts at {number}, but this datadir needs the next chunk to \
                         start at block {}; re-export with --from {}",
                        resume.next_block,
                        resume.next_block
                    ),
                    Some(previous) if number != previous + 1 => eyre::bail!(
                        "blocks stream jumps from {previous} to {number} at line {line_number}; \
                         it must be contiguous and ascending"
                    ),
                    _ => {}
                }
                previous = Some(number);

                if let Some(done) = pending.take() {
                    batch_txs += done.body.as_ref().map_or(0, |b| b.transactions.len());
                    batch.push(done);
                }
                if batch.len() >= BLOCK_BATCH || batch_txs >= TX_BATCH {
                    flush_blocks(
                        factory,
                        &mut batch,
                        &mut next_tx_num,
                        &mut first,
                        &mut stats,
                    )?;
                    batch_txs = 0;
                }
                let block = PendingBlock::open(number, hash, &rlp)?;
                check_header_identity(number, hash, &block.header, &format!("line {line_number}"))?;
                pending = Some(block);
            }
            BlockRecord::Body { number, rlp } => {
                if skipping {
                    continue;
                }
                expect_pending(&mut pending, number, "body")?.attach_body(&rlp)?;
            }
            BlockRecord::Receipts { number, rlp } => {
                if skipping {
                    continue;
                }
                expect_pending(&mut pending, number, "receipts")?.attach_receipts(&rlp)?;
            }
        }
    }

    if let Some(done) = pending.take() {
        batch.push(done);
    }
    flush_blocks(
        factory,
        &mut batch,
        &mut next_tx_num,
        &mut first,
        &mut stats,
    )?;

    if stats.blocks == 0 {
        if already_present > 0 {
            // Re-running a chunk the datadir already has is a no-op, not a failure; a retry loop
            // should be able to replay the last chunk without special-casing it.
            tracing::info!(
                blocks = already_present,
                "chunk is already imported; nothing to do"
            );
        } else {
            eyre::bail!("no H records in {path:?}");
        }
    } else if already_present > 0 {
        tracing::info!(
            skipped = already_present,
            resumed_at = resume.next_block,
            "chunk overlapped what the datadir already held"
        );
    }
    Ok(stats)
}

/// Initialise the changeset segments for a datadir that carries no changesets at all.
///
/// Mirrors the three invariants spelled out in [`write_head_blocks`]: the segments must report the
/// head as their highest block, their expected start must equal where their data really starts, and
/// `csoff[0]` must map to the head. An explicit empty entry at the head satisfies all three.
fn init_empty_changeset_segments(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    head_num: u64,
) -> eyre::Result<()> {
    let provider_rw = factory.database_provider_rw()?;
    let sfp = provider_rw.static_file_provider();
    for seg in [
        StaticFileSegment::AccountChangeSets,
        StaticFileSegment::StorageChangeSets,
    ] {
        let mut w = sfp.get_writer(head_num, seg)?;
        w.user_header_mut().set_expected_block_start(head_num);
        match seg {
            StaticFileSegment::AccountChangeSets => {
                w.append_account_changeset(Vec::new(), head_num)?
            }
            StaticFileSegment::StorageChangeSets => {
                w.append_storage_changeset(Vec::new(), head_num)?
            }
            _ => unreachable!(),
        }
        w.commit()?;
    }
    provider_rw
        .commit()
        .map_err(|e| eyre::eyre!("initialise changeset segments: {e}"))?;
    Ok(())
}

/// Write every `H <num> <hash> <headerRLP>` record into the static-file Headers segment plus
/// `HeaderNumbers`/`BlockBodyIndices`, then set all stage checkpoints to the highest block so a
/// `ProviderFactory` reports it as the head. Returns `(head_number, head_hash)`.
fn write_head_blocks(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    path: &Path,
) -> eyre::Result<(u64, B256)> {
    let provider_rw = factory.database_provider_rw()?;
    let sfp = provider_rw.static_file_provider();

    let reader = std::io::BufReader::new(File::open(path)?);
    let mut head_num = 0u64;
    let mut head_hash = B256::ZERO;
    let mut count = 0u64;

    for (line_index, line) in reader.lines().enumerate() {
        let Some((num, hash, header)) = parse_header_record(&line?, line_index + 1)? else {
            continue;
        };

        // Genesis TD == difficulty for the first block (Arbitrum difficulty is 1).
        let mut writer = sfp.get_writer(num, StaticFileSegment::Headers)?;
        if num > 0 {
            writer.user_header_mut().set_block_range(num, num);
            writer.append_header_direct(&header, header.difficulty, &hash)?;
        } else {
            writer.append_header(&header, &hash)?;
        }
        writer.commit()?;

        provider_rw
            .tx_ref()
            .put::<tables::HeaderNumbers>(hash, num)?;
        provider_rw
            .tx_ref()
            .put::<tables::BlockBodyIndices>(num, Default::default())?;

        if num >= head_num {
            head_num = num;
            head_hash = hash;
        }
        count += 1;
    }

    // Initialize the per-block static-file segments to the head block. Without this, reth's launch
    // `check_consistency` sees those segments empty (highest block None) while the stage checkpoints
    // say `head_num`, and unwinds to block 0. The head block has no txs/receipts, so the segments
    // stay empty; only the block range / expected start needs setting. Mirrors reth `init_genesis`'s
    // non-zero-genesis v2 path (db-common init.rs): Receipts/Transactions/TransactionSenders use
    // `set_block_range`; the changeset segments use `set_expected_block_start` (their block range is
    // established lazily on the first append, but `next_block_number` must start at `head_num`, else
    // the first per-block append during sync tries to write block 0).
    sfp.get_writer(head_num, StaticFileSegment::Receipts)?
        .user_header_mut()
        .set_block_range(head_num, head_num);
    sfp.get_writer(head_num, StaticFileSegment::Transactions)?
        .user_header_mut()
        .set_block_range(head_num, head_num);
    sfp.get_writer(head_num, StaticFileSegment::TransactionSenders)?
        .user_header_mut()
        .set_block_range(head_num, head_num);
    // Changeset segments need all three of these to be true, or the DB is broken for stock reth's
    // v2 unwind/rewind (all invisible to forward sync; hashed state / state root are unaffected):
    //   (a) highest_static_file_block == head, or launch `check_consistency` sees highest=None while
    //       the Execution checkpoint says head and unwinds to block 0 (panic).
    //   (b) expected_block_start == the actual data start, or `truncate_changesets` (which keys off
    //       expected_block_start, = the fixed 500k slot 22000000) over-counts and corrupts the
    //       offset map on every unwind.
    //   (c) csoff[0] must map to `head`, or `changeset_offset_index(N) = N - block_range.start` is
    //       shifted (genesis carries no changeset, so a naive first-append lands csoff[0] at head+1).
    // We satisfy all three by giving genesis an explicit empty changeset entry (matching reth's
    // init_genesis model): `set_expected_block_start(head)` aligns (b), and appending an empty
    // changeset for `head` sets block_range=[head,head] with csoff[0]=head, giving highest=head (a)
    // and an aligned map (c). The file is then renamed to match its new expected range.
    for seg in [
        StaticFileSegment::AccountChangeSets,
        StaticFileSegment::StorageChangeSets,
    ] {
        let mut w = sfp.get_writer(head_num, seg)?;
        w.user_header_mut().set_expected_block_start(head_num);
        match seg {
            StaticFileSegment::AccountChangeSets => {
                w.append_account_changeset(Vec::new(), head_num)?
            }
            StaticFileSegment::StorageChangeSets => {
                w.append_storage_changeset(Vec::new(), head_num)?
            }
            _ => unreachable!(),
        }
        w.commit()?;
    }

    // Mark every stage complete at the head so reth treats the DB as synced to that block.
    let cp = StageCheckpoint::new(head_num);
    for stage in StageId::ALL {
        provider_rw.save_stage_checkpoint(stage, cp)?;
    }
    write_snapshot_history_boundaries(&provider_rw, head_num)?;
    provider_rw.commit()?;
    tracing::info!(count, head_num, ?head_hash, "wrote headers + checkpoints");
    Ok((head_num, head_hash))
}

/// Record that account and storage history before the imported snapshot head is unavailable.
///
/// The imported hashed state is the complete state at `head_num`, but the import contains no
/// changesets or history index for earlier blocks. Without these checkpoints, a storage-v2
/// historical lookup can mistake an imported account for an account first created after its MDBX
/// snapshot when RocksDB is one persistence commit ahead. Marking the missing prefix makes that
/// lookup fall back to the imported hashed state.
fn write_snapshot_history_boundaries(
    provider: &impl PruneCheckpointWriter,
    head_num: u64,
) -> eyre::Result<()> {
    let checkpoint = PruneCheckpoint {
        block_number: Some(head_num),
        tx_number: None,
        prune_mode: PruneMode::before_inclusive(head_num),
    };

    for segment in [PruneSegment::AccountHistory, PruneSegment::StorageHistory] {
        provider.save_prune_checkpoint(segment, checkpoint)?;
    }

    Ok(())
}

/// Re-open the DB and assert the head is wired correctly (the boot-wiring gate).
fn verify_head(
    factory: &ProviderFactory<ArbNodeTypesWithDB>,
    head_num: u64,
    head_hash: B256,
) -> eyre::Result<()> {
    let provider = factory.provider()?;
    let best = provider.best_block_number()?;
    let sealed = HeaderProvider::sealed_header(&provider, head_num)?
        .ok_or_else(|| eyre::eyre!("no sealed header at {head_num}"))?;
    println!("best_block_number = {best}");
    println!("sealed_header({head_num}).hash() = {:#x}", sealed.hash());
    if best == head_num && sealed.hash() == head_hash {
        println!("HEAD OK");
        Ok(())
    } else {
        Err(eyre::eyre!(
            "head mismatch: best={best} (want {head_num}), hash={:#x} (want {head_hash:#x})",
            sealed.hash()
        ))
    }
}

#[derive(Debug)]
enum StateRecord {
    Account {
        account_hash: B256,
        account: Account,
    },
    Code {
        code_hash: B256,
        bytecode: Bytecode,
    },
    Storage {
        slot_hash: B256,
        value: U256,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct StateStreamStats {
    accounts: u64,
    slots: u64,
    bytecodes: u64,
}

fn parse_state_record(line: &str, line_number: usize) -> eyre::Result<Option<StateRecord>> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }

    let mut parts = line.split_whitespace();
    let tag = parts.next().expect("non-empty line");
    let mut next = |field: &str| {
        parts
            .next()
            .ok_or_else(|| eyre::eyre!("{tag}: missing {field} at line {line_number}"))
    };

    let record = match tag {
        "A" => {
            let account_hash = parse_b256(next("accountHash")?).map_err(|error| {
                eyre::eyre!("A: bad accountHash at line {line_number}: {error}")
            })?;
            let nonce = next("nonce")?
                .parse()
                .map_err(|error| eyre::eyre!("A: bad nonce at line {line_number}: {error}"))?;
            let balance = U256::from_str_radix(next("balance")?.trim_start_matches("0x"), 16)
                .map_err(|error| eyre::eyre!("A: bad balance at line {line_number}: {error}"))?;
            let code_hash = parse_b256(next("codeHash")?)
                .map_err(|error| eyre::eyre!("A: bad codeHash at line {line_number}: {error}"))?;
            parse_b256(next("storageRoot")?).map_err(|error| {
                eyre::eyre!("A: bad storageRoot at line {line_number}: {error}")
            })?;

            let bytecode_hash = (code_hash.0 != KECCAK_EMPTY).then_some(code_hash);
            StateRecord::Account {
                account_hash,
                account: Account {
                    nonce,
                    balance,
                    bytecode_hash,
                },
            }
        }
        "C" => {
            let code_hash = parse_b256(next("codeHash")?)
                .map_err(|error| eyre::eyre!("C: bad codeHash at line {line_number}: {error}"))?;
            let code = hex::decode(next("code")?)
                .map_err(|error| eyre::eyre!("C: bad code hex at line {line_number}: {error}"))?;
            let actual_hash = keccak256(&code);
            if actual_hash != code_hash {
                eyre::bail!(
                    "C: bytecode hash mismatch at line {line_number}: declared={code_hash:#x}, actual={actual_hash:#x}"
                );
            }
            StateRecord::Code {
                code_hash,
                bytecode: Bytecode::new_raw(Bytes::from(code)),
            }
        }
        "S" => {
            let slot_hash = parse_b256(next("slotHash")?)
                .map_err(|error| eyre::eyre!("S: bad slotHash at line {line_number}: {error}"))?;
            let value = U256::from_str_radix(next("value")?.trim_start_matches("0x"), 16)
                .map_err(|error| eyre::eyre!("S: bad value at line {line_number}: {error}"))?;
            StateRecord::Storage { slot_hash, value }
        }
        _ => {
            eyre::bail!("unknown state record {tag:?} at line {line_number}");
        }
    };

    if parts.next().is_some() {
        eyre::bail!("{tag}: unexpected trailing fields at line {line_number}");
    }
    Ok(Some(record))
}

fn preflight_state_stream(
    path: &Path,
    preimages: Option<&SlotPreimagesReader>,
) -> eyre::Result<StateStreamStats> {
    let reader = BufReader::with_capacity(4 * 1024 * 1024, File::open(path)?);
    let mut stats = StateStreamStats::default();
    let mut saw_account = false;
    let mut required_code_hashes: HashSet<B256> = HashSet::new();
    let mut provided_code_hashes: HashSet<B256> = HashSet::new();

    for (line_index, line) in reader.lines().enumerate() {
        let Some(record) = parse_state_record(&line?, line_index + 1)? else {
            continue;
        };
        match record {
            StateRecord::Account { account, .. } => {
                saw_account = true;
                stats.accounts += 1;
                if let Some(code_hash) = account.bytecode_hash {
                    required_code_hashes.insert(code_hash);
                }
            }
            StateRecord::Code { code_hash, .. } => {
                stats.bytecodes += 1;
                provided_code_hashes.insert(code_hash);
            }
            StateRecord::Storage { slot_hash, value } => {
                if !saw_account {
                    eyre::bail!("S record before any A record at line {}", line_index + 1);
                }
                if value.is_zero() {
                    continue;
                }
                if let Some(preimages) = preimages {
                    require_slot_preimage(preimages, slot_hash).map_err(|error| {
                        eyre::eyre!(
                            "S: invalid slot preimage at line {}: {error}",
                            line_index + 1
                        )
                    })?;
                }
                stats.slots += 1;
            }
        }
    }

    if stats.accounts == 0 {
        eyre::bail!("state stream contains no accounts");
    }
    if let Some(missing) = required_code_hashes
        .difference(&provided_code_hashes)
        .next()
    {
        eyre::bail!("state stream is missing bytecode record {missing:#x}");
    }
    Ok(stats)
}

fn stream_import<PF>(
    factory: &PF,
    path: &PathBuf,
    preimages: Option<&SlotPreimagesReader>,
) -> eyre::Result<()>
where
    PF: reth_provider::DatabaseProviderFactory<ProviderRW: DBProvider<Tx: DbTxMut>>,
{
    let file = File::open(path)?;
    let reader = BufReader::with_capacity(4 * 1024 * 1024, file);

    let mut provider_rw = factory.database_provider_rw()?;

    // Track progress
    let mut total_accounts: usize = 0;
    let mut total_slots: usize = 0;
    let mut total_bytecodes: usize = 0;
    let mut storage_units: usize = 0;

    // Flush storage when the next A/C line arrives.
    let mut current_account_hash: Option<B256> = None;

    for (line_index, line) in reader.lines().enumerate() {
        let Some(record) = parse_state_record(&line?, line_index + 1)? else {
            continue;
        };

        match record {
            StateRecord::Account {
                account_hash,
                account,
            } => {
                // Commit if threshold reached (before this account pushes us over).
                if storage_units >= COMMIT_THRESHOLD {
                    provider_rw.commit()?;
                    provider_rw = factory.database_provider_rw()?;
                    tracing::info!(
                        total_accounts,
                        total_slots,
                        total_bytecodes,
                        storage_units,
                        "committed chunk"
                    );
                    storage_units = 0;
                }

                // Write hashed account.
                provider_rw
                    .tx_ref()
                    .put::<tables::HashedAccounts>(account_hash, account)?;
                current_account_hash = Some(account_hash);
                total_accounts += 1;
                storage_units += 1;

                if total_accounts.is_multiple_of(100_000) {
                    tracing::info!(total_accounts, total_slots, "writing accounts...");
                }
            }
            StateRecord::Code {
                code_hash,
                bytecode,
            } => {
                // Commit if threshold reached.
                if storage_units >= COMMIT_THRESHOLD {
                    provider_rw.commit()?;
                    provider_rw = factory.database_provider_rw()?;
                    tracing::info!(
                        total_accounts,
                        total_slots,
                        total_bytecodes,
                        storage_units,
                        "committed chunk"
                    );
                    storage_units = 0;
                }

                provider_rw
                    .tx_ref()
                    .put::<tables::Bytecodes>(code_hash, bytecode)?;
                total_bytecodes += 1;
                storage_units += 1;
            }
            StateRecord::Storage { slot_hash, value } => {
                let acct_hash = match current_account_hash {
                    Some(h) => h,
                    None => {
                        return Err(eyre::eyre!(
                            "S record before any A record at line {}",
                            line_index + 1
                        ));
                    }
                };

                if value.is_zero() {
                    // Zero slots have no effect on the trie.
                    continue;
                }

                if let Some(preimages) = preimages {
                    require_slot_preimage(preimages, slot_hash).map_err(|e| {
                        eyre::eyre!("S: invalid slot preimage at line {}: {e}", line_index + 1)
                    })?;
                }

                // Commit if threshold reached.
                if storage_units >= COMMIT_THRESHOLD {
                    provider_rw.commit()?;
                    provider_rw = factory.database_provider_rw()?;
                    tracing::info!(
                        total_accounts,
                        total_slots,
                        total_bytecodes,
                        storage_units,
                        "committed chunk"
                    );
                    storage_units = 0;
                }

                let entry = StorageEntry {
                    key: slot_hash,
                    value,
                };
                let tx = provider_rw.tx_ref();
                let mut cursor = tx.cursor_dup_write::<tables::HashedStorages>()?;
                cursor.upsert(acct_hash, &entry)?;

                total_slots += 1;
                storage_units += 1;
            }
        }
    }

    // Final commit.
    provider_rw.commit()?;
    tracing::info!(
        total_accounts,
        total_slots,
        total_bytecodes,
        "all data written to MDBX"
    );

    Ok(())
}

fn require_slot_preimage(preimages: &SlotPreimagesReader, hashed_slot: B256) -> eyre::Result<B256> {
    let plain_slot = preimages
        .get(&hashed_slot)?
        .ok_or_else(|| eyre::eyre!("missing preimage for slot {hashed_slot:#x}"))?;
    let actual_hash = keccak256(plain_slot);
    if actual_hash != hashed_slot {
        eyre::bail!(
            "corrupt preimage for slot {hashed_slot:#x}: plain={plain_slot:#x}, hash={actual_hash:#x}"
        );
    }
    Ok(plain_slot)
}

pub(crate) fn compute_state_root_chunked<PF>(factory: &PF) -> eyre::Result<B256>
where
    PF: reth_provider::DatabaseProviderFactory<
            ProviderRW: DBProvider<Tx: DbTxMut> + TrieWriter + StorageSettingsCache,
        >,
{
    let mut intermediate_state: Option<IntermediateStateRootState> = None;
    let mut total_flushed: usize = 0;

    loop {
        let provider_rw = factory.database_provider_rw()?;

        // Borrow tx for the root computation, then drop the borrow before commit.
        let (root_result, state_opt, updates_opt) = {
            let tx = provider_rw.tx_ref();
            let state_root = DbStateRoot::from_tx(tx)
                .with_intermediate_state(intermediate_state.take())
                .with_threshold(TRIE_COMMIT_THRESHOLD);

            match state_root.root_with_progress()? {
                StateRootProgress::Progress(state, _, updates) => {
                    (None, Some(*state), Some(updates))
                }
                StateRootProgress::Complete(root, _, updates) => (Some(root), None, Some(updates)),
            }
        };

        let n = provider_rw.write_trie_updates(updates_opt.unwrap())?;
        total_flushed += n;

        if let Some(state) = state_opt {
            tracing::info!(
                last_key = %state.account_root_state.last_hashed_key,
                flushed = n,
                total_flushed,
                "trie progress: committing to free dirty pages"
            );
            intermediate_state = Some(state);
            provider_rw
                .commit()
                .map_err(|e| eyre::eyre!("trie progress commit: {e}"))?;
        } else if let Some(root) = root_result {
            tracing::info!(%root, flushed = n, total_flushed, "state root computation complete");
            provider_rw
                .commit()
                .map_err(|e| eyre::eyre!("trie final commit: {e}"))?;
            return Ok(root);
        }
    }
}

fn parse_b256(hex_str: &str) -> eyre::Result<B256> {
    let s = hex_str.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(eyre::eyre!(
            "expected 64 hex chars, got {}: {:?}",
            s.len(),
            &hex_str[..s.len().min(20)]
        ));
    }
    let bytes = hex::decode(s)?;
    Ok(B256::from_slice(&bytes))
}

pub fn read(args: SnapshotReadArgs) -> eyre::Result<()> {
    // Parse the address.
    let addr_str = args.addr.trim_start_matches("0x");
    if addr_str.len() != 40 {
        return Err(eyre::eyre!(
            "--addr must be 40 hex chars (20 bytes), got {}",
            args.addr
        ));
    }
    let addr_bytes = hex::decode(addr_str)?;
    let address = Address::from_slice(&addr_bytes);

    // Compute the keccak hash of the address (the hashed-state key).
    let hashed_key = keccak256(address);

    // Open the MDBX read-only.
    // arb-snapshot-import stores MDBX in <out>/db.
    let db_path = args.db.join("db");

    // Pick the actual MDBX directory: prefer <dir>/db, fall back to <dir>.
    let mdbx_path = if db_path.exists() {
        db_path
    } else {
        args.db.clone()
    };

    let db = open_db_read_only(
        mdbx_path.as_path(),
        DatabaseArguments::new(ClientVersion::default()),
    )?;

    let tx = db.tx()?;

    let maybe_account = account_by_address(&tx, address);

    let (nonce, balance, code_hash) = match &maybe_account {
        Some(acct) => {
            let ch = acct.bytecode_hash.unwrap_or(HASHED_KECCAK_EMPTY);
            (acct.nonce, acct.balance, ch)
        }
        None => (0u64, U256::ZERO, HASHED_KECCAK_EMPTY),
    };

    let code_len = if code_hash == HASHED_KECCAK_EMPTY {
        0usize
    } else {
        match code_of(&tx, code_hash) {
            Some(bytecode) => bytecode.0.len(),
            None => 0,
        }
    };

    println!(
        "addr {} keccak {} nonce {} balance {} codeHash {} codeLen {}",
        address, hashed_key, nonce, balance, code_hash, code_len,
    );

    if let Some(slot_str) = &args.slot {
        let slot_hex = slot_str.trim_start_matches("0x");
        // Pad to 64 hex chars if shorter.
        let padded = format!("{:0>64}", slot_hex);
        if padded.len() != 64 {
            return Err(eyre::eyre!(
                "--slot must be at most 32 bytes (64 hex chars), got {}",
                slot_str
            ));
        }
        let slot_bytes = hex::decode(&padded)?;
        let slot = B256::from_slice(&slot_bytes);

        let value = storage_at(&tx, address, slot);
        println!("slot {} value {}", slot, value);
    }

    if args.list_storage {
        let ak = keccak256(address);
        let mut cursor = tx.cursor_dup_read::<tables::HashedStorages>()?;

        // Walk all dup values for this account key.
        let walker = cursor.walk_dup(Some(ak), None)?;
        let mut count = 0usize;
        for entry_result in walker {
            let (_key, entry) = entry_result?;
            if !entry.value.is_zero() {
                println!("  storage hashed_slot {} value {}", entry.key, entry.value);
                count += 1;
            }
        }
        println!("storage non-zero slot count: {}", count);
    }

    tx.commit()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, b256};
    use reth_db_api::{
        BlockNumberList,
        models::{ShardedKey, storage_sharded_key::StorageShardedKey},
    };
    use reth_storage_api::{
        AccountReader, PruneCheckpointReader, StateProvider, TryIntoHistoricalStateProvider,
    };

    /// Blocks 0..=2 as the text stream `reth-export --mode blocks` writes, where block 1 carries
    /// transactions and receipts. Same fixtures as the binary importer's own block test, so the two
    /// paths are compared on identical input.
    fn chain_blocks_stream(dir: &Path) -> eyre::Result<(PathBuf, Vec<B256>)> {
        use super::super::snapshot_full::tests::{
            body_rlp, header, receipt_specs, stored_receipts_rlp, transactions,
        };

        let txs = transactions();
        let rcpts = super::super::snapshot_full::tests::receipts();
        let h0 = header(0, B256::ZERO, &[], &[]);
        let hash0 = h0.hash_slow();
        let h1 = header(1, hash0, &txs, &rcpts);
        let hash1 = h1.hash_slow();
        let h2 = header(2, hash1, &[], &[]);
        let hash2 = h2.hash_slow();

        let mut out = String::new();
        for (header, hash, body, receipts) in [
            (&h0, hash0, body_rlp(&[]), None),
            (
                &h1,
                hash1,
                body_rlp(&txs),
                Some(stored_receipts_rlp(&receipt_specs())),
            ),
            (&h2, hash2, body_rlp(&[]), None),
        ] {
            out.push_str(&format!(
                "H {} {:x} {}\n",
                header.number,
                hash,
                hex::encode(alloy_rlp::encode(header))
            ));
            out.push_str(&format!("B {} {}\n", header.number, hex::encode(&body)));
            if let Some(receipts) = receipts {
                out.push_str(&format!("R {} {}\n", header.number, hex::encode(&receipts)));
            }
        }

        let path = dir.join("blocks.stream");
        std::fs::write(&path, out)?;
        Ok((path, vec![hash0, hash1, hash2]))
    }

    fn chain_test_factory() -> ProviderFactory<
        NodeTypesWithDBAdapter<
            ArbNode,
            Arc<reth_db::test_utils::TempDatabase<reth_db::DatabaseEnv>>,
        >,
    > {
        use reth_provider::test_utils::create_test_provider_factory_with_node_types;
        let factory = create_test_provider_factory_with_node_types::<ArbNode>(
            super::super::snapshot_full::tests::spec(),
        );
        factory.set_storage_settings_cache(StorageSettings::v2());
        let provider = factory.database_provider_rw().unwrap();
        provider
            .write_storage_settings(StorageSettings::v2())
            .unwrap();
        provider.commit().unwrap();
        factory
    }

    #[test]
    fn a_text_blocks_stream_lands_bodies_and_receipts_not_just_headers() -> eyre::Result<()> {
        use reth_storage_api::{BlockBodyIndicesProvider, ReceiptProvider, TransactionsProvider};

        let temp = tempfile::tempdir()?;
        let (path, hashes) = chain_blocks_stream(temp.path())?;
        let factory = chain_test_factory();

        let stats = write_chain_blocks(&factory, &path, BlockResume::beginning())?;
        assert_eq!(stats.blocks, 3);
        assert_eq!(stats.transactions, 2);
        assert_eq!(stats.receipts, 2);
        assert_eq!((stats.first_block, stats.last_block), (0, 2));

        let provider = factory.provider()?;
        for (number, hash) in hashes.iter().enumerate() {
            let sealed = HeaderProvider::sealed_header(&provider, number as u64)?
                .unwrap_or_else(|| panic!("no header at {number}"));
            assert_eq!(sealed.hash(), *hash, "block {number} hash");
        }

        // The head-only importer wrote `BlockBodyIndices::default()` for every block; these are the
        // real ones, and they are what makes the receipts readable back.
        let indices = provider.block_body_indices(1)?.expect("indices at 1");
        assert_eq!((indices.first_tx_num, indices.tx_count), (0, 2));
        assert_eq!(
            provider
                .transactions_by_block(1u64.into())?
                .expect("txs at 1"),
            super::super::snapshot_full::tests::transactions()
        );
        assert_eq!(
            provider
                .receipts_by_block(1u64.into())?
                .expect("receipts at 1"),
            super::super::snapshot_full::tests::receipts()
        );
        assert_eq!(
            provider
                .block_body_indices(2)?
                .expect("indices at 2")
                .first_tx_num,
            2
        );
        Ok(())
    }

    #[test]
    fn chunks_resume_where_the_previous_one_stopped() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::{
            body_rlp, header, receipt_specs, receipts, stored_receipts_rlp, transactions,
        };
        use reth_storage_api::{BlockBodyIndicesProvider, ReceiptProvider, TransactionsProvider};

        // Blocks 0..=2 as two chunks split across the block that carries transactions, so the
        // resume has to carry the transaction numbering across the boundary as well as the height.
        let txs = transactions();
        let rcpts = receipts();
        let h0 = header(0, B256::ZERO, &[], &[]);
        let h1 = header(1, h0.hash_slow(), &txs, &rcpts);
        let h2 = header(2, h1.hash_slow(), &[], &[]);

        let temp = tempfile::tempdir()?;
        let render = |name: &str, blocks: &[(&Header, Option<Vec<u8>>)]| -> eyre::Result<PathBuf> {
            let mut out = String::new();
            for (h, receipts) in blocks {
                out.push_str(&format!(
                    "H {} {:x} {}\n",
                    h.number,
                    h.hash_slow(),
                    hex::encode(alloy_rlp::encode(*h))
                ));
                let body = if h.number == 1 {
                    body_rlp(&txs)
                } else {
                    body_rlp(&[])
                };
                out.push_str(&format!("B {} {}\n", h.number, hex::encode(&body)));
                if let Some(receipts) = receipts {
                    out.push_str(&format!("R {} {}\n", h.number, hex::encode(receipts)));
                }
            }
            let path = temp.path().join(name);
            std::fs::write(&path, out)?;
            Ok(path)
        };

        let stored = stored_receipts_rlp(&receipt_specs());
        let chunk_a = render("a.stream", &[(&h0, None), (&h1, Some(stored.clone()))])?;
        let chunk_b = render("b.stream", &[(&h2, None)])?;

        let factory = chain_test_factory();
        assert_eq!(read_block_resume(&factory)?, BlockResume::beginning());

        let a = append_blocks(&factory, &chunk_a)?;
        assert_eq!((a.first_block, a.last_block, a.transactions), (0, 1, 2));

        // The second chunk has to pick up both the height and the transaction numbering.
        let resume = read_block_resume(&factory)?;
        assert_eq!(
            resume,
            BlockResume {
                next_block: 2,
                next_tx_num: 2,
                fresh: false
            }
        );

        let b = append_blocks(&factory, &chunk_b)?;
        assert_eq!((b.first_block, b.last_block), (2, 2));

        // Replaying a chunk the datadir already holds is a no-op, which is what lets an interrupted
        // run simply be repeated.
        let again = append_blocks(&factory, &chunk_a)?;
        assert_eq!(again.blocks, 0);
        assert_eq!(read_block_resume(&factory)?.next_block, 3);

        // The result is the same database the one-shot import produces.
        let provider = factory.provider()?;
        for (number, expected) in [
            (0, h0.hash_slow()),
            (1, h1.hash_slow()),
            (2, h2.hash_slow()),
        ] {
            let sealed = HeaderProvider::sealed_header(&provider, number)?
                .unwrap_or_else(|| panic!("no header at {number}"));
            assert_eq!(sealed.hash(), expected, "block {number} hash");
        }
        let indices = provider.block_body_indices(1)?.expect("indices at 1");
        assert_eq!((indices.first_tx_num, indices.tx_count), (0, 2));
        assert_eq!(
            provider
                .block_body_indices(2)?
                .expect("indices at 2")
                .first_tx_num,
            2
        );
        assert_eq!(
            provider
                .transactions_by_block(1u64.into())?
                .expect("txs at 1"),
            txs
        );
        assert_eq!(
            provider
                .receipts_by_block(1u64.into())?
                .expect("receipts at 1"),
            rcpts
        );
        Ok(())
    }

    #[test]
    fn a_chunk_that_skips_ahead_of_the_datadir_is_rejected() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::{body_rlp, header};

        let temp = tempfile::tempdir()?;
        let h0 = header(0, B256::ZERO, &[], &[]);
        let h1 = header(1, h0.hash_slow(), &[], &[]);
        let h2 = header(2, h1.hash_slow(), &[], &[]);
        let render = |name: &str, hs: &[&Header]| -> eyre::Result<PathBuf> {
            let mut out = String::new();
            for h in hs {
                out.push_str(&format!(
                    "H {} {:x} {}\nB {} {}\n",
                    h.number,
                    h.hash_slow(),
                    hex::encode(alloy_rlp::encode(*h)),
                    h.number,
                    hex::encode(body_rlp(&[]))
                ));
            }
            let path = temp.path().join(name);
            std::fs::write(&path, out)?;
            Ok(path)
        };

        let factory = chain_test_factory();
        append_blocks(&factory, &render("first.stream", &[&h0])?)?;

        // Block 1 is missing: appending 2 here would leave a hole the segments cannot represent.
        let error = append_blocks(&factory, &render("skip.stream", &[&h2])?).unwrap_err();
        assert!(
            error.to_string().contains("start at block 1"),
            "unexpected error: {error}"
        );

        // The chunk that does start there is accepted.
        append_blocks(&factory, &render("second.stream", &[&h1, &h2])?)?;
        assert_eq!(read_block_resume(&factory)?.next_block, 3);
        Ok(())
    }

    #[test]
    fn a_whole_chain_stream_must_be_contiguous_and_start_at_zero() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::header;

        let temp = tempfile::tempdir()?;
        let write = |name: &str, headers: &[Header]| -> eyre::Result<PathBuf> {
            let mut out = String::new();
            for h in headers {
                out.push_str(&format!(
                    "H {} {:x} {}\n",
                    h.number,
                    h.hash_slow(),
                    hex::encode(alloy_rlp::encode(h))
                ));
            }
            let path = temp.path().join(name);
            std::fs::write(&path, out)?;
            Ok(path)
        };

        let h0 = header(0, B256::ZERO, &[], &[]);
        let h1 = header(1, h0.hash_slow(), &[], &[]);
        let h3 = header(3, h1.hash_slow(), &[], &[]);

        // A gap would silently misalign the static-file segments, which index by offset.
        let gap = write("gap.stream", &[h0.clone(), h1.clone(), h3])?;
        let error =
            write_chain_blocks(&chain_test_factory(), &gap, BlockResume::beginning()).unwrap_err();
        assert!(
            error.to_string().contains("jumps from 1 to 3"),
            "unexpected error: {error}"
        );

        // Starting above genesis leaves the datadir with no block 0 for reth's launch check.
        let headless = write("headless.stream", &[h1])?;
        let error = write_chain_blocks(&chain_test_factory(), &headless, BlockResume::beginning())
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("needs the next chunk to start at block 0"),
            "unexpected error: {error}"
        );
        Ok(())
    }

    #[test]
    fn a_stream_cut_mid_record_is_rejected_before_anything_is_created() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::{body_rlp, header};

        let temp = tempfile::tempdir()?;
        let out = temp.path().join("out");
        let h0 = header(0, B256::ZERO, &[], &[]);
        let complete = format!(
            "H 0 {:x} {}\nB 0 {}\n",
            h0.hash_slow(),
            hex::encode(alloy_rlp::encode(&h0)),
            hex::encode(body_rlp(&[]))
        );

        let whole = temp.path().join("whole.stream");
        std::fs::write(&whole, &complete)?;
        check_stream_is_complete(&whole)?;

        // What a killed exporter leaves: the final record cut short, with no closing newline.
        let cut = temp.path().join("cut.stream");
        std::fs::write(&cut, &complete[..complete.len() - 12])?;
        let error = check_stream_is_complete(&cut).unwrap_err();
        assert!(
            error.to_string().contains("ends mid-record"),
            "unexpected error: {error}"
        );

        let error = import(SnapshotImportArgs {
            state: temp.path().join("missing-state.stream"),
            out: out.clone(),
            expect: format!("{:#x}", B256::ZERO),
            blocks: cut,
            chain_info: Some(temp.path().join("chaininfo.json")),
            genesis_json: Some(temp.path().join("genesis.json")),
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("ends mid-record"),
            "unexpected error: {error}"
        );
        assert!(
            !out.exists(),
            "a rejected stream must leave no target behind"
        );
        Ok(())
    }

    #[test]
    fn a_head_only_stream_is_rejected_before_anything_is_created() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::header;

        let temp = tempfile::tempdir()?;
        let out = temp.path().join("out");
        // What `reth-export --mode blocks` writes by default: the head alone, high above genesis.
        let head = header(55_813_699, B256::ZERO, &[], &[]);
        let blocks = temp.path().join("head-block.stream");
        std::fs::write(
            &blocks,
            format!(
                "H {} {:x} {}\n",
                head.number,
                head.hash_slow(),
                hex::encode(alloy_rlp::encode(&head))
            ),
        )?;
        assert_eq!(first_block_number(&blocks)?, 55_813_699);

        let error = import(SnapshotImportArgs {
            // Deliberately absent: the block check must fire before the state stream is read.
            state: temp.path().join("missing-state.stream"),
            out: out.clone(),
            expect: format!("{:#x}", B256::ZERO),
            blocks,
            chain_info: Some(temp.path().join("chaininfo.json")),
            genesis_json: Some(temp.path().join("genesis.json")),
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("--from 0"),
            "unexpected error: {error}"
        );
        assert!(
            !out.exists(),
            "a rejected stream must not leave a target that a retry would have to clean up"
        );
        Ok(())
    }

    #[test]
    fn head_only_import_refuses_a_multi_block_stream() -> eyre::Result<()> {
        use super::super::snapshot_full::tests::header;

        let temp = tempfile::tempdir()?;
        let out = temp.path().join("out");
        let h0 = header(0, B256::ZERO, &[], &[]);
        let h1 = header(1, h0.hash_slow(), &[], &[]);
        let blocks = temp.path().join("blocks.stream");
        std::fs::write(
            &blocks,
            format!(
                "H 0 {:x} {}\nH 1 {:x} {}\n",
                h0.hash_slow(),
                hex::encode(alloy_rlp::encode(&h0)),
                h1.hash_slow(),
                hex::encode(alloy_rlp::encode(&h1)),
            ),
        )?;

        let error = import(SnapshotImportArgs {
            state: temp.path().join("unused-state.stream"),
            out: out.clone(),
            expect: format!("{:#x}", B256::ZERO),
            blocks,
            chain_info: None,
            genesis_json: None,
        })
        .unwrap_err();
        assert!(
            error.to_string().contains("--chain-info and --genesis"),
            "unexpected error: {error}"
        );
        assert!(
            !out.join("db/mdbx.dat").exists(),
            "no database for a rejected stream"
        );
        Ok(())
    }

    #[test]
    fn body_and_receipt_records_keep_their_payloads() -> eyre::Result<()> {
        // The head-only parser validated these and threw them away; the whole-chain path needs the
        // bytes back out.
        let body = alloy_rlp::encode(&arbitrum_alloy_consensus::reth::ArbBlockBody {
            transactions: Vec::new(),
            ommers: Vec::new(),
            withdrawals: None,
        });
        let line = format!("B 7 {}", hex::encode(&body));
        let Some(BlockRecord::Body { number, rlp }) = parse_block_record(&line, 1)? else {
            panic!("expected a body record");
        };
        assert_eq!(number, 7);
        assert_eq!(rlp, body);

        // And the head-only parser still skips them, so its behaviour is unchanged.
        assert!(parse_header_record(&line, 1)?.is_none());
        Ok(())
    }

    #[test]
    fn preimage_batches_are_deduplicated_and_native_store_roundtrips() -> eyre::Result<()> {
        let temp = tempfile::tempdir()?;
        let store = SlotPreimages::open(temp.path())?;
        let plain_a = b256!("0000000000000000000000000000000000000000000000000000000000000042");
        let plain_b = b256!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        let mut batch = vec![
            (keccak256(plain_b), plain_b),
            (keccak256(plain_a), plain_a),
            (keccak256(plain_a), plain_a),
        ];

        assert_eq!(flush_preimage_batch(&store, &mut batch)?, 2);
        assert!(batch.is_empty());

        let reader = store.reader()?;
        assert_eq!(reader.get(&keccak256(plain_a))?, Some(plain_a));
        assert_eq!(reader.get(&keccak256(plain_b))?, Some(plain_b));
        drop(reader);

        let mut duplicate_batch = vec![(keccak256(plain_a), plain_a)];
        assert_eq!(flush_preimage_batch(&store, &mut duplicate_batch)?, 0);

        let corrupt_temp = tempfile::tempdir()?;
        let corrupt_store = SlotPreimages::open(corrupt_temp.path())?;
        corrupt_store.insert_preimages(&[(keccak256(plain_a), plain_b)])?;
        let mut conflicting_batch = vec![(keccak256(plain_a), plain_a)];
        let error = flush_preimage_batch(&corrupt_store, &mut conflicting_batch).unwrap_err();
        assert!(error.to_string().contains("conflicting slot preimage"));

        let mut internally_conflicting = vec![(B256::ZERO, plain_a), (B256::ZERO, plain_b)];
        let error = flush_preimage_batch(&store, &mut internally_conflicting).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting slot preimages in batch")
        );
        Ok(())
    }

    #[test]
    fn imported_slot_requires_a_matching_preimage() -> eyre::Result<()> {
        let missing_temp = tempfile::tempdir()?;
        let missing_store = SlotPreimages::open(missing_temp.path())?;
        let plain = b256!("0000000000000000000000000000000000000000000000000000000000000042");
        let hashed = keccak256(plain);
        let error = require_slot_preimage(&missing_store.reader()?, hashed).unwrap_err();
        assert!(error.to_string().contains("missing preimage"));

        let corrupt_temp = tempfile::tempdir()?;
        let corrupt_store = SlotPreimages::open(corrupt_temp.path())?;
        let wrong_plain = b256!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        corrupt_store.insert_preimages(&[(hashed, wrong_plain)])?;
        let error = require_slot_preimage(&corrupt_store.reader()?, hashed).unwrap_err();
        assert!(error.to_string().contains("corrupt preimage"));
        Ok(())
    }

    #[test]
    fn state_stream_preflight_checks_code_and_slot_preimages() -> eyre::Result<()> {
        let temp = tempfile::tempdir()?;
        let store = SlotPreimages::open(&temp.path().join("preimages"))?;
        let state_path = temp.path().join("state.stream");
        let account_hash = keccak256(address!("0000000000000000000000000000000000001234"));
        let plain_slot = b256!("0000000000000000000000000000000000000000000000000000000000000042");
        let slot_hash = keccak256(plain_slot);
        store.insert_preimages(&[(slot_hash, plain_slot)])?;
        let code = [0x60, 0x00, 0x56];
        let code_hash = keccak256(code);

        std::fs::write(
            &state_path,
            format!(
                "A {account_hash:#x} 7 2a {code_hash:#x} {:#x}\nS {slot_hash:#x} 01\nC {code_hash:#x} {}\n",
                B256::ZERO,
                hex::encode(code),
            ),
        )?;
        assert_eq!(
            preflight_state_stream(&state_path, Some(&store.reader()?))?,
            StateStreamStats {
                accounts: 1,
                slots: 1,
                bytecodes: 1,
            }
        );
        assert_eq!(
            preflight_state_stream(&state_path, None)?,
            StateStreamStats {
                accounts: 1,
                slots: 1,
                bytecodes: 1,
            },
            "post-ArbOS 20 snapshots do not require slot preimages"
        );

        std::fs::write(
            &state_path,
            format!(
                "A {account_hash:#x} 7 2a {code_hash:#x} {:#x}\n",
                B256::ZERO
            ),
        )?;
        let error = preflight_state_stream(&state_path, Some(&store.reader()?)).unwrap_err();
        assert!(error.to_string().contains("missing bytecode record"));

        std::fs::write(&state_path, format!("C {code_hash:#x} 00\n"))?;
        let error = preflight_state_stream(&state_path, Some(&store.reader()?)).unwrap_err();
        assert!(error.to_string().contains("bytecode hash mismatch"));
        Ok(())
    }

    #[test]
    fn snapshot_import_requires_a_fresh_target() -> eyre::Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::create_dir_all(temp.path().join("db/preimage"))?;
        ensure_fresh_import_target(temp.path())?;

        let resume_path = temp.path().join(RESUME_FILE_NAME);
        std::fs::write(&resume_path, b"stale checkpoint")?;
        let error = ensure_fresh_import_target(temp.path()).unwrap_err();
        assert!(error.to_string().contains("stale L1 resume metadata"));
        std::fs::remove_file(&resume_path)?;

        let resume_tmp_path = resume_path.with_extension("json.tmp");
        std::fs::write(&resume_tmp_path, b"interrupted checkpoint write")?;
        let error = ensure_fresh_import_target(temp.path()).unwrap_err();
        assert!(error.to_string().contains("stale L1 resume metadata"));
        std::fs::remove_file(resume_tmp_path)?;

        std::fs::create_dir(temp.path().join("db/.preimage.tmp"))?;
        assert!(find_staging_preimage_dir(&temp.path().join("db"))?.is_some());
        std::fs::remove_dir(temp.path().join("db/.preimage.tmp"))?;

        std::fs::create_dir(temp.path().join("static_files"))?;
        let error = ensure_fresh_import_target(temp.path()).unwrap_err();
        assert!(error.to_string().contains("fresh target"));

        let other = tempfile::tempdir()?;
        std::fs::create_dir_all(other.path().join("db"))?;
        std::fs::write(other.path().join("db/mdbx.dat"), [])?;
        let error = ensure_fresh_import_target(other.path()).unwrap_err();
        assert!(error.to_string().contains("unexpected path"));
        Ok(())
    }

    #[test]
    fn snapshot_head_record_is_self_authenticating() -> eyre::Result<()> {
        use alloy_rlp::Encodable;

        let temp = tempfile::tempdir()?;
        let path = temp.path().join("head.stream");
        let header = Header {
            number: 42,
            state_root: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            ..Default::default()
        };
        let hash = header.hash_slow();
        let mut encoded = Vec::new();
        header.encode(&mut encoded);
        std::fs::write(&path, format!("H 42 {hash:#x} {}\n", hex::encode(encoded)))?;
        let (number, decoded_hash, decoded) = read_head_header(&path)?;
        assert_eq!(number, 42);
        assert_eq!(decoded_hash, hash);
        assert_eq!(decoded.state_root, header.state_root);

        std::fs::write(
            &path,
            format!(
                "H 42 {hash:#x} {}\nB 42 c2c0c0\nR 42 c0\n",
                hex::encode(alloy_rlp::encode(header.clone()))
            ),
        )?;
        assert_eq!(read_head_header(&path)?.0, 42);

        let bad_path = temp.path().join("bad-head.stream");
        std::fs::write(
            &bad_path,
            format!(
                "H 42 {:#x} {}\n",
                B256::ZERO,
                hex::encode(alloy_rlp::encode(header.clone()))
            ),
        )?;
        let error = read_head_header(&bad_path).unwrap_err();
        assert!(error.to_string().contains("header hash mismatch"));

        let trailing_path = temp.path().join("trailing-head.stream");
        let mut encoded = alloy_rlp::encode(header.clone());
        encoded.push(0);
        std::fs::write(
            &trailing_path,
            format!("H 42 {hash:#x} {}\n", hex::encode(encoded)),
        )?;
        let error = read_head_header(&trailing_path).unwrap_err();
        assert!(error.to_string().contains("trailing bytes"));

        let invalid_body_path = temp.path().join("invalid-body.stream");
        std::fs::write(
            &invalid_body_path,
            format!(
                "H 42 {hash:#x} {}\nB 42 80\n",
                hex::encode(alloy_rlp::encode(header))
            ),
        )?;
        let error = read_head_header(&invalid_body_path).unwrap_err();
        assert!(error.to_string().contains("invalid B RLP"));
        Ok(())
    }

    #[test]
    fn snapshot_identity_binds_export_header_and_state_root() {
        let head = canonical_test_head();
        assert_eq!(
            validate_snapshot_identity(arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT, &head,)
                .unwrap(),
            SnapshotPreimagePolicy::CanonicalGenesisRequired
        );

        let wrong_number = (head.0 + 1, head.1, head.2.clone());
        assert!(
            validate_snapshot_identity(
                arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT,
                &wrong_number,
            )
            .is_err()
        );

        let mut wrong_root_header = head.2.clone();
        wrong_root_header.state_root = B256::ZERO;
        assert!(
            validate_snapshot_identity(
                arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT,
                &(head.0, head.1, wrong_root_header),
            )
            .is_err()
        );
        assert!(validate_snapshot_identity(B256::ZERO, &head).is_err());

        let mut alternate_header = head.2.clone();
        alternate_header.timestamp += 1;
        let alternate = (head.0, alternate_header.hash_slow(), alternate_header);
        let error = validate_snapshot_identity(
            arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT,
            &alternate,
        )
        .unwrap_err();
        assert!(error.to_string().contains("pre-ArbOS 20 snapshot"));

        let mut post_arbos_twenty = Header {
            number: 500_000_000,
            state_root: b256!("1111111111111111111111111111111111111111111111111111111111111111"),
            ..Default::default()
        };
        ArbHeaderInfo {
            arbos_format_version: 20,
            ..Default::default()
        }
        .update_header(&mut post_arbos_twenty);
        let post_arbos_twenty = (
            post_arbos_twenty.number,
            post_arbos_twenty.hash_slow(),
            post_arbos_twenty,
        );
        assert_eq!(
            validate_snapshot_identity(post_arbos_twenty.2.state_root, &post_arbos_twenty).unwrap(),
            SnapshotPreimagePolicy::NotRequired
        );
    }

    #[test]
    fn new_snapshot_format_requires_a_matching_completion_manifest() -> eyre::Result<()> {
        let temp = tempfile::tempdir()?;
        let preimage_path = temp.path().join("db/preimage");
        std::fs::create_dir_all(&preimage_path)?;
        drop(SlotPreimages::open(&preimage_path)?);
        write_preimage_manifest(&preimage_path, canonical_test_manifest())?;
        let head = canonical_test_head();

        let error = validate_snapshot_import_for_launch(temp.path(), &head).unwrap_err();
        assert!(error.to_string().contains("snapshot import is incomplete"));

        write_snapshot_import_manifest(temp.path(), &head)?;
        validate_snapshot_import_for_launch(temp.path(), &head)?;

        let mut altered_header = head.2.clone();
        altered_header.timestamp += 1;
        let altered = (head.0, altered_header.hash_slow(), altered_header);
        assert!(validate_snapshot_import_for_launch(temp.path(), &altered).is_err());

        let post_temp = tempfile::tempdir()?;
        let mut post_header = Header {
            number: 500_000_000,
            state_root: b256!("2222222222222222222222222222222222222222222222222222222222222222"),
            ..Default::default()
        };
        ArbHeaderInfo {
            arbos_format_version: 20,
            ..Default::default()
        }
        .update_header(&mut post_header);
        let post_head = (post_header.number, post_header.hash_slow(), post_header);
        write_snapshot_import_manifest(post_temp.path(), &post_head)?;
        validate_snapshot_import_for_launch(post_temp.path(), &post_head)?;
        Ok(())
    }

    #[test]
    fn invalid_snapshot_identity_does_not_create_database() -> eyre::Result<()> {
        let temp = tempfile::tempdir()?;
        let out = temp.path().join("out");
        let preimage_path = out.join("db/preimage");
        std::fs::create_dir_all(&preimage_path)?;
        drop(SlotPreimages::open(&preimage_path)?);
        write_preimage_manifest(&preimage_path, canonical_test_manifest())?;

        let mut header = Header {
            number: arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_NUMBER + 1,
            state_root: arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT,
            ..Default::default()
        };
        ArbHeaderInfo {
            arbos_format_version: 19,
            ..Default::default()
        }
        .update_header(&mut header);
        let blocks = temp.path().join("head.stream");
        std::fs::write(
            &blocks,
            format!(
                "H {} {:#x} {}\n",
                header.number,
                header.hash_slow(),
                hex::encode(alloy_rlp::encode(header.clone())),
            ),
        )?;

        let error = import(SnapshotImportArgs {
            state: temp.path().join("unused-state.stream"),
            out: out.clone(),
            expect: format!("{:#x}", arb_reth_genesis::arbitrum_one::GENESIS_STATE_ROOT),
            blocks,
            chain_info: None,
            genesis_json: None,
        })
        .unwrap_err();
        assert!(error.to_string().contains("pre-ArbOS 20 snapshot"));
        assert!(!out.join("db/mdbx.dat").exists());
        assert!(!out.join("static_files").exists());
        assert!(!out.join("rocksdb").exists());
        Ok(())
    }

    fn canonical_test_manifest() -> SlotPreimageManifest {
        SlotPreimageManifest::new(
            arb_reth_genesis::preimages::SlotPreimageStats {
                next_block_number: arb_reth_genesis::arbitrum_one::GENESIS_BLOCK_NUMBER,
                classic_accounts: 1_294_583,
                classic_slots: 24_491_013,
                arbos_accounts: 15,
                arbos_slots: 1_410_458,
                address_table_entries: 680_046,
                retryables: 16_206,
            },
            18_784_532,
        )
        .unwrap()
    }

    fn canonical_test_head() -> (u64, B256, Header) {
        let line = include_str!("../../tests/fixtures/arb1_nitro_genesis_head.stream")
            .lines()
            .next()
            .unwrap();
        parse_header_record(line, 1).unwrap().unwrap()
    }

    #[test]
    fn snapshot_history_boundaries_preserve_imported_state_during_rocks_ahead_window()
    -> eyre::Result<()> {
        const SNAPSHOT_HEAD: u64 = 22_207_817;
        let address = address!("0000000000000000000000000000000000001234");
        let storage_key = b256!("0000000000000000000000000000000000000000000000000000000000000042");
        let account = Account {
            nonce: 7,
            balance: U256::from(123_456u64),
            bytecode_hash: None,
        };
        let storage_value = U256::from(987_654u64);

        let temp = tempfile::tempdir()?;
        let db = init_db(
            temp.path().join("db"),
            DatabaseArguments::new(ClientVersion::default()),
        )?;
        let static_files = StaticFileProvider::read_write(temp.path().join("static_files"))?;
        let rocksdb = RocksDBProvider::builder(temp.path().join("rocksdb"))
            .with_default_tables()
            .build()
            .map_err(|error| eyre::eyre!("RocksDB open error: {error}"))?;
        let factory: ProviderFactory<ArbNodeTypesWithDB> = ProviderFactory::new(
            db,
            Arc::new(MAINNET.as_ref().clone()),
            static_files,
            rocksdb.clone(),
            Runtime::test(),
        )?;
        factory.set_storage_settings_cache(StorageSettings::v2());

        // Model an imported snapshot account and storage slot. The Finish checkpoint is one block
        // ahead of the snapshot so requesting SNAPSHOT_HEAD takes the historical-provider path.
        {
            let provider = factory.database_provider_rw()?;
            provider.write_storage_settings(StorageSettings::v2())?;
            provider
                .tx_ref()
                .put::<tables::HashedAccounts>(keccak256(address), account)?;
            let mut storage = provider
                .tx_ref()
                .cursor_dup_write::<tables::HashedStorages>()?;
            storage.upsert(
                keccak256(address),
                &StorageEntry {
                    key: keccak256(storage_key),
                    value: storage_value,
                },
            )?;
            provider
                .save_stage_checkpoint(StageId::Finish, StageCheckpoint::new(SNAPSHOT_HEAD + 1))?;
            provider.commit()?;
        }

        // Model the normal storage-v2 commit window: RocksDB history for the next block is visible
        // while the companion MDBX snapshot still reports the previous visible tip.
        rocksdb.put::<tables::AccountsHistory>(
            ShardedKey::new(address, u64::MAX),
            &BlockNumberList::new([SNAPSHOT_HEAD + 2]).expect("valid history list"),
        )?;
        rocksdb.put::<tables::StoragesHistory>(
            StorageShardedKey::new(address, storage_key, u64::MAX),
            &BlockNumberList::new([SNAPSHOT_HEAD + 2]).expect("valid history list"),
        )?;

        // Without a snapshot boundary, Reth interprets the first history entry as the account and
        // slot not existing yet, even though both are present in the imported hashed state.
        let state = factory
            .provider()?
            .try_into_history_at_block(SNAPSHOT_HEAD)?;
        assert_eq!(state.basic_account(&address)?, None);
        assert_eq!(state.storage(address, storage_key)?, None);

        {
            let provider = factory.database_provider_rw()?;
            write_snapshot_history_boundaries(&provider, SNAPSHOT_HEAD)?;
            provider.commit()?;
        }

        for segment in [PruneSegment::AccountHistory, PruneSegment::StorageHistory] {
            let checkpoint = factory
                .provider()?
                .get_prune_checkpoint(segment)?
                .expect("snapshot history checkpoint");
            assert_eq!(checkpoint.block_number, Some(SNAPSHOT_HEAD));
            assert_eq!(checkpoint.prune_mode, PruneMode::Before(SNAPSHOT_HEAD + 1));
        }

        // The boundary changes an ambiguous no-history result into a fallback to the imported
        // hashed state, preserving both the account and storage value during the same skew window.
        let state = factory
            .provider()?
            .try_into_history_at_block(SNAPSHOT_HEAD)?;
        assert_eq!(state.basic_account(&address)?, Some(account));
        assert_eq!(state.storage(address, storage_key)?, Some(storage_value));

        Ok(())
    }
}
