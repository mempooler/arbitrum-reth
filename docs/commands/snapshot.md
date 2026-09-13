# `arb-reth snapshot`

Snapshot tools convert an Arbitrum One Nitro snapshot into a Storage V2 reth datadir and inspect its hashed state.

The required inputs depend on the ArbOS version encoded in the snapshot-head header:

- The canonical Nitro-genesis snapshot predates ArbOS 20 and requires the Classic Export preimage workflow below.
- ArbOS 20 and newer snapshots can be imported directly from the Nitro state and block streams. Legacy destructive storage wipes are no longer possible, so inherited snapshot slots do not need plaintext preimages for forward sync.
- Other pre-ArbOS 20 snapshots are rejected for now. Supporting one safely requires a complete plaintext slot-preimage set for that exact snapshot.

## Import workflow

The Nitro-genesis conversion needs both official source snapshots:

- The [Arbitrum One Classic Export](https://snapshot-explorer.arbitrum.io/?chain=Arbitrum+One&dir=Classic+Export) provides plaintext storage-slot keys.
- The [Nitro genesis Pebble snapshot](https://snapshot.arbitrum.io/arb1/nitro-genesis-pebble-path.tar) provides the canonical hashed state and head header.

Start with a new output directory. The commands below intentionally use the same `--out` path.

### Nitro genesis: build slot preimages

Extract the Classic Export, then point `--classic-state` at the directory containing its `index.json` file:

```sh
arb-reth snapshot build-preimages \
  --classic-state /data/classic-export/state/<block> \
  --out /data/arb1
```

This creates a validated preimage store and completion manifest under `/data/arb1/db/preimage`.

### Export state and the snapshot head

Build the `reth-export` helper from `crates/arb-reth-genesis/go-exporter`, using a Nitro checkout so it links against Nitro's geth fork. Run it against the extracted Nitro genesis database:

```sh
reth-export --mode state /data/nitro/l2chaindata > /data/genesis-state.stream
reth-export --mode blocks /data/nitro/l2chaindata > /data/head-block.stream
```

The default blocks range is the database head, which is the record required by the importer and later by `node --snapshot-head`.

### Import and verify

```sh
arb-reth snapshot import \
  --state /data/genesis-state.stream \
  --blocks /data/head-block.stream \
  --out /data/arb1 \
  --expect 0x7f2bfc4481d02bfcfc606ebb949384ef78d03a0f30a2dc9cccd652eb80926ae1
```

- `--state` is the Nitro state stream to import.
- `--blocks` is required. It supplies the canonical snapshot-head header and stage checkpoints.
- `--expect` is required. The importer verifies the computed root and snapshot identity.
- `--out` must be fresh except for the preimage sidecar created for a Nitro-genesis import.

If an import fails after creating database files, discard the entire output directory and restart from step 1. The importer refuses to continue in a partially written target.

A successful import writes `snapshot-import.json` only after the state root, snapshot head, launch check, and static-file layout all pass. The node refuses to boot a new-format snapshot datadir without this completion manifest.

Use `/data/head-block.stream` with `node --snapshot-head` when starting the converted datadir.

## Whole-chain import

The workflow above produces a datadir holding one block. To keep the chain's block history as well,
export every block and pass the chain's own spec:

```sh
reth-export --mode state --rewind 512 /data/nitro/l2chaindata > /data/state.stream
# --rewind reports the block P it settled on; give that same P to the blocks export.
reth-export --mode blocks --from 0 --to <P> /data/nitro/l2chaindata > /data/blocks.stream

arb-reth snapshot import \
  --state /data/state.stream \
  --blocks /data/blocks.stream \
  --chain-info /data/chaininfo.json \
  --genesis /data/genesis.json \
  --out /data/chain \
  --expect 0x<state root at P>
```

`--chain-info` and `--genesis` are what select this mode, and they are required for it. A head-only
import stands the head header in for a genesis it does not have; once block 0 is really present the
chain spec has to be the chain's own, so `--blocks` carrying more than one block without them is
rejected rather than silently producing a datadir with a false genesis.

`<P>` must be the block `--mode state --rewind N` reported exporting, or the state and the blocks
describe different heads. `--mode blocks` needs no `--rewind` of its own once `--to` names that block
explicitly.

The stream must start at block 0 and be contiguous. reth's static-file segments are indexed by
offset from the segment start rather than by block number, so a gap or a late start would misalign
them silently; both are rejected before anything is written.

What this datadir has that a head-only one does not:

- Every block's header, body and receipts, so historical block and transaction queries work.
- Sender and transaction-lookup indices, built by running reth's own stages over the imported bodies.

What it still does not have is per-block **state** history. A hash-scheme Nitro snapshot records no
per-block state diffs, so there are no changesets to convert and historical *state* queries below the
head are unavailable — the import marks that boundary explicitly. A path-scheme snapshot carries
those diffs in its `ancient/state` freezer; convert one of those with `snapshot import-full`
instead, which turns them into reth changesets.

### Chunked conversion

The blocks stream for a large chain is the biggest thing in the conversion by far — on a 55M-block
Arbitrum chain it runs to roughly 1.5 TB of hex, against ~50 GB for the state stream. When it will
not fit alongside both databases, import it a range at a time instead: `import-blocks` appends to the
datadir, so the stream only has to hold one chunk at a time.

```sh
DIR=/data/chain
P=55813699
SPEC="--chain-info /data/chaininfo.json --genesis /data/genesis.json"

for lo in $(seq 0 5000000 $P); do
  hi=$(( lo + 4999999 )); [ $hi -gt $P ] && hi=$P
  reth-export --mode blocks --from $lo --to $hi /data/nitro/l2chaindata > /data/chunk.stream
  arb-reth snapshot import-blocks --blocks /data/chunk.stream --out $DIR $SPEC
  rm /data/chunk.stream
done

arb-reth snapshot import-state --state /data/state.stream --out $DIR $SPEC \
  --expect 0x<state root at P>
```

Each chunk must start where the datadir left off, and the first must start at block 0. Blocks the
datadir already holds are skipped rather than rejected, so **a chunk that failed part-way can simply
be re-run**: blocks are committed in batches, and the highest header present decides where the next
one resumes. `import-blocks` reports what it skipped.

Until `import-state` runs, the datadir has no completion manifest and the node refuses to boot it, so
a conversion interrupted between chunks cannot be mistaken for a finished database.

The peak disk requirement is the Nitro database plus the reth datadir plus one chunk. The Nitro
database has to stay readable for the whole conversion — the blocks come from its freezer and the
state from its trie — so it cannot be deleted partway to make room.

## Storage V2 preimages

The Nitro state stream contains hashed storage keys, but Storage V2 changesets use plain slot keys. Before ArbOS 20, those plain keys are required to record reversible storage wipes. The canonical Classic Export supplies the complete set for Nitro genesis.

Keep `db/preimage`, including its manifest, with a Nitro-genesis datadir permanently. Include it when moving or backing up the database. It is not temporary conversion data. The node adds newly observed slot preimages while syncing, while the Classic Export supplies the historical set present at genesis.

An ArbOS 20 or newer snapshot does not need this sidecar. The importer still verifies that the supplied state root and snapshot-head header agree before creating the database.

## Read

`snapshot read` opens the converted datadir read-only and queries hashed state using a normal address input.

```sh
arb-reth snapshot read --db /data/arb1 --addr 0x1234...
arb-reth snapshot read --db /data/arb1 --addr 0x1234... --slot 0x0000...
arb-reth snapshot read --db /data/arb1 --addr 0x1234... --list-storage
```

The command prints account data and, when requested, a storage value or the non-zero storage slots for the address.
