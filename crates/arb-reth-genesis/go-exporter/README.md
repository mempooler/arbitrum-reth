# reth-export (Go)

Streams a Nitro geth pebble DB (path-scheme state + ancient freezer) → line-oriented
`A`/`C`/`S` (state) and `H`/`B`/`R` (blocks) records consumed by `arb-snapshot-import`.

`reth-export.go` is a **copy for version control**, the `nitro/` checkout in this
workspace is not a git repo. Build/run it from the Nitro module so it links the geth fork:

```
cp reth-export.go <nitro>/cmd/reth-export/main.go   # if not already there
cd <nitro> && go build -o reth-export-bin ./cmd/reth-export/
./reth-export-bin --mode state   <l2chaindata-dir>   # A/C/S stream
./reth-export-bin --mode blocks  <l2chaindata-dir>   # H/B/R stream (--from/--to)
```

## `--rewind N`

    ./reth-export-bin --mode state --rewind 512 <l2chaindata-dir>

For:

    reth-export: open state at head root: missing trie node <root> (path )
    state 0x<root> is not available, not found

The empty `(path )` means the **root node itself** is absent, so this is a state that was
never written rather than a damaged trie. A geth database in hash scheme does not commit a
state root every block — trie nodes accumulate in the dirty cache and are flushed periodically
and on a clean shutdown — and Nitro widens that window further through
`--execution.caching.block-count` and its `*-skip-state-saving` settings. A snapshot taken
from a running node therefore routinely carries a head block whose state is not on disk.

Nitro itself never trips over this: it rewinds to the last available state on startup.
`--rewind N` is that same recovery, walking back at most `N` blocks to the newest one whose
state opens.

It is **off by default and reports loudly**, because rewinding changes which block the export
describes. It moves the head rather than only the state: `--mode blocks` defaults its range to
the head, so rewinding both together is what keeps a state stream and a blocks stream
describing the same block. Pass the same `--rewind` to both modes and they agree; the tool
prints the block and root to pass to `snapshot import --expect`.

If it reports no committed state within `N`, the snapshot was probably taken from a node that
was not stopped cleanly. Restoring it into Nitro and stopping that gracefully commits the head
state and removes the need for this flag.
