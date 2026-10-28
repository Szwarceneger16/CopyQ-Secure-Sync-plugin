# Revision history: native C++ module

`src/history.h` and `src/history.cpp` implement the metadata graph for the
existing `copyq-secure-sync-v1` protocol. They use only the C++17 standard
library: no Python runtime, Qt object, other CopyQ plugin or new dependency.

This is an incremental native-plugin component, not an installable plugin.
The [event reader](EVENTS.md) now authenticates envelopes before constructing
this graph. The filesystem adapter, CopyQ lifecycle and settings UI remain
pending. No sync is started merely by building these modules.

## Integration contract

1. Read a bounded set of `.cqs` files from the user-selected transport folder.
2. Authenticate each envelope with K-SYNC and validate its payload. Never build
   a trusted graph directly from an unverified JSON header. Check that the
   filename's ID matches the authenticated header and reject duplicate IDs.
3. Convert that metadata to `Revision{id, device, sequence, parents}` and
   construct a `Graph`. The graph stores no payload or key and does not open,
   modify, delete or publish any file.
4. On `MissingParent`, defer the operation without changing the local head or
   CopyQ data. Nextcloud can deliver a child before a required parent. This
   outcome does not authorize reseeding, accepting a different head or
   permanently discarding the missing ancestor.
5. Other validation errors also block the import, but are not silently treated
   as a temporary delivery delay. Known cycles and malformed metadata are
   rejected even when other references are missing.
6. `tips()` returns every unreferenced revision in deterministic ASCII order.
   `hasConflict()` means there are multiple tips, including independent seeds.
   The graph never picks a winner based on file time or the larger sequence.
   A merge is an explicit, authenticated revision with two sorted parents;
   constructing the graph does not create one.
7. `isAncestor(old, new)` is true for equal IDs only when the ID exists. A
   persisted local head missing from the history is not permission to import.
   `nextSequence(device)` computes a number only; it does not reserve it.
   The later filesystem adapter must enforce exclusive publication, durable
   writes and no-overwrite semantics, and retain rollback/equivocation checks.

## Validation and limits

- Device IDs follow `[a-z][a-z0-9-]{2,31}`.
- Revision IDs are `device/` plus exactly 12 decimal digits. Zero is invalid.
- The sequence is between 1 and 999999999999, inclusive. Exhaustion is an error.
- ID, device and sequence must agree; duplicate IDs are rejected even when
  their metadata is identical.
- Each revision has at most two unique, sorted parents and no self reference.
- A parent from the same device must have a smaller sequence.
- Missing parent files are distinguished from cycles or malformed history.
- At most 1000 revisions are accepted, matching the existing v1 event limit.
- Cycle detection and ancestry traversal are iterative, not recursive.

These checks are deliberately independent of `pack()` byte equality. Item
content normalization and comparison belong in the CopyQ bridge. A valid graph
alone proves neither successful import nor semantic equality of item contents.

`validateRevision()` exposes the same structural checks for one event header
without requiring its parents to have arrived. It does not authenticate data.

## Offline tests

```bash
./tests/run-history.sh
CXX=clang++ ./tests/run-history.sh
./tests/run-crypto.sh
./tests/run-events.sh
```

The history script uses an isolated temporary output directory, cleans it on
exit and builds with `-DNDEBUG` while retaining all test checks. It uses no
network or real user profiles. Tests cover empty history, ordered and shuffled
chains, branches and explicit merges, independent seeds, missing parents,
invalid IDs, cycles, maximum history length, sequence exhaustion and unknown
ancestry. An independent reachability oracle checks 100 deterministic random
DAGs, including shuffled input and comparison of every node pair.

The module is standard C++17 and intended for both Linux and Windows. Windows
MSVC/CNG integration and a real CopyQ load test remain separate checks; Linux
compiler results must not be presented as Windows runtime validation.
