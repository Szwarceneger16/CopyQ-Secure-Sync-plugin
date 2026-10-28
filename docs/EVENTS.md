# Authenticated v1 event reader

`src/events.{h,cpp}` connects the cryptographic core to `history::Graph` without
starting CopyQ, a Python process, a service or a network request. The code uses
C++17 and the existing crypto/compression interface; it introduces no new
runtime library. This is an internal component, not an installable plugin.

## Data flow and boundary

1. `decode(key, Envelope{expectedId, bytes})` accepts one bounded JSON envelope.
   The expected ID must come from an independently checked file path, not from
   the header being decoded. Input string views must remain valid for the call.
2. Only the exact v1 envelope/header schema is accepted. The revision ID must
   agree with `device` and `seq`, and with `expectedId`. Parent metadata uses
   the same `history::validateRevision()` checks as the graph.
3. The reader reconstructs Python v1's canonical header and AES-GCM additional
   authenticated data (AAD), including the NUL after
   `CopyQ-Secure-Sync-event-v1`. The nonce is 12 bytes, K-SYNC is 32 bytes, and
   the ciphertext includes its 16-byte authentication tag.
4. Authentication MUST succeed before any decompression or payload decoding.
   Modified headers, keys, nonces, ciphertext or tags fail closed.
5. Bounded zlib decompression rejects truncated, concatenated and trailing
   compressed data. Payload keys must be exactly `items`, `tab`, `v`; v1 fixes
   the transport tab name to `synced_tray` and version to the integer `1`.
6. Items remain opaque, canonical base64 strings. Empty snapshots are valid.
   Binary bytes and Unicode text inside base64 are not interpreted or normalized.
   A valid event is NOT proof that a CopyQ item is semantically safe to import.
7. `AuthenticatedHistory` first decodes all input envelopes and only then
   constructs the graph. It exposes const views, never a partially accepted
   history. A malformed event cannot be silently skipped to fabricate one tip.
   Missing authenticated parents remain a distinct `history::ErrorCode::MissingParent`
   error; duplicates, cycles and multiple tips retain the graph's behavior.

The reader does not store keys, print payloads, write files, update sync state,
choose conflict winners or invoke callbacks. Error messages are fixed text,
not copies of attacker-controlled JSON or clipboard content. Temporary
compressed/plain byte buffers are cleared on exit from decoding; this is not
an assurance against all memory copies, swap or compromise of the host process.
Returned items are plaintext in memory and must never be logged or exported
unencrypted by a caller.

## JSON and interoperability

The parser is deliberately schema-directed, not a general JSON implementation.
It handles reordered members, JSON whitespace and ASCII JSON escapes, but
rejects duplicate members (also when escaped), unknown/missing fields,
floating point/exponent/boolean sequence values, comments, trailing input,
arbitrary nesting, BOMs and non-ASCII protocol names. v1 has only ASCII field
values; actual clipboard bytes, including UTF-8, travel inside base64.

Base64 requires the standard alphabet, padding and zero pad bits. This is
stricter than Python's permissive decoding of some noncanonical pad bits,
but accepts the canonical output produced by Secure Sync 0.1.1. Ambiguous or
manually rewritten noncanonical events are rejected, not repaired.

The three frozen fixtures were generated with the original Python 0.1.1
implementation and a PUBLIC TEST KEY. See [fixture provenance](../tests/fixtures/README.md).
They validate the transport envelope, including empty snapshots and binary
items; they do not test Qt `pack()` equivalence or real CopyQ imports.

## Limits

`Limits` defaults to v1 ceilings and accepts only equal or smaller budgets:

| Resource | Ceiling |
| --- | --- |
| One wire envelope | 25 MiB |
| One decompressed payload | 32 MiB |
| Items in one snapshot | 10,000 |
| Events in one history | 1,000 |
| Total wire bytes | 256 MiB |
| Total decompressed JSON bytes | 256 MiB |

The final limit deliberately counts the full decompressed JSON, not just
base64 characters (more conservative than the Python prototype). The remaining
history budget constrains decompression of the next event, before retaining its
items. These are protocol byte limits, not an RSS cap; inputs, JSON strings and
containers also occupy memory. The future runtime must enforce its own resource
budget. Smaller caller limits are useful for constrained hosts and boundary tests.

## Stream and filesystem contract

`read(key, expectedId, istream)` consumes a finite, already-open binary stream
with an extra-byte oversize check. It handles normal EOF with or without stream
exceptions and rejects I/O failures. It does NOT open or enumerate paths.

The next filesystem adapter must provide bounded, race-resistant directory
scanning: reject symlinks/reparse points and special files before opening,
validate identities and conflict copies, detect concurrent mutation, enforce
aggregate scan budgets and never follow untrusted paths from JSON. Do not
mistake a generic `std::ifstream(path)` call for that hardened adapter.

This module also does not prove freshness: a server can replay an old valid
history or withhold files. Retained local heads, anti-rollback/equivocation
checks, immutable publication and recovery belong in subsequent layers.

## Offline verification

```bash
./tests/run-events.sh
CXX=clang++ ./tests/run-events.sh
CXX=clang++ SANITIZE=1 ./tests/run-events.sh
./tests/run-crypto.sh
./tests/run-history.sh
```

The script builds in a temporary directory and tests only synthetic fixtures.
No real K-SYNC, CopyQ profile or Nextcloud folder is accessed. The C++ tests cover
52 base scenarios plus stream exception/chunk boundaries, the production item
count boundary, and 10,000 mutations of a valid envelope. A separate 10,000
random malformed-input corpus is also exercised. Both corpora are deterministic
smoke fuzz tests, not exhaustive fuzzing or an independent security audit.

Windows CNG builds and live CopyQ/Flatpak integration remain untested by this
Linux script. No workflow, self-hosted runner, release or installation is created.

## Background references

- JSON member interoperability and implementation limits:
  <https://www.rfc-editor.org/rfc/rfc8259.html> (sections 4, 9).
- OpenSSL AEAD authentication contract:
  <https://docs.openssl.org/3.3/man3/EVP_EncryptInit/#aead-interface>.
- zlib stream completion and input accounting:
  <https://www.zlib.net/manual.html>.
