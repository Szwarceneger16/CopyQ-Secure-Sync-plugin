# Portable private-record interoperability tests

The encrypted Linux disk Store is implemented in `state_store_linux.cpp`;
[STATE.md](STATE.md) documents its atomic commit, locking and recovery contracts.
This follow-up tests its **portable record codec**, not a second Store, a format
migration, or the real CopyQ clipboard adapter. No production implementation or
record schema is changed by this test batch.

## Why these tests are separate

A roundtrip through our own encoder/decoder can hide a shared layout mistake.
`tests/fixtures/state_record_vectors.h` therefore contains frozen plaintext and
AES-GCM wire vectors independently encoded by the optional Python test oracle.
It uses Python `struct` and the high-level `cryptography` AEAD API, and never
imports, invokes or links the C++ record codec. This is independence of record
encoding, not a claim of an independent cryptographic implementation/audit.

The normal test executable is C++17 and needs no Python, Qt, CopyQ profile,
private key file, transport directory or platform-specific filesystem backend.
CTest registers `state-codec` outside the Linux-only block, so it can exercise
Windows CNG as well as the Linux OpenSSL backend when those targets are built.
The Linux filesystem suite `state` remains separate.

## Covered records and checks

Four frozen vectors represent: an empty unjoined record; a pending first import
with empty original data; a pending Restore with an existing checkpoint and
nonempty backup; and a checkpoint with no pending transaction. They contain
binary bytes, UTF-8 Polish text and an emoji, CRLF, NUL and an empty MIME value.
The packed item fields are synthetic opaque base64, NOT actual CopyQ pack()
encodings. No relationship to real clipboard content is claimed.

The 35 named scenarios check field-by-field decode, exact canonical plaintext
bytes, AES-GCM fixture authentication, fresh encryption and exact byte limits.
They also reject a one-bit change at every byte position and truncation at every
length of each frozen wire fixture, wrong keys, wrong profile binding, a wrong
AAD domain, and a correctly authenticated envelope with inconsistent inner
binding. Large generation values (`2^63 + 5` and `2^64 - 1`) exercise exact
64-bit big-endian encoding without floating-point or platform-word-size loss.

Repeatedly sealing an unchanged record checks 128 sampled nonce values for
accidental reuse. This smoke check does not prove RNG quality or rule out all
collisions. Fixed keys/nonces in the fixtures are PUBLIC TEST MATERIAL ONLY;
never use them in a real profile. Production `seal()` still requests random
nonces; it has no deterministic override for these tests.

## Run without Qt or a live CopyQ installation

```sh
cmake -S . -B build-core -DCQS_BUILD_NATIVE_PLUGIN=OFF -DBUILD_TESTING=ON
cmake --build build-core --config Release --target cqs-state-codec-test
ctest --test-dir build-core -C Release -R '^state-codec$' --output-on-failure
```

There is also an offline Linux shell entry point:

```sh
./tests/run-state-codec.sh
CXX=clang++ ./tests/run-state-codec.sh
CXX=clang++ SANITIZE=1 ./tests/run-state-codec.sh
```

The shell entry point builds in an isolated temporary directory and cleans it
on exit. Its release checks remain active under `-DNDEBUG`; ASan/UBSan builds
use `-O0`. This batch was executed with GCC and Clang on Linux, including
Clang ASan/UBSan. No Windows CNG execution, full native-plugin/CMake build,
physical power-cut test or live CopyQ/Flatpak validation is claimed.

## Optional fixture provenance check

The generator is a developer-only helper, not called by CMake or the normal
suite. Explicit regeneration/checking requires Python with `cryptography`:

```sh
python tests/generate-state-vectors.py --check
# Only when intentionally updating the documented format and expected vectors:
python tests/generate-state-vectors.py --write
```

`--check` compares the entire header without changing it. The fixed test key is
bytes 0 through 31. The four nonces are disjoint 12-byte slices of bytes 0 through
47, in vector order. AAD includes the documented domain's terminating NUL, the
magic `CQSREC01`, and binding `public-state-vector-v1`. Each vector's wire SHA-256
is embedded beside it. Generation was checked with cryptography 46.0.4.

For reverse-direction verification the test binary can explicitly emit a fresh
AEAD encoding of ONLY its fixed public checkpoint. It cannot load a real key or
record path. Pass that hex output to the optional oracle:

```sh
./build-core/cqs-state-codec-test --emit-public-checkpoint > public-checkpoint.hex
python tests/generate-state-vectors.py --verify-cpp public-checkpoint.hex
```

Both the frozen-header check and the reverse C++-to-Python check were executed.
They check format/AEAD interoperability, not disk durability or user-data import.
Primary AEAD contract: https://cryptography.io/en/latest/hazmat/primitives/aead/
