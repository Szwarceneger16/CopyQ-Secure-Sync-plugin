# Public transport fixtures (not user data)

These files were generated from `copyq-secure-sync-v0.1.1.zip`, specifically
`copyq_secure_sync/protocol.py`, using its `encrypt()` and `canonical()` functions.
The original `decrypt()` also verified each generated fixture.

- Archive SHA-256: `59576f2629597b158699998f8f311dc8d9aa8d5865c5182a2abba8ea72299fb6`
- protocol.py SHA-256: `951071968dfcf2a10f6cc2c6ca8b6d212f22a4bcf55ca5d302267b6439cb13ae`
- TEST key: byte values 0 through 31, in order.
- TEST nonce: byte values 0 through 11, in order (fixed ONLY for fixtures).
- JSON bytes: `canonical(encrypt(key, header, items))` followed by one LF.

**Never use this known key or these fixed nonces for real encryption. Never
copy these synthetic events into a user's synchronization history.** Reusing
a GCM nonce with a real key is unsafe. No production writer uses this generator.

The root contains base64 of ASCII `SYNC_TEST_001`. Its child is an empty
snapshot and references `mint-lab/000000000001`. The independent binary root
contains base64 of `bytes(range(256))`, UTF-8 `Zażółć gęślą jaźń\r\n🙂\0`,
and an empty byte string. They are opaque transport data, not guaranteed Qt
`pack()` encodings. This distinguishes transport tests from CopyQ integration.

The normal C++ test script reads these frozen files, so it needs no Python.

## SHA-256 of frozen file bytes

- `binary-pc-000000000001.cqs`: `3187bfda4efd263721a97ea4c2a9b619026b077660ef72adc3636e425bcaa90a`
- `mint-lab-000000000001.cqs`: `777bcbec645a604516a991f254905e191d516fbc0a0450309cf0909866120c94`
- `win-lab-000000000001.cqs`: `2a7221940edddd33b69d87a53bdf32c9653205ea377ec54892187ca1b692f1db`
