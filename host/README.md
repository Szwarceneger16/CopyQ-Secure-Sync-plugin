# CopyQ 17 host extension

This directory is a historical, opt-in regression fixture. The current
standalone `securesync` module does not use this extension or require a patched
CopyQ binary; `CQS_TEST_LEGACY_HOST_BRIDGE` only enables its test executable.
The instructions below describe the superseded host-extension experiment.

This extension supplies a real synchronous encrypted save/readback barrier to
the native Secure Sync plugin. Build it into CopyQ; it is not another separately
loaded plugin. It supports native global Encrypt Tabs, leaves the plugin loader
ABI unchanged, and requires no Python runtime or other CopyQ plugin.

Use a clean CopyQ checkout at
`d0c179f75c04974bfe801289ea6e58a1a49535fc` and export to a separate directory:

```sh
python3 host/prepare.py --copyq /path/to/clean/copyq --out /path/to/work/copyq-with-bridge
```

The build helper requires Python 3.12+ for filtered tar extraction. It exports
committed source bytes with executable modes, so Windows CRLF conversion and
untracked local files do not enter the host source export.
The output may be under the plugin checkout, as in Windows CI. Patch application
is isolated from the enclosing repository and inherited Git repository selectors;
every applied hunk is reverse-checked before success is reported. Existing output
is replaced only when it carries the matching export marker.

Build that exported tree with CopyQ's normal platform instructions and matching
Qt 6.10 SDK, with `WITH_QCA_ENCRYPTION=ON`. QCA and its OpenSSL provider must be
available to the host. Build Secure Sync against the original clean pinned
CopyQ API checkout. Its module detects the optional host interface at runtime.
Do not point the plugin's COPYQ_SOURCE_DIR at the modified export: that input
deliberately requires pristine API sources.

For development, `CQS_BUILD_NATIVE_PLUGIN=ON` with `BUILD_TESTING=ON` additionally
requires QCA 2.3.10 with a working encryption provider. CI prepares pinned QCA
and matching Qt Core5Compat. The `native-host-persistence` executable uses real
host encryption and private disposable disk fixtures, and the build compiles
the modified browser/factory/itemstore integration sources. It does not install
or unlock a real profile.

On Windows the verified temporary file owner must be destroyed before calling
`MoveFileExW`: Qt 6.10 `QTemporaryFile::close()` rewinds its file engine but keeps
the native handle open without `FILE_SHARE_DELETE`. Native replacement then
fails with a sharing violation. The mandatory regression tests reproduce that
failure, verify successful replacement after releasing the owner, and retain
the existing precommit, ambiguous-commit and interrupted-recovery checks.

The module still has a configuration/inspection UI. This host capability enables
the transaction adapter; it does not itself provision state, start workers or
activate automatic imports. See the [implementation and failure contract](../docs/COPYQ-PERSISTENCE.md).
