# Standalone CopyQ 17 storage experiment

The product must be installable into an existing CopyQ 17 application without
patching or rebuilding CopyQ. `securesynclab` is a separate, opt-in DLL/SO which
tests that requirement through the existing `ItemLoaderInterface` and
`ItemSaverInterface`. It does not depend on the old `host/` extension, Synchronize,
a Python runtime or a service. Python below is only the integration test driver.

At the time of this experiment, the normal module only provided configuration/
inspection. The current `securesync` is the full native synchronization module;
see [the release contract](RELEASING.md). `securesynclab` remains an opt-in test
experiment and is excluded from ordinary product ZIPs. It never silently
migrates profiles or enables synchronization.

The main module now has its own opt-in storage path: see
[standalone storage](STANDALONE-STORAGE.md). This page retains the original lab contract.

## Storage and recovery contract

Only the reserved `cqs-standalone-lab` tab is claimed, and only when the explicit
laboratory environment below is present. An existing private directory and
strictly private 32-byte key file are required. Both Linux and Windows use the
already tested handle-based `FileStore` backend, with a dedicated binding and
directory. The laboratory reuses the checkpoint record codec for locally
numbered snapshots; these checkpoints are not published synchronization events
or the production Importer's accepted remote head.

The saver captures bounded effective MIME bytes, writes the encrypted private
checkpoint atomically under a lease, reloads/authenticates it and compares its
content. Only then does it write a 16-byte cache marker to the QIODevice supplied
by CopyQ. CopyQ still owns that device's later flush/commit. The experiment never
commits a borrowed QSaveFile or claims to confirm CopyQ's final cache write.

On restart, standard `loadItems()` reads the newest private snapshot. An older
cache marker is recoverable. If the tab file is absent, `initializeTab()` can
restore existing private data without resetting it. A cache generation newer
than private state is refused, as are a wrong key, damaged/missing private state,
an unsupported model/value or a smaller capacity that would crop saved items.
Disable/unavailable-key failures do not fall back to saving plaintext content.

The explicit `CQS_LAB_CREATE=1` switch provisions an empty laboratory record and
must be used only for initial disposable setup. Subsequent launches use `0`.
Saving and loading an existing cache never initialize a missing record.

Bounds are 200 items and 2 MiB of effective MIME bytes. File I/O/key loading occur
in a short-lived C++ worker, but the synchronous saver waits for it. Production
GUI scheduling, latency, cancellation and lifecycle behavior still need design.
The prototype has no network/cloud worker, key rotation, migration or conflict UI.

## Build only the experiment, without a patched host

Use the clean pinned CopyQ 17 API checkout and a matching Qt SDK:

```sh
cmake -S . -B work/standalone -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DCQS_BUILD_STANDALONE_LAB=ON \
  -DCQS_TEST_LEGACY_HOST_BRIDGE=OFF \
  -DCOPYQ_SOURCE_DIR=/path/to/clean/CopyQ17 -DCMAKE_PREFIX_PATH=/path/to/Qt
cmake --build work/standalone --parallel 2
ctest --test-dir work/standalone --output-on-failure
```

This uses CopyQ headers/support sources to build the external module and model
fixtures. It does not build or modify the CopyQ application. The legacy bridge
suite remains separately available for historical regression coverage; it is
not a product installation requirement. The laboratory is off by default and
is excluded from the ordinary main-module product ZIP. CI explicitly
builds it and requires `native-standalone-lab` on both operating systems.

## Actual CopyQ process test

With an existing CopyQ 17 executable and a running X11/Wayland session:

```sh
python3 tests/run-standalone-copyq.py --storage lab \
  --copyq /path/to/existing/copyq \
  --plugin /path/to/libsecuresynclab.so \
  --out work/standalone-session
```

The driver creates a unique disposable session, isolated configuration/data
directories, a public synthetic key and a test-only tab. It sets `COPYQ_PLUGINS`
to the separate module and sets save delays to zero only in that fixture.
Stock CopyQ otherwise delays saves after add/modify by five minutes; production
sync must schedule its own checkpoints and cannot use that timer as an import
confirmation. The driver checks binary MIME/order, normal restart, SIGKILL
followed by a deliberately stale host cache, missing host cache, and an ordinary
tab served by CopyQ's default saver. `result.json` and the scoped process log
remain after the fixture is deleted. The native driver additionally terminates
a child exactly after our private commit, during the borrowed-device write.

CopyQ 17 discovers plugins once per process startup. Installing the library
does not require recompilation; restarting the application loads it. Live
replacement of a running plugin is not supported by the standard loader.

The full driver passed five checks in the official CopyQ 17.0.0 x86_64 AppImage,
using Qt 6.11.1, Xvfb/openbox and an isolated Ubuntu 26.04 container. The release
asset SHA256 was verified as
`b63fb78eed3300af61ce2db7bf537bf12160ef86c7122147fc1c3cceb826c0d1`.
Neither the AppImage nor its executable was patched/recompiled. The laboratory
module was built separately with Qt 6.10.3. This certifies that tested native
combination, not every CopyQ 17 package or a Flatpak installation.

## Flatpak

The current Flathub manifest selects CopyQ 17's pinned source and KDE Platform/
SDK **6.10**. Build a dedicated module against that SDK and test it inside the
actual sandbox. A native Ubuntu artifact is not automatically a Flatpak artifact.
The application path under `/app` is read-only; `COPYQ_PLUGINS` can point to an
additional module in a sandbox-visible user directory.

The same driver can use the fixture-only launcher:

```sh
python3 tests/run-standalone-copyq.py --storage lab \
  --copyq tests/flatpak-lab-wrapper.sh \
  --plugin /path/to/flatpak-sdk-build/libsecuresynclab.so \
  --out work/flatpak-session
```

The launcher supplies per-launch environment and access to only the disposable
fixture and module directory; it creates no persistent Flatpak override. The
app/runtime must already be installed and user namespaces must work. The cloud
validation environment has no installed Flatpak runtime and `bubblewrap`
reports that unprivileged user namespaces are unavailable. Flathub hosts are
also outside the current network allowlist. A real Flatpak result remains blocked;
native loader/model tests are not a substitute.

Manifest reference: <https://github.com/flathub/com.github.hluk.copyq/blob/master/com.github.hluk.copyq.yaml>.

## Encryption compatibility is still a gate

The laboratory uses its own fixture key and does not obtain CopyQ's DEK. It
returns `supportsEncryption() == false` because interaction with global Encrypt
Tabs, lock/unlock, password changes, disable/removal and return to default storage
has not yet been certified. It must not be enabled on a real encrypted user
profile. The production design must preserve those behaviors and specify which
key protects the selected tab before any storage migration is offered.

The private snapshot makes restart recovery possible without a host patch. It
does not make the existing import coordinator's host-persistence contract true
automatically: incoming transactions, recovery intents and local edits still
need an integrated atomic record/runtime design and fault tests.
