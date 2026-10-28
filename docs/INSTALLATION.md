# Install into the selected CopyQ

Secure Sync is a separate native module for **stock CopyQ 17.0.0, x86_64**.
CopyQ is never patched or replaced by our package. The running GUI discovers
modules only at startup: staging can happen while it runs, activation needs a
restart. Updates must retain private state and the password vault.

## Ask CopyQ, not the user's filesystem

Unzip the matching plugin package into an explicit download directory. Python 3
is needed only for the optional installation helper, never for synchronization.
Start the intended CopyQ session normally, then run one of:

```sh
python3 tools/install.py probe -- /usr/bin/copyq
python3 tools/install.py probe -- /explicit/build/prefix/bin/copyq --session work
python3 tools/install.py probe -- /explicit/CopyQ-17.0.0-x86_64.AppImage
python3 tools/install.py probe -- flatpak run --user com.github.hluk.copyq
python3 tools/install.py probe -- snap run YOUR_INSTALLED_COPYQ_APP
```

Windows uses `python tools/install.py probe -- "D:\CopyQ\copyq.exe"` (or the
explicit executable from the installed CopyQ shortcut). No registry, Program
Files, AppData, home-directory or recursive executable search is performed.
Choose the exact launcher/session; failure to connect does not create a profile.

CopyQ 17 requires a readable plugin directory **before** loading COPYQ_PLUGINS.
The helper conservatively checks exactly the directory reported by info(),
without enumerating it. On split DEB installations, install the matching
`copyq-plugins` package too. Source builds are tested after installation into
their configured prefix; uninstalled build-tree fallback paths not exposed by
info() are not certified by this probe. Staging cannot add missing host support.

The helper evaluates `installation.js` through CopyQ's public scripting API.
`info("exe")`, `info("plugins")`, `info("config")`, `info("data")`,
`info("state")`, version, Qt, compiler and architecture come from that CopyQ.
Operating-system admission also checks Qt's OS information and the fixed public
Linux kernel type; pointer layout alone cannot admit macOS/BSD as Linux.
Flatpak additionally reports its own `FLATPAK_ID` and fixed `/.flatpak-info`
runtime. Snap supplies `SNAP`, its own `meta/snap.yaml` base and **SNAP_USER_COMMON**, which survives snap
revision updates. Paths are in the application's namespace, never guessed or
translated into host paths. The installation report deliberately contains local
paths: inspect it locally; it is separate from the UI's redacted diagnostics.

Suggested private state/vault directories are distinct from the clipboard data,
module directory and Nextcloud transport. Separate CopyQ configuration files
get separate suggestions. These are suggestions only: probing changes no
settings or files and never moves an existing vault or state record.

## Check, stage, restart and verify

Check SHA256SUMS against the downloaded ZIP. Then use its exact checksum:

```sh
python3 tools/install.py stage --package /explicit/plugin.zip --sha256 ZIP_SHA256 -- /usr/bin/copyq
# Same syntax with -- flatpak run --user com.github.hluk.copyq
# or -- snap run YOUR_INSTALLED_COPYQ_APP, or the explicit Windows executable.
```

The helper checks both ZIP/module hashes and actual build ABI metadata before
sending module bytes over stdin to CopyQ. CopyQ writes and reads back a new,
unique module directory in its own writable space. It never overwrites a loaded
DLL/SO, changes plugin settings, activates code, edits launchers/overrides, or
accesses keys/clipboard contents. Interrupted staging leaves an unactivated
file; repeat to a fresh directory. It does not claim power-loss durability for
the staged code. No state/vault transaction is involved.

The result gives `stage.staged_module` and the previous **COPYQ_PLUGINS**.
Stop the selected GUI normally. Add the returned module path to its launch
configuration using CopyQ's supported `COPYQ_PLUGINS` variable (semicolon
separated). Preserve unrelated custom entries; replace the old Secure Sync
entry, and do not load Secure Sync a second time from `info("plugins")`.
For a native Linux installation, an explicit launcher can use:

```sh
env COPYQ_PLUGINS='/the/reported/module/libsecuresync.so' /usr/bin/copyq
```

Use that launcher for future starts/autostart too. On Windows set
`COPYQ_PLUGINS` in the process launcher before starting the selected copyq.exe;
a normal writable CopyQ plugins directory reported by `info("plugins")` is also
supported, with DLL replacement only after the application has exited.
Never copy Linux Qt libraries into Windows or replace CopyQ's Qt libraries.

After restarting, `copyq eval 'plugins.securesync.capability'` (through the same
Flatpak/Snap/session launcher) must return `device-setup/5`. Check Items → Secure
Sync in Preferences. A Qt/OS loader rejection is a failed install: preserve the
previous launcher and data and choose/build the correct plugin package.

## Flatpak

Use only `linux-flatpak-kde6.10-x86_64`, built in KDE SDK 6.10, for the installed
`org.kde.Platform/x86_64/6.10` runtime. The native Ubuntu library is refused.
Use paths returned **inside CopyQ**, including for COPYQ_PLUGINS:

```sh
flatpak override --user --env=COPYQ_PLUGINS='/the/reported/module/libsecuresync.so' com.github.hluk.copyq
flatpak run --user com.github.hluk.copyq
```

An override affects the next process, so exit the old GUI first. The helper's
stdin transfer needs no access to the host download folder inside Flatpak.
The staged library and suggested state/vault paths use **XDG_DATA_HOME supplied
by Flatpak inside CopyQ**. Older Flatpak versions can leave info("state") under
an ephemeral sandbox home even though it is writable; that path must not be
used to infer persistence. No guessed ~/.var/app path or host translation is
used. Separate-process and restart tests verify the library and both suggested
private folders in the provider-supplied persistent space.
Create private state/vault directories there with user-only permissions, or
choose existing private directories visible to the application. Do not move an
existing profile merely because suggestions changed.

For Nextcloud, grant **only the selected local transport folder**, for example:

```sh
flatpak override --user --filesystem='/explicit/Nextcloud/CopyQ-Sync' com.github.hluk.copyq
```

Nextcloud desktop runs on the host and delivers encrypted events to that folder.
No `--filesystem=host` or blanket home grant is needed. A host mount must also
support the plugin's atomic Linux file operations; a document-portal alias or
remote FUSE filesystem is not automatically sufficient. Test inspection and a
two-device Seed/Join cycle before adopting real data. Removing access must pause
sync safely; it must not initialize empty state. Do not expose the private vault
or state to Nextcloud. Record current per-app overrides before changing them;
remove only the grant/variable you added, never reset all application overrides.

## Snap

There is no verified CopyQ 17 Snap Store artifact in this release matrix.
A package called CopyQ with a different version/Qt is **not compatible**.
The helper understands a running matching Snap and stages through CopyQ inside
its sandbox, using SNAP_USER_COMMON rather than revision-specific SNAP_USER_DATA
or a guessed `~/snap` path. Native tests additionally exercise a disposable
strict core24 Snap containing unmodified CopyQ 17 and system Qt 6.4; that fixture
is **not distributed as CopyQ** and does not certify an arbitrary store snap.

Confinement, the snap base, available Qt/QCA and the app's declared interfaces
all matter. The separately built system-Qt package is the tested fixture target.
Launch configuration must set COPYQ_PLUGINS **inside that snap**, preserving the
snap's command chain; do not invoke a guessed `/snap/.../copyq` from the host.
The snap must allow executable library mapping from its own common data and
access to the selected Nextcloud folder through its declared interfaces. The
fixture separately accesses a host-home transport folder through its home
interface, while keeping state/vault inside its own common data. CopyQ's own
local GUI/CLI socket server requires the snap's network-bind interface.
A missing interface cannot be fixed by a plugin or by inventing a filesystem
permission. Refuse and report that packaging limitation; never use devmode,
classic confinement or a host scan as a workaround. Actual store-snap support
needs a named package/revision and its own successful installed-host test.

## Supported build matrix and separate tests

| Target | CopyQ / Qt | Scope of installed-host test |
| --- | --- | --- |
| Native Linux Ubuntu 24.04 ABI | 17.0.0 / module Qt 6.10.3; official AppImage Qt 6.11.1 | Full GUI, actual Nextcloud desktop delivery, public-path probe |
| Linux Ubuntu 24.04 system Qt | 17.0.0 / distro Qt 6.4.x | Clean stock source install and generated DEB installed by dpkg, separately; full GUI/package lifecycle |
| Windows x64 MSVC | 17.0.0 / module Qt 6.10.3 | Official portable Windows GUI on real NTFS; separate official portable ZIP and setup.exe installations, full GUI/package lifecycle |
| Flatpak x86_64 KDE | 17.0.0 / org.kde.Platform 6.10 | Installed Flathub app, module built inside SDK; full GUI, staging, scoped folder permissions |
| Snap strict core24 fixture | 17.0.0 / system Qt 6.4.x | Separate snapd/AppArmor process test; fixture only, not Store certification |

Only successful reports for the current commit establish the corresponding row.
No arm64, Qt5, MinGW, CopyQ 13/16/18, macOS or all-distro certification is claimed.
Windows requires local fixed NTFS for private state and publication staging.
Native Linux packages target Ubuntu 24.04's glibc 2.39 and GCC 13 libstdc++
baseline (also tested in the newer official AppImage environment), compatible
libcrypto/OpenSSL 3 and zlib. Other/older distributions need a plugin build for
their own SDK/system libraries; a DEB filename alone does not make that ABI
compatible. Linux uses anonymous staging and fsync. Qt Core/Gui/Widgets come
from the host installation. Build
metadata records the **actual** compiled Qt, pointer size, CPU and compiler,
not just the nominal CI toolchain. The helper checks Qt's minor-version loading
rule and rejects unvalidated future minors. Loader/OS dependency verification
is still required; metadata is not a complete dependency resolver or signature.
CopyQ's has-encryption flag reports **compiled** support only. A working QCA
provider and successful encrypted handoff must be tested separately; the helper
does not call that flag proof of working encryption.

To build for an existing Linux installation, use its matching Qt SDK and the
pinned CopyQ **headers/API sources** at d0c179f75c04974bfe801289ea6e58a1a49535fc:

```sh
cmake -S . -B build -DCQS_BUILD_NATIVE_PLUGIN=ON -DBUILD_TESTING=OFF \
  -DCOPYQ_SOURCE_DIR=/explicit/clean/CopyQ-17-checkout \
  -DCMAKE_PREFIX_PATH=/explicit/matching/Qt-SDK -DCMAKE_INSTALL_PREFIX=/explicit/stage
cmake --build build --target securesync
cmake --install build
```

This compiles only the separate plugin; users never rebuild CopyQ. Linux's
minimum build Qt is 6.4; Windows remains 6.10 because its path semantics were
validated there. A distro's old CopyQ package must be upgraded independently;
installing the plugin cannot upgrade the host's ABI.

## Update, rollback and removal

Back up encrypted state and vault while the GUI is stopped. Do not clear,
reinitialize or silently migrate either directory to fix a loader problem.
Stage the new matching package into a new path, exit normally, switch only the
Secure Sync launch entry and restart/unlock. Keep the previous library for
recovery, but **schema-6 state cannot be read by older schema modules**: do not
downgrade in place. Same-version package replacement is tested; historical
version-to-version upgrades and every crash boundary remain release gates.

Before disabling/deleting the plugin or removing its launcher variable, run
**Secure Sync: finish encrypted removal** in CopyQ. It requires working stock
Encrypt Tabs and confirms encrypted handoff. Verify normal CopyQ can reopen the
items, then stop it and remove only the staged Secure Sync module/launch entry.
Keep encrypted state/vault backups until recovery is no longer needed. Do not
remove the entire CopyQ/Flatpak/Snap profile or reset unrelated overrides.
See [key lifecycle](KEY-LIFECYCLE.md) and [history compatibility](CONFLICTS-AND-HISTORY.md).

## Versioned packages

`VERSION`, `CHANGELOG.md`, `COMPATIBILITY.json`, dependency notices and both
module/package checksums accompany the main synchronization module. Choose the
matching native, system-Qt or Flatpak ZIP from a verified release or CI run.
See [release provenance and publication](RELEASING.md); a candidate version is
not production certification. The installer remains installation-time tooling,
not a runtime Python synchronization agent.
