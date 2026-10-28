// SPDX-License-Identifier: GPL-3.0-or-later
// Evaluated by the selected, already running CopyQ. No directory enumeration,
// settings access, clipboard access, or host/container path translation.
(function () {
    var paths = {}, runtime = {};
    var platform = "unsupported";
    if (str(info("OS")).indexOf("Windows") === 0) platform = "windows";
    else {
        // Fixed public kernel metadata. lp64 alone also describes macOS/BSD;
        // never admit a Linux library from pointer layout alone.
        var kernel = new File("/proc/sys/kernel/ostype");
        if (kernel.openReadOnly()) {
            if (str(kernel.read(64)).trim() === "Linux") platform = "linux";
            kernel.close();
        }
    }
    ["exe", "plugins", "config", "data", "state"].forEach(function (name) {
        paths[name] = str(info(name));
    });
    var pluginDirectory = new Dir(paths.plugins);
    ["FLATPAK_ID", "XDG_DATA_HOME", "XDG_STATE_HOME", "SNAP", "SNAP_NAME", "SNAP_USER_COMMON", "APPIMAGE", "APPDIR", "COPYQ_PLUGINS"].forEach(function (name) {
        runtime[name] = str(env(name));
    });
    // Fixed sandbox metadata, never a search through the host filesystem.
    var metadata = new File("/.flatpak-info");
    if (runtime.FLATPAK_ID && metadata.openReadOnly()) {
        var text = str(metadata.read(65537)); metadata.close();
        if (text.length > 65536) throw new Error("Oversized Flatpak metadata");
        var section = "";
        text.split(/\r?\n/).forEach(function (line) {
            if (/^\[.*\]$/.test(line)) section = line;
            if (section === "[Application]" && line.indexOf("runtime=") === 0) {
                // /.flatpak-info uses a full ref (runtime/id/arch/branch),
                // while flatpak info --show-runtime omits its kind prefix.
                var ref = line.slice(8).trim();
                runtime.flatpak_runtime = ref.indexOf("runtime/") === 0 ? ref.slice(8) : ref;
            }
        });
    }
    if (runtime.SNAP) {
        var snapMetadata = new File(runtime.SNAP + "/meta/snap.yaml");
        if (snapMetadata.openReadOnly()) {
            var snapText = str(snapMetadata.read(65537)); snapMetadata.close();
            if (snapText.length > 65536) throw new Error("Oversized Snap metadata");
            snapText.split(/\r?\n/).forEach(function (line) {
                if (line.indexOf("base:") === 0)
                    runtime.snap_base = line.slice(5).trim().replace(/^['\"]|['\"]$/g, "");
            });
        }
    }
    return JSON.stringify({schema: 1, platform: platform, version: str(version()).split("\n")[0],
        qt: str(info("Qt")), arch: str(info("Arch")), compiler: str(info("Compiler")),
        encryption_compiled: str(info("has-encryption")) === "1",
        plugins_directory_readable: pluginDirectory.exists() && pluginDirectory.isReadable(),
        paths: paths, runtime: runtime});
})()
