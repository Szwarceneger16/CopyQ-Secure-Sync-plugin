#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Official CopyQ GUI process smoke, disposable public keys/data only.

Works on Windows and Linux launchers (including a matching Flatpak). Never
uses a user's session. Windows assigns each server to a kill-on-close Job.
"""
import argparse
import base64
import ctypes
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile
import importlib.util

_helper_spec = importlib.util.spec_from_file_location("cqs_install", Path(__file__).resolve().parents[1] / "tools/install.py")
installation = importlib.util.module_from_spec(_helper_spec)
_helper_spec.loader.exec_module(installation)


class FixtureGroup:
    def __init__(self, process):
        self.process = process
        self.job = None
        if os.name == "nt":
            from ctypes import wintypes as W
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            class Limits(ctypes.Structure):
                _fields_ = [("per_process", ctypes.c_longlong), ("per_job", ctypes.c_longlong),
                    ("flags", W.DWORD), ("min_working", ctypes.c_size_t), ("max_working", ctypes.c_size_t),
                    ("active", W.DWORD), ("affinity", ctypes.c_size_t), ("priority", W.DWORD), ("scheduling", W.DWORD)]
            class IO(ctypes.Structure):
                _fields_ = [(n, ctypes.c_ulonglong) for n in ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]
            class Extended(ctypes.Structure):
                _fields_ = [("basic", Limits), ("io", IO), ("process_memory", ctypes.c_size_t),
                    ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]
            kernel.CreateJobObjectW.restype = W.HANDLE
            kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, W.LPCWSTR]
            kernel.SetInformationJobObject.argtypes = [W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD]
            kernel.AssignProcessToJobObject.argtypes = [W.HANDLE, W.HANDLE]
            kernel.OpenProcess.restype = W.HANDLE
            kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
            kernel.CloseHandle.argtypes = [W.HANDLE]
            self.kernel = kernel
            self.job = kernel.CreateJobObjectW(None, None)
            if not self.job:
                raise ctypes.WinError(ctypes.get_last_error())
            limits = Extended(); limits.basic.flags = 0x2000
            if not kernel.SetInformationJobObject(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                raise ctypes.WinError(ctypes.get_last_error())
            handle = kernel.OpenProcess(0x0101, False, process.pid)  # SET_QUOTA | TERMINATE
            if not handle:
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                if not kernel.AssignProcessToJobObject(self.job, handle):
                    raise ctypes.WinError(ctypes.get_last_error())
            finally:
                kernel.CloseHandle(handle)

    def close(self):
        if self.job:
            self.kernel.CloseHandle(self.job); self.job = None
        elif os.name == "posix":
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        elif self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=15)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--copyq", type=Path, required=True)
    p.add_argument("--plugin", type=Path, required=True)
    p.add_argument("--fixture-tool", type=Path, required=True)
    p.add_argument("--ui-driver", type=Path)
    p.add_argument("--bundled-renderers", action="store_true", help="Exercise audited stock text/image/notes/FakeVim plugins")
    p.add_argument("--nextcloud-fixture", action="store_true", help="Use disposable cqs-nextcloud and actual nextcloudcmd")
    p.add_argument("--package", type=Path, help="Verify/install the generated ZIP, replace it on restart, then complete encrypted removal")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--installation-kind", choices=("native", "source", "deb", "flatpak", "snap", "appimage", "windows"))
    p.add_argument("--private-parent", type=Path, help="Explicit sandbox-provided parent for disposable profiles")
    p.add_argument("--transport-parent", type=Path, help="Explicit host-visible transport parent, separate from sandbox private data")
    a = p.parse_args(); a.out.mkdir(parents=True, exist_ok=True)
    copyq = str(a.copyq.resolve()); plugin = str(a.plugin.resolve())
    report = {"status": "running", "checks": [], "platform": os.name, "installation": a.installation_kind}
    servers = []
    # CopyQ uses the settings path in its AF_UNIX server name. Deep checkout
    # paths exceed Linux's 108-byte sockaddr limit; use a short private root.
    with tempfile.TemporaryDirectory(prefix="cqs-standalone-",
            dir=str(a.private_parent) if a.private_parent else ("/tmp" if os.name == "posix" else None)) as temporary:
        root = Path(temporary).resolve(); transport = (a.transport_parent.resolve() if a.transport_parent else root) / "transport"
        transport.mkdir(mode=0o700); (transport / "events").mkdir(mode=0o700)
        key = root / "public.key"; key.write_bytes(bytes(range(32))); key.chmod(0o600)
        installed = root / "installed"; installed.mkdir(mode=0o700)
        module = installed / Path(plugin).name
        def install_package():
            if not a.package:
                return
            with zipfile.ZipFile(a.package) as package:
                metadata = json.loads(package.read("BUILD-INFO.json"))
                raw = package.read("copyq/plugins/" + Path(plugin).name)
            import hashlib
            if hashlib.sha256(raw).hexdigest() != metadata["binary_sha256"] or raw != Path(plugin).read_bytes():
                raise RuntimeError("Packaged binary/checksum differs from the tested module")
            # A stopped application is required before changing a loaded DLL/SO.
            staged = module.with_suffix(".new"); staged.write_bytes(raw); staged.replace(module)
        install_package()
        cloud = None
        if a.nextcloud_fixture:
            from nextcloud_fixture import NextcloudFixture
            cloud = NextcloudFixture(root, a.out)
        def protect():
            if os.name == "nt":
                subprocess.run([str(a.fixture_tool.resolve()), "--protect-public-copyq-root", str(root)], check=True, capture_output=True)
        class Server:
            def __init__(self, label):
                self.label = label; self.process = None; self.group = None
                self.password = b"public-gui-fixture-password"
                folder_name = {"gui-first":"a", "gui-peer":"b", "gui-migration":"c", "gui-rotation":"d", "gui-successor":"e"}.get(label,label) if a.private_parent else label
                self.folder = root / folder_name; self.folder.mkdir(mode=0o700)
                self.transport = self.folder / "transport" if cloud else transport
                if cloud:
                    self.transport.mkdir(mode=0o700); (self.transport / "events").mkdir(mode=0o700)
                    cloud.servers.append(self)
                for n in ("settings", "items", "runtime", "cache", "private", "vault"):
                    (self.folder / n).mkdir(mode=0o700)
                if os.name == "nt":
                    (self.folder / "publication-staging").mkdir()
                self.env = os.environ.copy()
                # Stock CopyQ embeds both the config directory and session in
                # AF_UNIX names. Snap's provider-reported common root is longer.
                self.env.update({"COPYQ_SESSION_NAME": "cqslab-" + uuid.uuid4().hex[:4 if a.private_parent else 8],
                    "CQS_TEST_PRIVATE_ROOT": str(root),
                    "COPYQ_SETTINGS_PATH": str(self.folder / "settings"), "COPYQ_STATE_PATH": str(self.folder / "settings"),
                    "COPYQ_ITEM_DATA_PATH": str(self.folder / "items"), "XDG_RUNTIME_DIR": str(self.folder / "runtime"),
                    "XDG_CACHE_HOME": str(self.folder / "cache"), "COPYQ_PLUGINS": str(module) if a.package else plugin,
                    "COPYQ_ALLOW_PLUGINS": "__no_bundled_plugin__", "COPYQ_DEFAULT_ICON": "1"})
                if a.bundled_renderers:
                    self.env["COPYQ_ALLOW_PLUGINS"] = ",".join("*" + name + "*" for name in ("itemtext", "itemimage", "itemnotes", "itemfakevim", "itempinned", "itemtags"))
                if a.ui_driver and label in ("gui-first", "gui-migration"):
                    self.env["COPYQ_PLUGINS"] += ";" + str(a.ui_driver.resolve())
                if a.ui_driver and (label == "gui-migration" or (a.package and label == "gui-first")):
                    self.env["CQS_GUI_PUBLIC_PASSWORDS"] = "1"
                if os.name == "nt":
                    self.env["QT_QPA_PLATFORM"] = "windows"
                self.log = (a.out / (label + ".log")).open("w", encoding="utf-8")
                servers.append(self); protect()
            def command(self, *args):
                r = subprocess.run([copyq, *args], env=self.env, capture_output=True, text=True, encoding="utf-8", timeout=20)
                if r.returncode:
                    raise RuntimeError(self.label + ": " + r.stderr.strip())
                return r.stdout.strip()
            def callback(self, name, *args):
                encoded = [json.dumps("securesync"), json.dumps(name)]
                for arg in args:
                    if isinstance(arg, dict):
                        raw = json.dumps(arg).encode()
                        encoded.append("JSON.parse(str(fromBase64(" + json.dumps(base64.b64encode(raw).decode()) + ")))")
                        continue
                    raw = arg if isinstance(arg, bytes) else arg.encode()
                    b = "fromBase64(" + json.dumps(base64.b64encode(raw).decode()) + ")"
                    encoded.append(b if isinstance(arg, bytes) else "str(" + b + ")")
                result = self.command("eval", "callPlugin(" + ",".join(encoded) + ")")
                if result.startswith("Working:"):
                    token = result[8:]; deadline = time.monotonic() + 30
                    while True:
                        result = self.callback("operationStatus", token)
                        if result != "Working": break
                        if time.monotonic() > deadline: raise RuntimeError("Secure Sync operation timed out")
                        time.sleep(0.025)
                if name == "stopAutomaticSync" and result.startswith("Stopping"):
                    deadline = time.monotonic() + 30
                    while self.callback("automaticSyncStatus") == "Working":
                        if time.monotonic() > deadline: raise RuntimeError("Secure Sync stop timed out")
                        time.sleep(0.025)
                    result = "Stopped"
                return result
            def gui(self, name):
                request_id = uuid.uuid4().hex
                temporary = self.folder / "ui-request-new"
                temporary.write_text(request_id + " " + name, encoding="ascii")
                temporary.replace(self.folder / "ui-request")
                end = time.monotonic() + 15
                while time.monotonic() < end:
                    response = self.folder / "ui-response"
                    if response.exists():
                        text = response.read_text(encoding="ascii")
                        if text.startswith(request_id + " "):
                            return text[len(request_id) + 1:]
                    time.sleep(.1)
                raise RuntimeError("Fixture editor driver timed out")
            def start(self, loaded_plugin=True):
                self.process = subprocess.Popen([copyq], env=self.env, stdout=self.log, stderr=self.log, start_new_session=True)
                self.group = FixtureGroup(self.process)
                end = time.monotonic() + 20
                while time.monotonic() < end:
                    try:
                        if self.command("eval", "plugins.securesync.capability" if loaded_plugin else "str(1)") == ("device-setup/5" if loaded_plugin else "1"):
                            return
                    except (RuntimeError, subprocess.TimeoutExpired):
                        if self.process.poll() is not None:
                            break
                    time.sleep(.1)
                raise RuntimeError("Official CopyQ GUI startup failed: " + self.label)
            def stop(self):
                self.command("exit"); self.process.wait(timeout=20); self.group.close(); self.group = None; self.process = None
            def setup(self):
                self.start(); self.command("eval", 'config("check_clipboard",false);'); self.stop()
                files = list((self.folder / "settings").rglob("copyq-" + self.env["COPYQ_SESSION_NAME"] + ".ini")); assert len(files) == 1
                file = files[0]; original = file.read_text(encoding="utf-8")
                options = {"profile_schema": "3", "standalone_storage": "true", "device": self.label,
                    "transport": self.transport.as_posix(), "key_file": key.as_posix(),
                    "state_directory": (self.folder / "private").as_posix(), "vault_directory": (self.folder / "vault").as_posix()}
                if os.name == "nt":
                    options["publication_staging"] = (self.folder / "publication-staging").as_posix()
                entries = "".join("securesync\\" + k + "=" + v + "\n" for k, v in options.items())
                if a.bundled_renderers:
                    entries += "itemtags\\tags=private;;;;;;;;;;L\n"
                file.write_text(original.replace("[Plugins]\n", "[Plugins]\n" + entries, 1) if "[Plugins]\n" in original else original + "\n[Plugins]\n" + entries, encoding="utf-8")
                protect(); self.start(); assert self.callback("initializeStorage", self.password) == "Initialized"
            def wait_head(self, revision):
                end = time.monotonic() + 45
                while time.monotonic() < end:
                    if cloud:
                        cloud.cycle()
                    if self.callback("syncRevision") == revision:
                        return
                    time.sleep(.15)
                raise RuntimeError(self.label + ": " + self.callback("automaticSyncStatus") + "; revision=" + self.callback("syncRevision"))
        try:
            first, peer = Server("gui-first"), Server("gui-peer")
            first.start()
            helper = Path(__file__).resolve().parents[1] / "tools/install.py"
            probe_reply = subprocess.run([sys.executable,str(helper),"probe","--",copyq],env=first.env,capture_output=True,text=True,timeout=60)
            if probe_reply.returncode: raise RuntimeError("Installation probe failed: " + probe_reply.stderr)
            probe_result = json.loads(probe_reply.stdout)
            probe, discovered = probe_result["probe"], probe_result["plan"]
            expected = {"source":"native", "deb":"native", "windows":"native"}.get(a.installation_kind, a.installation_kind)
            if expected:
                assert discovered["environment"] == expected, discovered
            assert Path(probe["paths"]["data"]).as_posix() == (first.folder / "items").as_posix()
            assert Path(probe["paths"]["state"]).as_posix() == (first.folder / "settings").as_posix()
            assert ("cqslab-" in probe["paths"]["config"]), probe
            (a.out / "installation.json").write_text(json.dumps({"probe":probe,"plan":discovered},indent=2),encoding="utf-8")
            report["checks"].append("CopyQ public info paths, version, architecture and sandbox metadata selected the installation without filesystem search")
            if a.package:
                import hashlib
                package_hash = hashlib.sha256(a.package.read_bytes()).hexdigest()
                metadata, name, raw = installation.read_package(a.package, package_hash)
                reply = subprocess.run([sys.executable,str(helper),"stage","--package",str(a.package),"--sha256",package_hash,"--",copyq],env=first.env,capture_output=True,timeout=60)
                if reply.returncode: raise RuntimeError("CopyQ staging failed: " + reply.stderr.decode("utf-8",errors="replace"))
                staged = json.loads(reply.stdout)["stage"]
                assert staged["activated"] is False and staged["restart_required"]
                assert Path(staged["staged_module"]).read_bytes() == raw
                original_plugins = first.env["COPYQ_PLUGINS"]
                first.stop()
                first.env["COPYQ_PLUGINS"] = staged["staged_module"] + (";" + str(a.ui_driver.resolve()) if a.ui_driver else "")
                first.start(); first.stop()
                first.env["COPYQ_PLUGINS"] = original_plugins
                report["checks"].append("CopyQ staged a checksum-verified new module inside its own namespace; unchanged host loaded it on restart")
            else:
                first.stop()
            first.setup(); peer.setup()
            if a.bundled_renderers:
                for server in servers:
                    inventory = server.command("eval", "stats()")
                    for name in ("itemtext", "itemimage", "itemnotes", "itemfakevim", "itempinned", "itemtags"):
                        assert "PLUGIN " + name + ": enabled" in inventory, (name, inventory)
            if a.ui_driver:
                assert first.command("eval", 'callPlugin("cqsuiprobe","armEditorFixture")') == "Queued"
                assert first.command("eval", 'callPlugin("cqsuiprobe","armConflictDecision","Keep both versions")') == "Queued"
                assert first.command("eval", 'callPlugin("cqsuiprobe","disable")') == "Disabled"
            first.command("eval", 'show("fixture-other");show("synced_tray");tab("synced_tray");add("public-first");')
            assert first.callback("checkpointStorage") == "Checkpointed"
            first.command("eval", 'setCurrentTab("fixture-other");hide();')
            assert "synced_tray" in json.loads(first.command("eval", 'JSON.stringify(unload("synced_tray"))'))
            assert first.callback("seedHistory", first.password, first.command("eval", "stats()")) == "Applied"
            if os.name == "nt":
                assert not any((first.folder / "publication-staging").iterdir())
            if cloud:
                cloud.cycle()
            assert peer.callback("joinHistory", peer.password, peer.command("eval", "stats()")) == "Applied"
            peer.command("show", "synced_tray"); first.command("show", "synced_tray")
            assert first.callback("enableAutomaticSync") == peer.callback("enableAutomaticSync") == "Enabled"
            initial = time.monotonic() + 20
            while any(server.callback("automaticSyncStatus") != "UpToDate" for server in (first, peer)):
                if time.monotonic() > initial:
                    raise RuntimeError("Automatic scheduler did not complete its initial reconciliation")
                if cloud:
                    cloud.cycle()
                time.sleep(.1)
            first.command("eval", 'tab("synced_tray");add("public-draft");for(var i=0;i<16;++i)change(0,"text/plain","public-burst-"+i);change(0,"text/plain","public-update");')
            peer.wait_head("gui-first/000000000002")
            assert peer.command("eval", 'tab("synced_tray");str(read("text/plain",0))') == "public-update"
            report["checks"].append("official CopyQ GUI loaded external module and synchronized selected visible tabs")
            # The checkpoint timer and import's model signals must not publish
            # intermediate drafts or echo the accepted version back as a change.
            quiet = time.monotonic() + 3
            while time.monotonic() < quiet:
                if cloud:
                    cloud.cycle()
                revisions = [server.callback("syncRevision") for server in (first, peer)]
                assert all(value in ("Working", "gui-first/000000000002") for value in revisions), revisions
                assert len(list((first.transport / "events").rglob("*.cqs"))) == 2
                time.sleep(.1)
            for server in (first, peer):
                server.wait_head("gui-first/000000000002")
            report["checks"].append("rapid committed edits coalesced into one revision; import and checkpoint notifications produced no echo revisions")
            peer.command("eval", 'tab("synced_tray");add("public-peer");')
            first.wait_head("gui-peer/000000000001")
            assert first.command("eval", 'tab("synced_tray");str(read("text/plain",0))') == "public-peer"
            peer.stop(); peer.start(); assert peer.callback("unlockStorage", peer.password) == "Unlocked"
            peer.command("show", "synced_tray")
            first.command("eval", 'tab("synced_tray");add("public-restart");')
            peer.wait_head("gui-first/000000000003")
            assert peer.command("eval", 'tab("synced_tray");str(read("text/plain",0))') == "public-restart"
            assert len(list((first.transport / "events").rglob("*.cqs"))) == 4
            report["checks"].append("bidirectional publication and automatic restart resumed after unlock without another Start action")
            if a.ui_driver:
                assert first.gui("openEditor") == "Queued"
                end = time.monotonic() + 15
                while first.gui("activeEditors") != "1":
                    if time.monotonic() > end:
                        raise RuntimeError("CopyQ inline editor did not open")
                    time.sleep(.1)
                peer.command("eval", 'tab("synced_tray");add("public-editor-guard");')
                peer.wait_head("gui-peer/000000000002")
                end = time.monotonic() + 15
                while not first.callback("automaticSyncStatus").startswith("Waiting: active editor"):
                    if cloud:
                        cloud.cycle()
                    if time.monotonic() > end:
                        raise RuntimeError("Incoming update was not deferred for the actual editor")
                    time.sleep(.1)
                assert first.callback("syncRevision") == "gui-first/000000000003"
                assert first.gui("activeEditors") == "1"
                end = time.monotonic() + 15
                while first.gui("cancelEditor") != "Queued":
                    if time.monotonic() > end:
                        raise RuntimeError("Could not close the fixture editor normally")
                    time.sleep(.1)
                first.wait_head("gui-peer/000000000002")
                assert first.command("eval", 'tab("synced_tray");str(read("text/plain",0))') == "public-editor-guard"
                report["checks"].append("actual CopyQ inline editor deferred incoming replacement until it was closed normally")
            for server in servers:
                server.callback("stopAutomaticSync")
            if a.ui_driver:
                end = time.monotonic() + 20
                while first.gui("openSecureSettings") != "Ready":
                    if time.monotonic() > end:
                        raise RuntimeError("Secure Sync preferences panel did not open")
                assert first.command("eval", "plugins.securesync.userAction('syncNow-unknown')") == "Refused"
                assert first.gui("panelSync") == "Queued"
                end = time.monotonic() + 20
                while True:
                    diagnostic = json.loads(first.gui("panelDiagnostics"))
                    if not diagnostic["operation_active"]:
                        break
                    if time.monotonic() > end:
                        raise RuntimeError("Preferences synchronization did not finish")
                    time.sleep(.1)
                assert diagnostic["state"] in ("ready", "locked"), (diagnostic, first.callback("automaticSyncStatus"), first.callback("userStatus"))
                assert set(diagnostic) == {"format", "component", "state", "automatic", "locked", "operation_active", "local_save"}
                assert str(root) not in json.dumps(diagnostic) and "gui-first" not in json.dumps(diagnostic)
                assert first.gui("closePreferences") == "Queued"
                report["checks"].append("real preferences sync button completed guarded command; copied diagnostics contain only allowlisted state and flags")
            if a.ui_driver:
                first.command("eval", 'tab("synced_tray");add("public-local-conflict");')
                peer.command("eval", 'tab("synced_tray");add("public-remote-conflict");')
                peer.callback("enableAutomaticSync"); peer.wait_head("gui-peer/000000000003")
                first.callback("enableAutomaticSync")
                end = time.monotonic() + 30
                while not first.callback("automaticSyncStatus").startswith("Conflict"):
                    if cloud:
                        cloud.cycle()
                    if time.monotonic() > end:
                        raise RuntimeError("Expected explicit local/remote conflict")
                    time.sleep(.1)
                assert first.callback("stopAutomaticSync") == "Stopped"
                assert first.command("eval", 'plugins.securesync.resolveConflict()') == "Working"
                end = time.monotonic() + 30
                while True:
                    if cloud:
                        cloud.cycle()
                    values = json.loads(first.command("eval", 'tab("synced_tray");JSON.stringify([str(read("text/plain",0)),str(read("text/plain",6))])'))
                    if values == ["public-local-conflict", "public-remote-conflict"] and first.callback("syncState") == "Joined":
                        break
                    if time.monotonic() > end:
                        raise RuntimeError("Chosen conflict result not projected: " + repr(values))
                    time.sleep(.1)
                resolved = first.callback("syncRevision")
                assert resolved.startswith("gui-first/")
                peer.wait_head(resolved)
                count = len(list((first.transport / "events").rglob("*.cqs")))
                assert count in ((7, 8) if cloud else (7,))
                report["checks"].append("real conflict dialogs explicitly kept both versions and synchronized the result with an encrypted local backup")
            if a.bundled_renderers:
                report["checks"].append("actual bundled text/image/notes/FakeVim/Pinned/Tags loaders remained enabled through publication, import and restart")
            if cloud:
                # Pause delivery of one real client, publish while disconnected,
                # verify its accepted revision stays fixed, then reconnect it.
                peer.callback("stopAutomaticSync")
                first.callback("enableAutomaticSync")
                old = peer.callback("syncRevision")
                previous_count = cloud.verify_ciphertexts()
                previous_local_sequence = int(first.callback("syncRevision").split("/")[1])
                cloud.paused.add(peer.label)
                first.command("eval", 'tab("synced_tray");add("public-offline");')
                expected = "gui-first/%012d" % (previous_local_sequence + 1)
                first.wait_head(expected)
                assert peer.callback("syncRevision") == old
                assert not (peer.transport / "events/gui-first" / (expected.split("/")[1] + ".cqs")).exists()
                cloud.paused.clear(); peer.callback("enableAutomaticSync"); peer.wait_head(expected)
                assert peer.command("eval", 'tab("synced_tray");str(read("text/plain",0))') == "public-offline"
                cloud.cycle(); assert cloud.verify_ciphertexts() == previous_count + 1
                report["checks"].append("actual Nextcloud desktop clients delivered between separate roots, resumed offline delivery and preserved server ciphertext bytes")
            if a.bundled_renderers:
                # Publish protection metadata using stock plugins, then update
                # rows around these anchors while both tabs remain visible.
                for server in servers:
                    server.callback("stopAutomaticSync")
                first.command("eval", 'tab("synced_tray");plugins.itempinned.pin(0);plugins.itempinned.pin(2);plugins.itemtags.tag("private",3);')
                assert first.callback("checkpointStorage")=="Checkpointed"
                first.callback("enableAutomaticSync")
                deadline=time.monotonic()+45
                while first.callback("syncState") != "Joined":
                    if cloud: cloud.cycle()
                    if time.monotonic()>deadline: raise RuntimeError("Protection metadata was not published")
                    time.sleep(.15)
                protected_head=first.callback("syncRevision")
                peer.callback("enableAutomaticSync");peer.wait_head(protected_head)
                protected=peer.command("eval", 'tab("synced_tray");JSON.stringify([str(read("text/plain",0)),str(read("text/plain",3)),str(read("text/plain",2))])')
                assert peer.command("eval", 'tab("synced_tray");plugins.itempinned.isPinned(0)') == "true"
                assert peer.command("eval", 'tab("synced_tray");plugins.itemtags.hasTag("private",3)') == "true"
                previous=int(protected_head.split("/")[1])
                first.command("eval", 'tab("synced_tray");add("public-around-protected");')
                update="gui-first/%012d"%(previous+1);peer.wait_head(update)
                assert peer.command("eval", 'tab("synced_tray");JSON.stringify([str(read("text/plain",0)),str(read("text/plain",4)),str(read("text/plain",2))])') == protected
                assert peer.command("eval", 'tab("synced_tray");plugins.itemtags.hasTag("private",4)') == "true"
                # Release on the publishing device only. The receiving device
                # keeps its protection and must not acknowledge the deletion.
                first.command("eval", 'tab("synced_tray");plugins.itempinned.unpin(0);plugins.itempinned.unpin(2);plugins.itemtags.untag("private",4);remove(4);remove(2);remove(0);')
                deletion="gui-first/%012d"%(previous+2);first.wait_head(deletion)
                deadline=time.monotonic()+45
                while not peer.callback("automaticSyncStatus").startswith("Waiting: pinned or locked tagged"):
                    if cloud: cloud.cycle()
                    if time.monotonic()>deadline: raise RuntimeError("Protected deletion was not deferred: "+peer.callback("automaticSyncStatus"))
                    time.sleep(.15)
                assert peer.callback("syncRevision")==update
                assert peer.command("eval", 'tab("synced_tray");JSON.stringify([str(read("text/plain",0)),str(read("text/plain",4)),str(read("text/plain",2))])') == protected
                report["checks"].append("stock Pinned/locked Tags survived live imports around protected rows; remote deletion stopped before acknowledging the new head")
            for server in servers:
                server.callback("stopAutomaticSync"); server.stop()
            if a.ui_driver:
                migration=Server("gui-migration");migration.setup()
                migration.command("eval", 'config("item_data_threshold",1);tab("synced_tray-before-secure-sync");write(0,"text/plain",Array(8193).join("native-blob-"),"application/octet-stream",fromBase64("AP8NCg=="),"text/html","<b>file</b>");config("encrypt_tabs",true);')
                assert migration.command("eval", 'config("encrypt_tabs")') == "true", "CopyQ native encryption provider is unavailable"
                migration.command("eval", 'setCurrentTab("fixture-other");hide();unload("synced_tray-before-secure-sync");show("synced_tray-before-secure-sync");')
                source=migration.command("eval", 'tab("synced_tray-before-secure-sync");str(toBase64(read("application/x-copyq-item",0)))')
                assert migration.command("eval", 'callPlugin("cqsuiprobe","disable")')=="Disabled"
                blobs=[file for file in (migration.folder/"items").rglob("*.dat") if len(file.stem)==16]
                assert blobs,"Official CopyQ did not materialize native files"
                ciphertext=blobs[0].read_bytes();state=migration.folder/"private/record-v1.cqr";before=state.read_bytes();blobs[0].unlink()
                refused=migration.command("eval", 'plugins.securesync.adoptFromTab()')
                assert refused.startswith("Refused") and state.read_bytes()==before,refused
                blobs[0].write_bytes(ciphertext);protect()
                adopted=migration.command("eval", 'plugins.securesync.adoptFromTab()')
                assert adopted=="AdoptedPreservedTab",adopted
                assert migration.command("eval", 'tab("synced_tray");str(toBase64(read("application/x-copyq-item",0)))')==source
                migration.stop();migration.start();assert migration.callback("unlockStorage",migration.password)=="Unlocked"
                assert migration.command("eval", 'tab("synced_tray");str(toBase64(read("application/x-copyq-item",0)))')==source
                migration.stop()
                report["checks"].append("official core-encrypted native DataFiles migrated with exact large/binary MIME data; missing source refused without commit and restored retry survived restart")
            if not cloud:
                state = first.folder / "private/record-v1.cqr"
                ancestor = first.transport / "events/gui-first/000000000001.cqs"
                original = ancestor.read_bytes(); durable = state.read_bytes()
                first.start()
                if a.ui_driver: assert first.command("eval", 'callPlugin("cqsuiprobe","disable")')=="Disabled"
                assert first.callback("unlockStorage", first.password) == "Unlocked"
                accepted = first.callback("syncRevision")
                first.callback("stopAutomaticSync"); first.stop()
                # Withholding a non-head ancestor is detected after restart;
                # the same accepted head and local data remain durable.
                withheld = first.folder / "withheld.cqs"; ancestor.replace(withheld)
                first.start()
                if a.ui_driver: assert first.command("eval", 'callPlugin("cqsuiprobe","disable")')=="Disabled"
                assert first.callback("unlockStorage", first.password) == "Unlocked"
                assert first.callback("enableAutomaticSync") == "Enabled"
                deadline = time.monotonic()+20
                while not first.callback("automaticSyncStatus").startswith("Waiting"):
                    if time.monotonic()>deadline: raise RuntimeError("Missing witnessed ancestor was not deferred: "+first.callback("automaticSyncStatus"))
                    time.sleep(.1)
                assert first.callback("syncRevision")==accepted and state.read_bytes()==durable
                first.callback("stopAutomaticSync"); first.stop(); withheld.replace(ancestor)
                # This is valid AES-GCM with the PUBLIC fixture key and unchanged
                # ID/parents, so failure must include the durable witness check.
                # The constrained fixture tool only mutates public events under
                # CQS_TEST_PRIVATE_ROOT. Snap deliberately uses a separate host
                # transport. Mutate a private mirror, then deliver its bytes to
                # that explicit synthetic transport as an untrusted peer would.
                with tempfile.TemporaryDirectory(prefix="history-fixture-",dir=root) as history_fixture:
                    mirrored = Path(history_fixture) / "transport" / ancestor.relative_to(first.transport)
                    mirrored.parent.mkdir(parents=True,mode=0o700)
                    mirrored.write_bytes(original)
                    replacement = subprocess.run([str(a.fixture_tool.resolve()), "--replace-public-event", str(mirrored)],env=first.env,capture_output=True,text=True)
                    if replacement.returncode:
                        raise RuntimeError("Public history fixture failed: "+replacement.stderr[-2000:])
                    ancestor.write_bytes(mirrored.read_bytes())
                protect(); first.start()
                if a.ui_driver: assert first.command("eval", 'callPlugin("cqsuiprobe","disable")')=="Disabled"
                assert first.callback("unlockStorage", first.password)=="Unlocked"
                assert first.callback("enableAutomaticSync")=="Enabled"
                deadline=time.monotonic()+20
                while not first.callback("automaticSyncStatus").startswith("Recovery: previously observed history was replaced"):
                    if time.monotonic()>deadline: raise RuntimeError("Authenticated ancestor replacement was not refused: "+first.callback("automaticSyncStatus"))
                    time.sleep(.1)
                assert first.callback("syncRevision")==accepted and state.read_bytes()==durable
                ancestor.write_bytes(original); protect(); time.sleep(1)
                assert first.callback("automaticSyncStatus").startswith("Recovery:")
                assert first.callback("enableAutomaticSync")=="Enabled"
                deadline=time.monotonic()+20
                while first.callback("automaticSyncStatus")!="UpToDate":
                    if time.monotonic()>deadline: raise RuntimeError("Trusted restored history did not resume")
                    time.sleep(.1)
                first.callback("stopAutomaticSync"); first.stop()
                report["checks"].append("restart retained non-head history witnesses; missing ancestor deferred, authenticated replacement paused without data changes, and explicit review resumed trusted history")
            if a.package and not cloud:
                rotation = Server("gui-rotation")
                rotation.transport = (a.transport_parent.resolve() if a.transport_parent else root) / "rotation-transport"
                rotation.transport.mkdir(mode=0o700); (rotation.transport / "events").mkdir(mode=0o700)
                rotation.setup()
                rotation.command("eval", 'show("fixture-other");show("synced_tray");tab("synced_tray");add("first");change(0,"application/octet-stream",fromBase64("AP8B"));add("");')
                def transition_unload(server=rotation):
                    assert server.callback("checkpointStorage") == "Checkpointed"
                    server.command("eval", 'setCurrentTab("fixture-other");hide();')
                    assert "synced_tray" in json.loads(server.command("eval", 'JSON.stringify(unload("synced_tray"))'))
                def packed_snapshot(server=rotation):
                    # Compare ordered MIME bytes, independently of CopyQ's
                    # QHash serialization order and binary pack representation.
                    return server.command("eval", 'tab("synced_tray");var r=[];for(var i=0;i<size();++i){var d=unpack(read("application/x-copyq-item",i));var o={};Object.keys(d).sort().forEach(function(k){o[k]=str(toBase64(d[k]));});r.push(o);}JSON.stringify(r)')
                def destination(label):
                    target = {key: str(root / (label+"-"+key)) for key in ("journal", "state", "vault")}
                    target["transport"] = str((a.transport_parent.resolve() if a.transport_parent else root) / (label+"-transport"))
                    if os.name == "nt": target["staging"] = str(root / (label+"-staging"))
                    for value in target.values(): Path(value).mkdir(mode=0o700)
                    (Path(target["transport"]) / "events").mkdir(mode=0o700)
                    protect(); return target
                original_snapshot = packed_snapshot(); transition_unload()
                assert rotation.callback("seedHistory", rotation.password, rotation.command("eval", "stats()")) == "Applied"
                old_transport = rotation.transport
                old_wire = {str(file.relative_to(old_transport)):file.read_bytes() for file in old_transport.rglob("*.cqs")}
                new = destination("rekey")
                changed = rotation.callback("rotateSyncKey", rotation.password, rotation.command("eval", "stats()"), new)
                assert changed.startswith("HistoryTransitioned") and "journal sealed without keys" in changed, changed
                assert rotation.callback("automaticSyncStatus") != "Working"
                rotation.transport = Path(new["transport"])
                assert rotation.callback("unlockStorage", rotation.password) == "Unlocked"
                actual_snapshot = packed_snapshot()
                assert actual_snapshot == original_snapshot, (original_snapshot, actual_snapshot)
                assert old_wire == {str(file.relative_to(old_transport)):file.read_bytes() for file in old_transport.rglob("*.cqs")}
                assert old_wire.keys() == {str(file.relative_to(rotation.transport)) for file in rotation.transport.rglob("*.cqs")}
                assert all((rotation.transport / name).read_bytes() != value for name,value in old_wire.items())
                rotation.stop(); rotation.start()
                assert rotation.callback("unlockStorage", rotation.password) == "Unlocked"
                actual_snapshot = packed_snapshot()
                assert actual_snapshot == original_snapshot, (original_snapshot, actual_snapshot)
                report["checks"].append("stock CopyQ activated a newly keyed full history, retained source ciphertexts, handed over the cache and reopened exact binary/empty data after restart")
                # A real second GUI process migrates from the old generation
                # using only a password-protected NEW-key transfer. Its offline
                # local edit is retained, not automatically sent over the new root.
                successor = Server("gui-successor"); successor.transport = old_transport
                successor.setup()
                assert successor.callback("joinHistory", successor.password, successor.command("eval", "stats()")) == "Applied"
                successor.command("eval", 'show("fixture-other");show("synced_tray");tab("synced_tray");add("offline-before-successor");')
                transition_unload(successor)
                transfer = root / "successor-key"; transfer.mkdir(mode=0o700); protect()
                transfer_password = b"successor-public-transfer"
                assert rotation.callback("exportSyncKey", rotation.password, transfer_password, str(transfer)) == "SyncKeyExported"
                joined = destination("peerjoin"); joined["transport"] = str(rotation.transport)
                joined.update({"transfer":str(transfer), "transferPassword":transfer_password.decode()})
                changed = successor.callback("joinSuccessor", successor.password, successor.command("eval", "stats()"), joined)
                assert changed.startswith("HistoryTransitioned") and "journal sealed without keys" in changed, changed
                assert successor.callback("unlockStorage", successor.password) == "Unlocked"
                assert packed_snapshot(successor) == original_snapshot
                successor.command("eval", 'tab("synced_tray");add("peer-after-key-change");')
                peer_snapshot = packed_snapshot(successor); transition_unload(successor)
                assert successor.callback("publishChanges", successor.password, successor.command("eval", "stats()")) == "Applied"
                transition_unload()
                assert rotation.callback("fastForward", rotation.password, rotation.command("eval", "stats()")) == "Applied"
                assert rotation.callback("unlockStorage", rotation.password) == "Unlocked"
                assert packed_snapshot() == peer_snapshot
                successor.stop()
                report["checks"].append("second stock CopyQ explicitly Joined the successor through a separately encrypted NEW key, retained offline local data and published back to the migrated first device")
                # Include a new, unsent local edit in the compact successor.
                rotation.command("eval", 'tab("synced_tray");add("local-after-rotation");')
                compact_snapshot = packed_snapshot(); transition_unload()
                compact = destination("rollover")
                # The old cloud folder can be unavailable at the history limit.
                # Rollover authenticates private state, without old-key delivery.
                rotation.transport.rename(rotation.transport.with_name(rotation.transport.name + "-offline"))
                changed = rotation.callback("compactHistory", rotation.password, rotation.command("eval", "stats()"), compact)
                assert changed.startswith("HistoryTransitioned") and "journal sealed without keys" in changed, changed
                rotation.transport = Path(compact["transport"])
                assert len(list(rotation.transport.rglob("*.cqs"))) == 1
                assert rotation.callback("unlockStorage", rotation.password) == "Unlocked"
                assert packed_snapshot() == compact_snapshot
                rotation.stop(); rotation.start()
                assert rotation.callback("unlockStorage", rotation.password) == "Unlocked"
                assert packed_snapshot() == compact_snapshot
                transition_unload()
                assert rotation.callback("publishChanges", rotation.password, rotation.command("eval", "stats()")) == "UpToDate"
                rotation.stop()
                report["checks"].append("stock CopyQ compact successor retained unsent local edits, started one root with the old transport offline and without echo publication and survived a second profile/cache handover and restart")
            if a.package:
                if not a.ui_driver:
                    raise RuntimeError("Package lifecycle requires the disposable dialog driver")
                # Replacement uses the actual generated archive. Schema upgrade
                # compatibility is covered by frozen records in native tests.
                state = first.folder / "private/record-v1.cqr"
                vault = first.folder / "vault/record-v1.cqr"
                durable_before, vault_before = state.read_bytes(), vault.read_bytes()
                install_package(); first.start()
                assert first.callback("unlockStorage", first.password) == "Unlocked"
                snapshot = first.command("eval", 'tab("synced_tray");var r=[];for(var i=0;i<size();++i)r.push(str(toBase64(read("application/x-copyq-item",i))));JSON.stringify(r)')
                assert state.read_bytes() == durable_before and vault.read_bytes() == vault_before
                report["checks"].append("generated ZIP installed/replaced only while CopyQ was stopped; encrypted state and vault survived restart")
                # Native encryption is an explicit prerequisite for uninstall.
                first.command("eval", 'config("item_data_threshold",1);config("encrypt_tabs",true);')
                assert first.command("eval", 'config("encrypt_tabs")') == "true"
                # Applying host options reloads persisted loader settings, so
                # disable the unshipped probe after enabling native encryption.
                assert first.command("eval", 'callPlugin("cqsuiprobe","disable")') == "Disabled"
                detached = first.command("eval", 'plugins.securesync.detachStorage()')
                assert detached == "Detached", detached
                assert state.exists() and vault.exists()
                first.command("eval", 'setCurrentTab("fixture-other");hide();'); first.stop()
                module.unlink()
                first.env["COPYQ_PLUGINS"] = str(a.ui_driver.resolve())
                first.start(loaded_plugin=False)
                after = first.command("eval", 'tab("synced_tray");var r=[];for(var i=0;i<size();++i)r.push(str(toBase64(read("application/x-copyq-item",i))));JSON.stringify(r)')
                assert after == snapshot
                assert state.read_bytes() == durable_before and vault.exists()
                assert not list((first.folder / "settings").rglob("*.dat")) or all(b"CQSLOC01" not in file.read_bytes()[:8] for file in (first.folder / "settings").rglob("*.dat"))
                first.command("eval", 'setCurrentTab("fixture-other");hide();'); first.stop()
                report["checks"].append("explicit encrypted handoff allowed module deletion and stock CopyQ reopened exact ordered MIME data; encrypted recovery files retained")
            report["status"] = "passed"
        except Exception as e:
            report["status"] = "failed"; report["error"] = str(e); raise
        finally:
            for server in servers:
                if server.group:
                    server.group.close(); server.group = None
                server.log.close()
            (a.out / "result.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            if cloud:
                cloud.close()
    print("PASS_OFFICIAL_COPYQ_GUI", len(report["checks"]))


if __name__ == "__main__":
    main()
