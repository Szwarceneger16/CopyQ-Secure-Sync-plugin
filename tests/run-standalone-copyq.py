#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test an external module in an existing, unmodified CopyQ binary and disposable session.

Requires POSIX and a running X11/Wayland session. --copyq may also be an executable wrapper
for flatpak run; all fixture/plugin paths must then be visible in that sandbox.
This does not compile CopyQ or touch the default CopyQ profile.
"""
import argparse
import base64
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile
import time
import uuid




def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--copyq", type=Path, required=True)
    p.add_argument("--plugin", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--ui-driver", type=Path)
    p.add_argument("--lifecycle", action="store_true")
    p.add_argument("--device-setup", action="store_true", help="Exercise ordinary encrypted-tab preservation, adoption and Seed in real CopyQ")
    p.add_argument("--auto-sync", action="store_true", help="Run bidirectional opt-in synchronization on two real CopyQ servers (requires --device-setup)")
    p.add_argument("--state-fixture-tool", type=Path, help="Disposable public-history fixture executable; enables real unloaded-tab state integration checks")
    p.add_argument("--storage", choices=("main", "lab"), default="main")
    a = p.parse_args()
    if a.auto_sync and not a.device_setup:
        p.error("--auto-sync requires --device-setup")
    if os.name != "posix":
        p.error("This process driver requires POSIX; Windows GUI needs its own driver (kernel/module tests use CTest).")
    tab = "synced_tray" if a.storage == "main" else "cqs-standalone-lab"
    plugin_id = "securesync" if a.storage == "main" else "securesynclab"
    capability = "device-setup/5" if a.storage == "main" else "standalone-storage-lab/1"
    magic = b"CQSLOC01" if a.storage == "main" else b"CQSLAB01"
    marker_size = 80 if a.storage == "main" else 16
    a.out.mkdir(parents=True, exist_ok=True)
    copyq, plugin = str(a.copyq.resolve()), str(a.plugin.resolve())
    report = {"status": "running", "checks": [], "binary": copyq}
    vault_password = b"public-fixture-password"
    server = None
    # Stock CopyQ embeds the settings path in its AF_UNIX socket name. Keep
    # synthetic profiles short regardless of the chosen report directory.
    with tempfile.TemporaryDirectory(prefix="cqs-standalone-", dir="/tmp") as temporary:
        root = Path(temporary).resolve()
        for name in ("settings", "items", "runtime", "private", "key-directory", "cache", "transport", "vault"):
            (root / name).mkdir(mode=0o700)
        (root / "transport" / "events").mkdir(mode=0o700)
        key = root / "key-directory" / "fixture.key"
        key.write_bytes(bytes(range(32)))  # PUBLIC fixture, never a user's K-SYNC.
        key.chmod(0o600)
        env = os.environ.copy()
        env.update({"COPYQ_SESSION_NAME": "cqslab-" + uuid.uuid4().hex[:8],
                    "COPYQ_SETTINGS_PATH": str(root / "settings"),
                    "COPYQ_STATE_PATH": str(root / "settings"),
                    "COPYQ_ITEM_DATA_PATH": str(root / "items"),
                    "XDG_RUNTIME_DIR": str(root / "runtime"),
                    "XDG_CACHE_HOME": str(root / "cache"),
                    "COPYQ_PLUGINS": plugin + (";" + str(a.ui_driver.resolve()) if a.ui_driver else ""), "COPYQ_ALLOW_PLUGINS": "__no_bundled_plugin__",
                    "COPYQ_PASSWORD": "copyq-public-fixture-password", "COPYQ_TESTS_KEY_DELAY": "10",
                    "COPYQ_DEFAULT_ICON": "1", "COPYQ_LOG_LEVEL": "WARNING",
                    "CQS_STANDALONE_LAB": "1", "CQS_LAB_CREATE": "1",
                    "CQS_LAB_STATE_DIR": str(root / "private"), "CQS_LAB_KEY_FILE": str(key)})
        log = (a.out / "copyq-session.log").open("w")

        def command(*args, check=True):
            result = subprocess.run([copyq, *args], env=env,
                                    capture_output=True, text=True, timeout=15)
            if check and result.returncode:
                raise RuntimeError(f"CopyQ command {args[0]} failed ({result.returncode}): {result.stderr.strip()}")
            return result

        def key_call(action, *values):
            # Every credential in this harness is a PUBLIC synthetic fixture.
            arguments = [json.dumps("securesync"), json.dumps(action)]
            for value in values:
                encoded = 'fromBase64(' + json.dumps(base64.b64encode(value if isinstance(value, bytes) else value.encode()).decode()) + ')'
                arguments.append(encoded if isinstance(value, bytes) else 'str(' + encoded + ')')
            result = command("eval", 'callPlugin(' + ','.join(arguments) + ')').stdout.strip()
            if result.startswith("Working:"):
                token = result[8:]; deadline = time.monotonic() + 30
                while True:
                    result = key_call("operationStatus", token)
                    if result != "Working": break
                    if time.monotonic() > deadline: raise RuntimeError("Secure Sync operation timed out")
                    time.sleep(0.025)
            if action == "stopAutomaticSync" and result.startswith("Stopping"):
                deadline = time.monotonic() + 30
                while key_call("automaticSyncStatus") == "Working":
                    if time.monotonic() > deadline: raise RuntimeError("Secure Sync stop timed out")
                    time.sleep(0.025)
                result = "Stopped"
            return result

        def gui_action(action, *values):
            if not a.ui_driver:
                raise RuntimeError("GUI lifecycle checks require the external disposable UI driver")
            return command("eval", 'callPlugin("cqsuiprobe",' + ','.join(json.dumps(v) for v in (action, *values)) + ')').stdout.strip()

        def gui_wait(action, *values):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if gui_action(action, *values) == "Queued":
                    return
                time.sleep(0.1)
            raise RuntimeError("Disposable GUI step timed out: " + action)

        def wait_for(predicate):
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if predicate():
                    return
                if server is not None and server.poll() is not None:
                    raise RuntimeError("CopyQ exited; inspect copyq-session.log")
                time.sleep(0.1)
            raise RuntimeError("CopyQ fixture timed out; inspect copyq-session.log")

        def start(loaded_plugin=True):
            nonlocal server
            server = subprocess.Popen([copyq], env=env, stdout=log, stderr=log, start_new_session=True)
            wait_for(lambda: command("eval", f"plugins.{plugin_id}.capability" if loaded_plugin else "str(1)", check=False).stdout.strip()
                     == (capability if loaded_plugin else "1"))
            if a.ui_driver:
                assert gui_action("ping") == "Ready", "Disposable GUI helper did not load"
            if loaded_plugin and a.storage == "main" and (root / "vault" / "record-v1.cqr").exists():
                if a.ui_driver and "QInputDialog" in command("eval", "stats()").stdout:
                    gui_wait("input", "Secure Sync password", vault_password.decode())
                assert key_call("unlockStorage", vault_password) == "Unlocked"

        def kill_fixture_group():
            # Only the newly created session/process group, including its
            # clipboard helpers; never another CopyQ/user profile.
            try:
                os.killpg(server.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        def stop(hard=False):
            nonlocal server
            if hard:
                kill_fixture_group()
            else:
                command("exit")
            server.wait(timeout=15)
            kill_fixture_group()
            server = None

        def markers():
            # CopyQ puts tab files alongside itemDataPath(), not inside it.
            return [f for f in root.rglob("*.dat")
                    if root/"peer" not in f.parents and f.is_file() and f.stat().st_size == marker_size and f.read_bytes().startswith(magic)]

        def prompted_eval(code):
            if not a.ui_driver:
                return command("eval", code).stdout
            pending=subprocess.Popen([copyq,"eval",code],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            deadline=time.monotonic()+20
            while pending.poll() is None and time.monotonic()<deadline:
                gui_action("input","Secure Sync password",vault_password.decode())
                gui_action("input","Current Tab Encryption Password",env["COPYQ_PASSWORD"])
                time.sleep(0.1)
            output,error=pending.communicate(timeout=5)
            assert pending.returncode==0,error
            return output

        def contents():
            code = (f'tab("{tab}");var r=[];for(var i=0;i<size();++i){{r.push(['
                    'str(toBase64(read("text/plain",i))),str(toBase64(read("application/octet-stream",i))),'
                    'str(toBase64(read("text/html",i)))]);}JSON.stringify(r);')
            return json.loads(prompted_eval(code))

        def peer_join(expected):
            # A second real CopyQ server, separate settings/data/vault and ID.
            transfer=root/"key-transfer";transfer.mkdir(mode=0o700)
            transfer_password=b"public-transfer-password"
            assert key_call("exportSyncKey",vault_password,transfer_password,str(transfer))=="SyncKeyExported"
            peer=root/"peer";peer.mkdir(mode=0o700)
            for name in ("settings","items","runtime","cache","private","vault"):
                (peer/name).mkdir(mode=0o700)
            peer_env=env.copy()
            peer_env.update({"COPYQ_SESSION_NAME":"cqslab-p"+uuid.uuid4().hex[:8],
                "COPYQ_SETTINGS_PATH":str(peer/"settings"),"COPYQ_STATE_PATH":str(peer/"settings"),
                "COPYQ_ITEM_DATA_PATH":str(peer/"items"),"XDG_RUNTIME_DIR":str(peer/"runtime"),
                "XDG_CACHE_HOME":str(peer/"cache"),"COPYQ_PLUGINS":plugin})
            peer_password=b"peer-fixture-password"
            loops=[]
            peer_server=None;peer_log=(a.out/"copyq-peer-session.log").open("w")
            def peer_command(*arguments):
                result=subprocess.run([copyq,*arguments],env=peer_env,capture_output=True,text=True,timeout=15)
                assert result.returncode==0,result.stderr
                return result.stdout.strip()
            def peer_key(action,*values):
                args=[json.dumps("securesync"),json.dumps(action)]
                for v in values:
                    raw=v if isinstance(v,bytes) else v.encode()
                    encoded='fromBase64('+json.dumps(base64.b64encode(raw).decode())+')'
                    args.append(encoded if isinstance(v,bytes) else 'str('+encoded+')')
                result = peer_command("eval",'callPlugin('+','.join(args)+')')
                if result.startswith("Working:"):
                    token = result[8:]; deadline = time.monotonic() + 30
                    while True:
                        result = peer_key("operationStatus", token)
                        if result != "Working": break
                        if time.monotonic() > deadline: raise RuntimeError("Secure Sync operation timed out")
                        time.sleep(0.025)
                return result
            def peer_start():
                nonlocal peer_server
                peer_server=subprocess.Popen([copyq],env=peer_env,stdout=peer_log,stderr=peer_log,start_new_session=True)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    try:
                        probe=subprocess.run([copyq,"eval","plugins.securesync.capability"],env=peer_env,capture_output=True,text=True,timeout=5)
                    except subprocess.TimeoutExpired:
                        if peer_server.poll() is not None:raise RuntimeError("Second disposable CopyQ exited during startup")
                        continue
                    if probe.stdout.strip()==capability:return
                    if peer_server.poll() is not None:raise RuntimeError("Second disposable CopyQ exited: "+probe.stderr.strip())
                    time.sleep(.1)
                raise RuntimeError("Second disposable CopyQ server did not start")
            def peer_stop():
                nonlocal peer_server
                peer_command("exit");peer_server.wait(timeout=15)
                try:os.killpg(peer_server.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                peer_server=None
            def peer_contents():
                return json.loads(peer_command("eval",'show("synced_tray");tab("synced_tray");var r=[];for(var i=0;i<size();++i){r.push(['
                    'str(toBase64(read("text/plain",i))),str(toBase64(read("application/octet-stream",i))),'
                    'str(toBase64(read("text/html",i)))]);}JSON.stringify(r);'))
            try:
                peer_start();peer_command("eval",'config("check_clipboard",false);');peer_stop()
                configs=list((peer/"settings").rglob("copyq-"+peer_env["COPYQ_SESSION_NAME"]+".ini"));assert len(configs)==1
                settings=configs[0];original=settings.read_text()
                options={"profile_schema":"3","standalone_storage":"true","device":"peer-pc",
                    "transport":str(root/"transport"),"key_file":"","state_directory":str(peer/"private"),"vault_directory":str(peer/"vault")}
                entries="".join("securesync\\"+k+"="+v+"\n" for k,v in options.items())
                settings.write_text(original.replace("[Plugins]\n","[Plugins]\n"+entries,1) if "[Plugins]\n" in original else original+"\n[Plugins]\n"+entries)
                peer_start()
                assert peer_key("importSyncKey",peer_password,transfer_password,str(transfer))=="InitializedFromSharedKey"
                assert peer_key("joinHistory",peer_password,peer_command("eval","stats()"))=="Applied"
                actual=peer_contents();state=peer_key("syncState")
                assert actual==expected and state=="Joined",repr((actual,expected,state))
                peer_stop();peer_start();assert peer_key("unlockStorage",peer_password)=="Unlocked"
                assert peer_contents()==expected and peer_key("syncState")=="Joined"
                assert (peer/"private"/"record-v1.cqr").read_bytes()!=(root/"private"/"record-v1.cqr").read_bytes()
                report["checks"].append("second real CopyQ device imported only shared encrypted key, Joined Seed history with exact binary data and survived its own restart")
                if a.auto_sync:
                    def wait_revision(call, wanted):
                        deadline=time.monotonic()+45
                        while time.monotonic()<deadline:
                            if call("syncRevision")==wanted:return
                            status=call("automaticSyncStatus")
                            if status.startswith("Stopped:"):raise RuntimeError(status)
                            time.sleep(.15)
                        raise RuntimeError("Automatic synchronization timed out: "+wanted+" / first="+key_call("automaticSyncStatus")+" / peer="+peer_key("automaticSyncStatus")+" / first-head="+key_call("syncRevision")+" / peer-head="+peer_key("syncRevision")+" / peer-visible="+peer_command("eval","visible()")+" / peer-unload="+peer_command("eval",'JSON.stringify(unload("synced_tray"))')+" / loops="+repr([(x.poll(), x.communicate(timeout=1) if x.poll() is not None else None) for x in loops]))
                    def loop_start(loop_env):
                        loop=subprocess.Popen([copyq,"eval","plugins.securesync.automaticSync()"],env=loop_env,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,start_new_session=True)
                        loops.append(loop)
                    def loops_stop():
                        key_call("stopAutomaticSync");peer_key("stopAutomaticSync")
                        for loop in loops:
                            output,error=loop.communicate(timeout=15)
                            assert loop.returncode==0,(output,error)
                        loops.clear()
                    command("show","synced_tray");peer_command("show","synced_tray")
                    peer_command("eval",'tab("synced_tray");add("peer-update");')
                    assert peer_contents()==[[base64.b64encode(b"peer-update").decode(),"",""]]+expected
                    assert peer_key("checkpointStorage")=="Checkpointed"
                    assert peer_key("syncState")=="LocalChanges"
                    assert key_call("enableAutomaticSync")=="Enabled"
                    assert peer_key("enableAutomaticSync")=="Enabled"
                    wait_revision(key_call,"peer-pc/000000000001")
                    loops_stop()
                    assert key_call("unlockStorage",vault_password)=="Unlocked"
                    command("show","synced_tray")
                    peer_expected=[[base64.b64encode(b"peer-update").decode(),"",""]]+expected
                    assert contents()==peer_expected
                    assert peer_key("unlockStorage",peer_password)=="Unlocked"
                    assert peer_contents()==peer_expected
                    command("eval",'tab("synced_tray");add("first-device-update");')
                    assert key_call("enableAutomaticSync")=="Enabled"
                    assert peer_key("enableAutomaticSync")=="Enabled"
                    wait_revision(peer_key,"fixture-pc/000000000002")
                    updated=[[base64.b64encode(b"first-device-update").decode(),"",""]]+peer_expected
                    assert peer_contents()==updated
                    peer_stop();peer_start()
                    deadline=time.monotonic()+15
                    while peer_key("automaticSyncStatus")=="Stopped" and time.monotonic()<deadline:time.sleep(.1)
                    assert peer_key("automaticSyncStatus").startswith("Waiting")
                    assert peer_key("unlockStorage",peer_password)=="Unlocked"
                    assert peer_contents()==updated
                    command("eval",'tab("synced_tray");add("after-peer-restart");')
                    wait_revision(peer_key,"fixture-pc/000000000003")
                    assert peer_contents()==[[base64.b64encode(b"after-peer-restart").decode(),"",""]]+updated
                    assert len(list((root/"transport"/"events").rglob("*.cqs")))==4
                    loops_stop()
                    report["checks"].append("two real CopyQ servers automatically published/imported updates with selected visible tabs in both directions using the supervised CopyQ client, stopped cleanly, preserved exact MIME data and restarted without duplicate revisions")
                peer_stop()
            finally:
                for loop in loops:
                    try:os.killpg(loop.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    loop.wait(timeout=15)
                if peer_server is not None:
                    try:os.killpg(peer_server.pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                    peer_server.wait(timeout=15)
                peer_log.close()

        try:
            report["copyq_version"] = command("--version").stdout.strip()
            if not report["copyq_version"].startswith("CopyQ Clipboard Manager 17."):
                raise RuntimeError("Standalone storage requires an existing CopyQ 17 binary")
            start()
            command("eval", 'config("item_data_threshold",1);config("check_clipboard",false);'
                    'config("save_delay_ms_on_item_added",0);'
                    'config("save_delay_ms_on_item_modified",0);'
                    'config("save_delay_ms_on_item_removed",0);')
            if a.storage == "main":
                preserved_contents = None
                if a.device_setup:
                    if not a.ui_driver:
                        raise RuntimeError("Ordinary encrypted-tab setup requires the disposable GUI helper")
                    command("eval",'config("item_data_threshold",1);tab("synced_tray");write(0,"text/plain",fromBase64("QQD/DQo="),"application/octet-stream",fromBase64("AAH/"));tab("cqs-lab-unrelated");add("unrelated");')
                    preserved_contents=contents()
                    enabling=subprocess.Popen([copyq,"eval",'config("encrypt_tabs",true);'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    deadline=time.monotonic()+30
                    while enabling.poll() is None and time.monotonic()<deadline:
                        if gui_action("input","New Tab Encryption Password",env["COPYQ_PASSWORD"])=="Queued":
                            gui_wait("input","Confirm Encryption Password",env["COPYQ_PASSWORD"])
                        time.sleep(0.1)
                    _,error=enabling.communicate(timeout=5)
                    assert enabling.returncode==0,error
                    assert gui_action("disable")=="Disabled"
                    assert command("eval",'plugins.securesync.preserveNativeTab();').stdout.strip()=="PreservedNativeTab"
                    report["checks"].append("ordinary encrypted source tab preserved through public unload and rename, without overwriting another tab")
                # Configure only the unique disposable session, while stopped.
                command("eval", 'config("check_clipboard",false);')
                stop()
                configs = list((root / "settings").rglob("copyq-" + env["COPYQ_SESSION_NAME"] + ".ini"))
                assert len(configs) == 1, "Expected only the isolated session INI: " + str([f.name for f in configs])
                settings = configs[0]
                options = {"profile_schema": "3", "standalone_storage": "true", "device": "fixture-pc",
                           "transport": str(root / "transport"), "key_file": str(key),
                           "state_directory": str(root / "private"), "vault_directory": str(root / "vault")}
                entries = "".join("securesync\\" + name + "=" + value + "\n" for name, value in options.items())
                original = settings.read_text()
                original = original.replace("[Options]\n", "[Options]\nuse_key_store=false\n", 1)
                settings.write_text(original.replace("[Plugins]\n", "[Plugins]\n" + entries, 1)
                    if "[Plugins]\n" in original else original + "\n[Plugins]\n" + entries)
                start()
                assert key_call("initializeStorage", vault_password) == "Initialized"
                assert key_call("initializeStorage", vault_password).startswith("Refused")
                report["checks"].append("main securesync configured through ordinary settings; initialization is explicit and create-only")
                if a.device_setup:
                    # Native CopyQ and Secure Sync have independent passwords.
                    # Unlock the retained native source while the disposable
                    # dialog driver is still enabled, before the inventory guard.
                    prompted_eval('show("synced_tray-before-secure-sync");tab("synced_tray-before-secure-sync");size();')
                    fixture_helper=a.ui_driver
                    assert gui_action("armPublicPasswords",vault_password.decode(),env["COPYQ_PASSWORD"])=="Queued"
                    assert gui_action("disable")=="Disabled"
                    a.ui_driver=None
                    assert "PLUGIN cqsuiprobe: enabled" not in command("eval","stats()").stdout
                    auth='fromBase64('+json.dumps(base64.b64encode(vault_password).decode())+')'
                    # Real encrypted DataFile must refuse a missing blob before
                    # adoption can commit anything, rather than import empty data.
                    blobs=[f for f in (root/"items").rglob("*.dat") if len(f.stem)==16]
                    assert blobs, "Native CopyQ did not create file-backed fixture data"
                    ciphertext=blobs[0].read_bytes();before_record=(root/"private"/"record-v1.cqr").read_bytes()
                    blobs[0].unlink()
                    refused=command("eval",'plugins.securesync.adoptFromTab('+auth+');').stdout.strip()
                    assert refused.startswith("Refused"),refused
                    assert (root/"private"/"record-v1.cqr").read_bytes()==before_record
                    blobs[0].write_bytes(ciphertext);blobs[0].chmod(0o600)
                    adopted=command("eval",'plugins.securesync.adoptFromTab('+auth+');').stdout.strip()
                    assert adopted=="AdoptedPreservedTab",adopted
                    assert contents()==preserved_contents
                    assert command("eval",'tab("synced_tray-before-secure-sync");str(toBase64(read("text/plain",0)));').stdout.strip()==preserved_contents[0][0]
                    report["checks"].append("bounded encrypted native DataFile adoption refused a missing blob without a commit, then retained the source and restored exact binary MIME bytes")
                    seeded=command("eval",'plugins.securesync.seedHistory('+auth+');').stdout.strip()
                    assert seeded=="Applied",seeded
                    assert key_call("syncState")=="Joined"
                    assert len(list((root/"transport"/"events").rglob("*.cqs")))==1
                    command("eval",'hide();setCurrentTab("cqs-lab-unrelated");')
                    assert tab in json.loads(command("eval",f'JSON.stringify(unload("{tab}"));').stdout)
                    assert key_call("retrySeed",vault_password,command("eval","stats()").stdout)=="UpToDate"
                    assert contents()==preserved_contents
                    report["checks"].append("real scriptable Seed used public checkpoint/unload/reload; idempotent retry retained one encrypted history event")
                    peer_join(preserved_contents)
                    # Later restart checks run without the optional helper module.
                    a.ui_driver=fixture_helper
                    # The remaining fixture uses its original two-row dataset;
                    # remove only the copied public test items, preserving the
                    # native backup and accepted Seed in the private record.
                    command("eval",f'tab("{tab}");while(size())remove(0);')
                if a.state_fixture_tool:
                    if a.ui_driver:
                        raise RuntimeError("State integration needs only securesync enabled; run lifecycle separately")
                    assert key_call("syncState") == "Unjoined"
                    command("show",tab);command("hide")
                    assert key_call("joinHistory",vault_password,command("eval","stats()").stdout).startswith("Refused: checkpoint")
                    command("eval", 'setCurrentTab("cqs-lab-unrelated");')
                    assert tab in json.loads(command("eval", f'JSON.stringify(unload("{tab}"));').stdout)
                    tool=str(a.state_fixture_tool.resolve())
                    def remote(sequence):
                        fixture=subprocess.run([tool,"--write-public-history",str(root/"transport"),str(sequence)],env=env,capture_output=True,text=True,timeout=15)
                        assert fixture.returncode==0,fixture.stderr
                    remote(1)
                    assert key_call("joinHistory",vault_password,command("eval","stats()").stdout)=="Applied"
                    joined=contents();assert len(joined)==2 and joined[0][0]==base64.b64encode(b'A\0\xff\r\n').decode(),repr(joined)+":"+key_call("syncState")+":"+str([(f.name,f.stat().st_size) for f in root.rglob("*.dat")])
                    assert key_call("syncState")=="Joined"
                    report["checks"].append("real module refused loaded-tab import, then Joined authenticated Qt-packed history after public unload")
                    command("eval", 'hide();setCurrentTab("cqs-lab-unrelated");')
                    assert tab in json.loads(command("eval",f'JSON.stringify(unload("{tab}"));').stdout)
                    remote(2)
                    assert key_call("fastForward",vault_password,command("eval","stats()").stdout)=="Applied"
                    newer=contents();assert len(newer)==3 and newer[0][0]==base64.b64encode(b'B').decode()
                    stop();start();assert contents()==newer and key_call("syncState")=="Joined"
                    report["checks"].append("manual FastForward committed local contents and accepted history together; real CopyQ restart restored exact bytes")
                    command("eval", f'tab("{tab}");add("preserve manual edit");')
                    assert key_call("checkpointStorage")=="Checkpointed"
                    edited=contents();assert key_call("syncState")=="LocalChanges"
                    command("eval", 'hide();setCurrentTab("cqs-lab-unrelated");')
                    assert tab in json.loads(command("eval",f'JSON.stringify(unload("{tab}"));').stdout)
                    assert key_call("fastForward",vault_password,command("eval","stats()").stdout).startswith("Refused")
                    assert contents()==edited
                    report["checks"].append("local edits retained accepted head and were preserved when another import was refused")
                    command("eval",f'tab("{tab}");while(size())remove(0);') # Only disposable public fixture items.
            command("eval", f'tab("{tab}");write(0,"application/octet-stream",fromBase64("AP8NCmNxcy1zdGFuZGFsb25l"),'
                    '"text/html","<b>standalone fixture</b>");add("second fixture");')
            expected = contents()
            assert len(expected) == 2, "Fixture rows were not inserted"
            wait_for(lambda: len(markers()) == 1)
            marker = markers()[0]
            first_marker = marker.read_bytes()
            record = root / "private" / "record-v1.cqr"
            assert record.exists()
            assert b"standalone fixture" not in record.read_bytes()
            assert b"standalone fixture" not in marker.read_bytes()
            report["checks"].append("external module loaded; binary MIME saved with encrypted authoritative checkpoint")
            stop()
            # Normal shutdown flushes CopyQ's delayed saves. Take the baseline
            # here, not from the earlier empty-tab initialization marker.
            first_marker = marker.read_bytes()
            env["CQS_LAB_CREATE"] = "0"
            start()
            assert contents() == expected, "Normal restart changed ordered MIME bytes"
            report["checks"].append("normal restart restored exact fixture content")
            command("eval", f'tab("{tab}");add("after crash fixture");')
            latest = contents()
            wait_for(lambda: marker.exists() and marker.read_bytes() != first_marker)
            stop(hard=True)
            # Simulate loss of CopyQ's final cache commit after our private commit.
            marker.write_bytes(first_marker)
            start()
            assert contents() == latest, "Stale host cache did not recover newest checkpoint"
            report["checks"].append("SIGKILL plus stale CopyQ cache recovered newest durable data")
            stop()
            marker.unlink()
            start()
            assert contents() == latest, "Missing host cache reset the private checkpoint"
            report["checks"].append("missing CopyQ cache reconstructed without resetting private data")
            command("eval", 'tab("cqs-lab-unrelated");add("ordinary tab fixture");')
            assert command("eval", 'tab("cqs-lab-unrelated");str(read(0));').stdout.strip() == "ordinary tab fixture"
            report["checks"].append("ordinary tab remains served by CopyQ's default saver")
            if a.lifecycle:
                if a.storage != "main" or not a.ui_driver:
                    raise RuntimeError("Lifecycle checks need main storage and the disposable GUI helper")
                enabling=subprocess.Popen([copyq,"eval",'config("encrypt_tabs",true);'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                deadline=time.monotonic()+30
                while enabling.poll() is None and time.monotonic()<deadline:
                    if gui_action("input","New Tab Encryption Password",env["COPYQ_PASSWORD"])=="Queued":
                        gui_wait("input","Confirm Encryption Password",env["COPYQ_PASSWORD"])
                    time.sleep(0.1)
                enabled_output,enabled_error=enabling.communicate(timeout=5)
                assert enabling.returncode==0,enabled_error
                assert command("eval", 'config("encrypt_tabs");').stdout.strip() == "true"
                assert contents() == latest
                report["checks"].append("CopyQ Encrypt Tabs enabled without rekeying or losing the independent local checkpoint")
                protected = record.read_bytes()
                prompted_eval('config("encrypt_tabs",false);')
                assert contents() == latest and record.read_bytes() == protected
                assert key_call("setNativeRoot",command("eval",'str(info("data"))').stdout.strip())=="Configured"
                assert key_call("prepareDetach", vault_password, "PLUGIN securesync: enabled").startswith("Refused")
                prompted_eval('config("encrypt_tabs",true);')
                assert contents() == latest and record.read_bytes() == protected
                report["checks"].append("disabling/re-enabling native Encrypt Tabs preserved independent ciphertext; unencrypted handoff refused")
                before = record.read_bytes()
                next_password = b"updated-public-fixture-password"
                assert key_call("changeStoragePassword", vault_password, next_password) == "PasswordChanged"
                old_password, vault_password = vault_password, next_password
                assert key_call("unlockStorage", old_password).startswith("Refused")
                assert key_call("unlockStorage", vault_password) == "Unlocked"
                assert record.read_bytes() == before and contents() == latest
                report["checks"].append("Secure Sync password changed; old password refused; CopyQ content and local ciphertext unchanged")
                assert key_call("rotateLocalKey", vault_password) == "KeyRotated"
                assert record.read_bytes() != before and contents() == latest
                report["checks"].append("local data key rotated while preserving ordered MIME bytes")
                command("show", tab)
                gui_wait("shortcut", "Ctrl+P")
                gui_wait("click", "pushButtonChangeEncryptionPassword")
                gui_wait("input", "Current Tab Encryption Password", env["COPYQ_PASSWORD"])
                native_new_password = "copyq-updated-fixture-password"
                gui_wait("input", "New Tab Encryption Password", native_new_password)
                gui_wait("input", "Confirm Encryption Password", native_new_password)
                gui_wait("message", "Change Password Successful")
                gui_wait("closePreferences")
                env["COPYQ_PASSWORD"] = native_new_password
                assert contents() == latest
                report["checks"].append("real CopyQ Preferences password change left Secure Sync password/key and data usable")
                command("eval", 'config("expire_encrypted_tab_seconds",1);setCurrentTab("cqs-lab-unrelated");hide();')
                wait_for(lambda: key_call("status") == "Locked")
                pending = subprocess.Popen([copyq, "eval", f'tab("{tab}");str(size());'], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                gui_wait("input", "Current Tab Encryption Password", native_new_password)
                gui_wait("input", "Secure Sync password", vault_password.decode())
                output, error = pending.communicate(timeout=15)
                assert pending.returncode == 0 and output.strip() == str(len(latest)), error
                assert contents() == latest
                report["checks"].append("real CopyQ password expiry unloaded the model and cleared plugin keys; both passwords restored exact data")
                prompted_eval('config("expire_encrypted_tab_seconds",0);show("'+tab+'");tab("'+tab+'");select(0);')
                gui_wait("shortcut", "F2")
                wait_for(lambda: "ItemEditorWidget" in command("eval", "stats()").stdout)
                unloaded = json.loads(command("eval", 'hide();JSON.stringify(unload("'+tab+'"));').stdout)
                assert tab not in unloaded and key_call("status") == "Unlocked"
                command("show",tab)
                gui_wait("cancelEditor")
                wait_for(lambda: "ItemEditorWidget" not in command("eval", "stats()").stdout)
                report["checks"].append("public unload refused an open editor and retained the unlocked model without forcing or discarding edits")
                assert key_call("setNativeRoot",command("eval",'str(info("data"))').stdout.strip())=="Configured"
                assert key_call("prepareDetach", vault_password, command("eval", "stats()").stdout).startswith("Refused")
                report["checks"].append("handoff refused while another item plugin was enabled")
                command("eval", 'hide();tab("cqs-lab-unrelated");')
                stop()
                env["COPYQ_PLUGINS"] = plugin
                a.ui_driver = None
                start()
                assert contents() == latest
                command("eval", 'hide();tab("cqs-lab-unrelated");')
                assert key_call("setNativeRoot",command("eval",'str(info("data"))').stdout.strip())=="Configured"
                native_before={f for f in (root/"items").rglob("*.dat") if len(f.stem)==16}
                assert key_call("prepareDetach", vault_password, command("eval", "stats()").stdout) == "DetachPrepared"
                assert tab in json.loads(command("eval", 'JSON.stringify(unload("'+tab+'"));').stdout)
                assert key_call("unlockStorage", vault_password) == "Unlocked"
                assert contents() == latest
                native_after={f for f in (root/"items").rglob("*.dat") if len(f.stem)==16}
                assert native_after-native_before,"Encrypted handoff did not create native DataFiles"
                # Terminate after CopyQ committed its native encrypted cache,
                # before the plugin persisted the final opt-out setting.
                command("eval", 'hide();tab("cqs-lab-unrelated");')
                stop(hard=True)
                start()
                assert key_call("setNativeRoot",command("eval",'str(info("data"))').stdout.strip())=="Configured"
                assert key_call("prepareDetach", vault_password, command("eval", "stats()").stdout) == "DetachPrepared"
                command("eval", 'unload("'+tab+'");')
                assert key_call("unlockStorage", vault_password) == "Unlocked"
                assert contents() == latest
                assert key_call("finishDetach") == "Detached"
                report["checks"].append("SIGKILL after native encrypted DataFile handoff resumed safely before final opt-out")
                assert not markers(), "Cache was not converted to ordinary CopyQ storage"
                report["checks"].append("explicit handoff committed ordinary encrypted CopyQ storage and retained encrypted recovery files")
                command("eval", 'hide();tab("cqs-lab-unrelated");')
                stop()
                env["COPYQ_PLUGINS"] = ""
                start(loaded_plugin=False)
                assert contents() == latest, "Removing the plugin lost ordered MIME content"
                assert record.exists() and (root / "vault" / "record-v1.cqr").exists()
                report["checks"].append("unmodified CopyQ restarted with plugin removed and read exact encrypted data using only its own password")
            stop()
            report["status"] = "passed"
        except Exception as error:
            report["status"] = "failed"
            report["error"] = str(error)
            if a.device_setup:
                try:
                    report["failure_stats"]=command("eval","stats()",check=False).stdout
                except Exception:
                    pass
            raise
        finally:
            if server is not None:
                kill_fixture_group()
                server.wait(timeout=15)
            log.close()
            (a.out / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS_STANDALONE_COPYQ_SESSION", len(report["checks"]))


if __name__ == "__main__":
    main()
