#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Default Flatpak namespace: no host folder grant for probe/module transfer."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import uuid

spec = importlib.util.spec_from_file_location("cqs_install", Path(__file__).resolve().parents[1] / "tools/install.py")
installer = importlib.util.module_from_spec(spec); spec.loader.exec_module(installer)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();a.out.mkdir(parents=True,exist_ok=True)
    report={"status":"running","checks":[]};process=None
    # A deliberately ungranted public marker on the disposable hosted runner.
    denied=a.out.resolve()/"host-only-marker";denied.write_text("public permission fixture")
    command=["flatpak","run","--user","--no-documents-portal",
        "--env=COPYQ_SESSION_NAME=cqsi-"+uuid.uuid4().hex[:8],"com.github.hluk.copyq"]
    log=(a.out/"copyq.log").open("wb")
    def stop():
        nonlocal process
        if process is None:return
        try:
            if process.poll() is None:
                subprocess.run([*command,"exit"],capture_output=True,timeout=15,check=True)
                process.wait(timeout=20)
        finally:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=10);process=None
    try:
        process=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
        deadline=time.monotonic()+30
        while True:
            try:probe=installer.call(command,installer.PROBE);break
            except ValueError:
                if time.monotonic()>deadline or process.poll() is not None:raise
                time.sleep(.2)
        plan=installer.plan(probe)
        (a.out/"installation.json").write_text(json.dumps({"probe":probe,"plan":plan},indent=2))
        assert plan["environment"]=="flatpak"
        assert not probe["paths"]["state"].startswith("/tmp/")
        assert probe["runtime"]["flatpak_runtime"]=="org.kde.Platform/x86_64/6.10", probe["runtime"]
        report["checks"].append("installed Flatpak reported its real default CopyQ directories and runtime without host-path translation")
        forbidden="JSON.stringify((function(){var f=new File("+json.dumps(str(denied))+");return f.openReadOnly();})())"
        assert installer.call(command,forbidden) is False
        report["checks"].append("ungranted host report/download directory stayed unreadable inside installed Flatpak")
        metadata,name,raw=installer.read_package(a.package,hashlib.sha256(a.package.read_bytes()).hexdigest())
        staged=installer.call(command,installer.stage_script(probe,metadata,name,raw),raw)
        assert staged["staged_module"].startswith(plan["module_root"]+"/")
        assert staged["activated"] is False
        (a.out/"stage.json").write_text(json.dumps(staged,indent=2))
        report["checks"].append("stdin transferred and read back the verified module inside CopyQ with no download-folder grant")
        # Independent marker bytes test namespace persistence for both suggested
        # private folders. Actual vault crypto/checkpoint behavior is exercised
        # separately by the full installed-Flatpak GUI cycle.
        mkdir_command=command[:-1]+["--command=sh",command[-1],"-c",
            'umask 077; mkdir -p "$1" "$2"',"sh",plan["suggested_state"],plan["suggested_vault"]]
        subprocess.run(mkdir_command,check=True,capture_output=True,timeout=20)
        markers=[plan["suggested_state"]+"/public-persistence-marker",plan["suggested_vault"]+"/public-persistence-marker"]
        marker_script="JSON.stringify((function(){var paths="+json.dumps(markers)+";return paths.every(function(p){var f=new File(p);if(!f.openWriteOnly())return false;var n=f.write('public namespace fixture');var ok=f.flush();f.close();return n===24&&ok;});})())"
        assert installer.call(command,marker_script) is True
        stop()
        command.insert(-1,"--env=COPYQ_PLUGINS="+staged["staged_module"])
        process=subprocess.Popen(command,stdout=log,stderr=log,start_new_session=True)
        deadline=time.monotonic()+30
        while True:
            try:
                if installer.call(command,"JSON.stringify(plugins.securesync.capability)")=="device-setup/5":break
            except ValueError:pass
            if time.monotonic()>deadline:raise RuntimeError("Default-namespace module did not load after restart")
            time.sleep(.2)
        assert installer.call(command,forbidden) is False
        report["checks"].append("same installed Flatpak loaded the staged module after restart and retained denial of unrelated host files")
        marker_script="JSON.stringify((function(){var paths="+json.dumps(markers)+";return paths.every(function(p){var f=new File(p);if(!f.openReadOnly())return false;var value=str(f.read(25));f.close();return value==='public namespace fixture';});})())"
        assert installer.call(command,marker_script) is True
        report["checks"].append("provider-supplied persistent data kept both suggested private state/vault folders readable with exact marker bytes across sandbox restart")
        report["status"]="passed"
    except Exception as error:
        report["status"]="failed";report["error"]=str(error);raise
    finally:
        try:stop()
        finally:
            log.close();(a.out/"result.json").write_text(json.dumps(report,indent=2)+"\n")
    print("PASS_FLATPAK_DEFAULT_INSTALLATION",len(report["checks"]))


if __name__=="__main__":main()
