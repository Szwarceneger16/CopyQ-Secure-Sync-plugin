#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Disposable actual Nextcloud transport, fixed public fixture identity only.

The Docker acceptance runner provides an internal hostname with no public
ports. This module never opens a user's account or accepts account credentials.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.error
import urllib.request
import uuid


class NextcloudFixture:
    url = "http://cqs-nextcloud"
    user = "public-fixture"
    password = "public-fixture-test-only"

    def __init__(self, root, out):
        self.root, self.out = Path(root), Path(out)
        self.remote = "/CQS-fixture-" + uuid.uuid4().hex
        self.round = 0
        self.servers = []
        self.paused = set()
        # Only this private, disposable hostname bypasses the session proxy.
        # Preserve proxies and their exclusions for every other destination.
        for name in ("NO_PROXY", "no_proxy"):
            os.environ[name] = ",".join(filter(None, (os.environ.get(name), "cqs-nextcloud")))
        status = json.loads(urllib.request.urlopen(self.url + "/status.php", timeout=20).read())
        if not status.get("installed") or status.get("maintenance"):
            raise RuntimeError("Disposable Nextcloud server is not ready")
        self.request(self.remote, "MKCOL")
        self.metadata = {"server": status["versionstring"], "client": self.command_version(), "cycles": 0}

    def request(self, relative, method="GET"):
        auth = base64.b64encode((self.user + ":" + self.password).encode()).decode()
        request = urllib.request.Request(self.url + "/remote.php/dav/files/" + self.user + relative,
                                         method=method, headers={"Authorization": "Basic " + auth})
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read()

    def environment(self):
        env = os.environ.copy()
        # CopyQ AppImage and system nextcloudcmd have different Qt libraries.
        env.pop("LD_LIBRARY_PATH", None)
        env["QT_QPA_PLATFORM"] = "offscreen"
        env["XDG_CONFIG_HOME"] = str(self.root / "nextcloud-config")
        env["XDG_CACHE_HOME"] = str(self.root / "nextcloud-cache")
        env["NC_USER"], env["NC_PASSWORD"] = self.user, self.password
        return env

    def command_version(self):
        return subprocess.run(["nextcloudcmd", "--version"], env=self.environment(),
                              capture_output=True, text=True, check=True, timeout=10).stdout.strip()

    def cycle(self):
        for server in self.servers:
            if server.label in self.paused:
                continue
            self.round += 1
            log = self.out / ("nextcloud-%03d-%s.log" % (self.round, server.label))
            with log.open("w", encoding="utf-8") as output:
                result = subprocess.run(["nextcloudcmd", "--non-interactive", "--max-sync-retries", "1",
                                         "--path", self.remote, str(server.transport), self.url],
                                        env=self.environment(), stdout=output, stderr=subprocess.STDOUT, timeout=45)
            if result.returncode:
                raise RuntimeError("Actual Nextcloud client failed: " + log.name)
        self.metadata["cycles"] += 1

    def verify_ciphertexts(self):
        files = {}
        for server in self.servers:
            for file in (server.transport / "events").rglob("*.cqs"):
                relative = file.relative_to(server.transport).as_posix()
                wire = file.read_bytes()
                if relative in files and files[relative] != wire:
                    raise RuntimeError("Different ciphertext under one immutable event name")
                files[relative] = wire
        for name, wire in files.items():
            received = self.request(self.remote + "/" + name)
            if received != wire or any(marker in received for marker in
                                       (b"public-first", b"public-update", b"public-local-conflict", b"public-offline")):
                raise RuntimeError("Server did not preserve encrypted immutable bytes")
        self.metadata["events"] = {name: hashlib.sha256(wire).hexdigest() for name, wire in sorted(files.items())}
        return len(files)

    def close(self):
        try:
            self.request(self.remote, "DELETE")
        finally:
            (self.out / "nextcloud-result.json").write_text(json.dumps(self.metadata, indent=2) + "\n", encoding="utf-8")
