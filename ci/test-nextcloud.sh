#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Disposable acceptance: no public port, real desktop client, fixed test account.
set -euo pipefail
cqs_source="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cqs_build="$(realpath "${1:?provide the tested native output directory}")"
cqs_fixture="$cqs_build/nextcloud-fixture"
cqs_reports="$cqs_build/reports/nextcloud"
mkdir -p "$cqs_fixture" "$cqs_reports"
cqs_docker(){ env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH docker --host=unix:///var/run/docker.sock "$@"; }
cqs_image="${CQS_NEXTCLOUD_CLIENT_IMAGE:-cqs-nextcloud-client:ci}"
if test -z "${CQS_NEXTCLOUD_CLIENT_IMAGE:-}"; then
  curl --fail --location --retry 3 'https://github.com/hluk/CopyQ/releases/download/v17.0.0/CopyQ-17.0.0-x86_64.AppImage' -o "$cqs_fixture/copyq.AppImage"
  echo "b63fb78eed3300af61ce2db7bf537bf12160ef86c7122147fc1c3cceb826c0d1  $cqs_fixture/copyq.AppImage" | sha256sum --check
  chmod +x "$cqs_fixture/copyq.AppImage"
  (cd "$cqs_fixture" && ./copyq.AppImage --appimage-extract >extract.log)
  cqs_secrets=()
  if test -n "${CODEX_PROXY_CERT:-}"; then cqs_secrets+=(--secret "id=proxy_ca,src=$CODEX_PROXY_CERT"); fi
  cqs_docker build "${cqs_secrets[@]}" --tag "$cqs_image" --file "$cqs_source/ci/Containerfile.nextcloud" "$cqs_fixture" >"$cqs_reports/container-build.log" 2>&1
fi
cqs_server_image='nextcloud:31-apache@sha256:07ec73cc816e58d6f45a162cd53ef886462c29271a23fc68d0124cec276e3767'
cqs_docker pull "$cqs_server_image"
cqs_network="cqs-nextcloud-$BASHPID"
cqs_server="$cqs_network-server"
cqs_client="$cqs_network-client"
cqs_docker network create --internal "$cqs_network" >/dev/null
cleanup(){
  cqs_docker logs "$cqs_server" >"$cqs_reports/server.log" 2>&1 || true
  cqs_docker rm --force --volumes "$cqs_client" "$cqs_server" >/dev/null 2>&1 || true
  cqs_docker network rm "$cqs_network" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cqs_docker run --detach --name "$cqs_server" --network "$cqs_network" --network-alias cqs-nextcloud \
  --cap-drop NET_RAW --pids-limit 256 --memory 3g --tmpfs /var/www/html:rw,nosuid,nodev,size=2g \
  --env NEXTCLOUD_ADMIN_USER=public-fixture --env NEXTCLOUD_ADMIN_PASSWORD=public-fixture-test-only \
  --env SQLITE_DATABASE=cqs --env NEXTCLOUD_TRUSTED_DOMAINS=cqs-nextcloud "$cqs_server_image" >/dev/null
# Readiness is bounded; startup failures remain failures rather than skipped tests.
for cqs_attempt in $(seq 1 60); do
  if cqs_docker exec --user www-data "$cqs_server" php /var/www/html/occ status --output=json 2>/dev/null | python3 -c 'import json,sys; s=json.load(sys.stdin); sys.exit(not s.get("installed") or s.get("maintenance"))' 2>/dev/null; then break; fi
  if test "$cqs_attempt" = 60; then echo 'Disposable Nextcloud startup failed' >&2; exit 1; fi
  sleep 2
done
cqs_docker image inspect "$cqs_image" "$cqs_server_image" >"$cqs_reports/images.json"
cqs_docker run --rm --name "$cqs_client" --network "$cqs_network" --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 512 --memory 3g --user "$(id -u):$(id -g)" \
  --env NO_PROXY=cqs-nextcloud --env no_proxy=cqs-nextcloud --tmpfs /tmp:rw,exec,nosuid,size=1g \
  --mount "type=bind,src=$cqs_source,dst=/source,readonly" \
  --mount "type=bind,src=$cqs_build,dst=/build,readonly" \
  --mount "type=bind,src=$cqs_reports,dst=/reports" \
  "$cqs_image" bash /source/ci/run-nextcloud-gui.sh
python3 - "$cqs_reports" <<'PY'
import json, pathlib, sys
root=pathlib.Path(sys.argv[1]); gui=json.loads((root/'result.json').read_text()); cloud=json.loads((root/'nextcloud-result.json').read_text())
if gui.get('status')!='passed' or len(gui.get('checks',[]))<6 or len(cloud.get('events',{})) not in (8,9) or cloud.get('cycles',0)<3:
    raise SystemExit('Required actual Nextcloud scenarios missing or failed')
print('REQUIRED_NEXTCLOUD_ACCEPTANCE_VERIFIED')
PY
