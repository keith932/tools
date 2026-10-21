#!/usr/bin/env bash
# Run locally on each selected server through a bastion Shell command module.
# Required environment: FALCON_CLIENT_ID, FALCON_CLIENT_SECRET.
set +x
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo '请使用 root 账号运行'; exit 10; }
: "${FALCON_CLIENT_ID:?请设置 API Client ID}"
: "${FALCON_CLIENT_SECRET:?请设置 API Client Secret}"
export FALCON_CLIENT_ID FALCON_CLIENT_SECRET
export FALCON_CLOUD="${FALCON_CLOUD:-}"
command -v curl >/dev/null || { echo '请先安装 curl'; exit 13; }
json_python=''
for candidate in python3 python python2; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (2,7) else 1)' 2>/dev/null; then
        json_python=$candidate; break
    fi
done
[[ -n "$json_python" ]] || { echo '需要 Python 2.7 或 Python 3 用于处理 API JSON'; exit 14; }
group_code=$(cat <<'FALCON_HOST_GROUP_CODE'
from __future__ import print_function
import json
import re
import sys
import time
import subprocess
try:
    from urllib import parse
except ImportError:
    import urllib as parse

CLOUDS = {
    "us-1": "https://api.crowdstrike.com",
    "us-2": "https://api.us-2.crowdstrike.com",
    "us-3": "https://api.us-3.crowdstrike.com",
    "eu-1": "https://api.eu-1.crowdstrike.com",
    "us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
    "us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}


class APIError(Exception):
    def __init__(self, status, route):
        self.status = status
        Exception.__init__(self, "Falcon API HTTP {} on {}".format(status, route))


def curl_quote(value):
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'


def api(base, route, token=None, body=None, form=None):
    # curl handles TLS on both Python 2 and 3. Secrets are sent in stdin config.
    config = ['url = ' + curl_quote(base + route), 'header = "Accept: application/json"']
    if token:
        config.append('header = ' + curl_quote('Authorization: Bearer ' + token))
    if form is not None:
        config.append('header = "Content-Type: application/x-www-form-urlencoded"')
        config.append('data = ' + curl_quote(parse.urlencode(form)))
    elif body is not None:
        config.append('header = "Content-Type: application/json"')
        config.append('data = ' + curl_quote(json.dumps(body)))
    config_bytes = ('\n'.join(config) + '\n').encode('utf-8')
    for attempt in range(3):
        proc = subprocess.Popen([
            'curl', '--config', '-', '--proto', '=https', '--tlsv1.2', '-sS',
            '--connect-timeout', '15', '--max-time', '40', '-w', '\n%{http_code}',
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, _ = proc.communicate(config_bytes)
        if proc.returncode:
            raise RuntimeError('Falcon API connection failed (curl code {}); response omitted'.format(proc.returncode))
        try:
            payload, status = output.rsplit(b'\n', 1)
            status = int(status)
        except (ValueError, TypeError):
            raise RuntimeError('Falcon API invalid response')
        if status in (429, 500, 502, 503, 504) and attempt < 2:
            time.sleep(2 ** attempt)
            continue
        if not 200 <= status < 300:
            raise APIError(status, route.split('?')[0])
        try:
            result = json.loads(payload.decode('utf-8'))
        except ValueError:
            raise RuntimeError('Falcon API invalid JSON; response omitted')
        if result.get('errors'):
            raise APIError(400, route.split('?')[0])
        return result
    raise RuntimeError('Falcon API retry limit reached')


def authenticate(client_id, secret, cloud):
    candidates = [cloud] if cloud else ["us-1", "us-2", "us-3", "eu-1"]
    for region in candidates:
        if region not in CLOUDS:
            raise RuntimeError("Unknown Falcon cloud region")
        try:
            response = api(CLOUDS[region], "/oauth2/token", form={
                "client_id": client_id, "client_secret": secret,
            })
            token = response.get("access_token")
            if token:
                return region, token
        except APIError as exc:
            if exc.status not in (301, 302, 307, 308, 400, 401, 403):
                raise
    raise RuntimeError("API authentication failed; check Client ID/Secret and --cloud")


def validate_group(base, token, group_id):
    result = api(base, "/devices/entities/host-groups/v1?" + parse.urlencode({"ids": group_id}), token)
    groups = result.get("resources", [])
    group = next((g for g in groups if g.get("id") == group_id), None)
    if not group:
        raise RuntimeError("Target group not found in this API tenant")
    if group.get("group_type") not in ("static", "staticByID"):
        raise RuntimeError("Target group is dynamic or unsupported: use its assignment rule; no group settings were changed")
    if group_id == "f21f4746723b4e4994c26d8b566fcab2" and group.get("name") != "misc1":
        raise RuntimeError("Target group ID no longer has expected name misc1; refusing enrollment")
    return group


def member_record(base, token, group_id, aid):
    # Enumerate the group's members without a host filter, then inspect the exact
    # device's groups field. Do not trust a filtered device-ID response alone.
    offset = 0
    while True:
        route = "/devices/combined/host-group-members/v1?" + parse.urlencode({
            "id": group_id, "limit": 500, "offset": offset,
        })
        response = api(base, route, token)
        records = response.get("resources", [])
        for record in records:
            if not isinstance(record, dict):
                raise RuntimeError("Unexpected group-member response; cannot verify membership")
            if record.get("device_id", "").lower() == aid.lower():
                return record
        if len(records) < 500:
            return None
        offset += len(records)
        if offset >= 1000000:
            raise RuntimeError("Group pagination limit reached; membership remains unverified")


def record_group_ids(record):
    if not record:
        return []
    groups = record.get("groups") or []
    return [g.get("id") if isinstance(g, dict) else g for g in groups]


def is_member(base, token, group_id, aid):
    return group_id in record_group_ids(member_record(base, token, group_id, aid))


def diagnose(base, token, group_id, aid):
    if not re.match(r"[0-9a-fA-F]{32}\Z", aid) or aid == "0" * 32:
        raise RuntimeError("Invalid or missing host registration identifier")
    route = "/devices/queries/host-group-members/v1?" + parse.urlencode({
        "id": group_id, "filter": "device_id:'{}'".format(aid.lower()), "limit": 1,
    })
    filtered = aid.lower() in api(base, route, token).get("resources", [])
    record = member_record(base, token, group_id, aid)
    groups = record_group_ids(record)
    print("AID_PREFIX={}".format(aid[:12]))
    print("FILTERED_MEMBER_QUERY={}".format(str(filtered).lower()))
    print("UNFILTERED_GROUP_RECORD={}".format(str(record is not None).lower()))
    print("HOSTNAME={}".format(record.get("hostname", "unknown") if record else "not_found_in_group"))
    print("HOST_GROUP_FIELD={}".format("misc1_present" if group_id in groups else "misc1_absent_or_unavailable"))
    print("GROUP_IDS={}".format(",".join(str(g) for g in groups) or "none"))
    if group_id not in groups:
        raise RuntimeError("Read-only check: misc1 is NOT confirmed in the host groups field; no changes made")


def enroll(base, token, group_id, aid):
    if not re.match(r"[0-9a-fA-F]{32}\Z", aid) or aid == "0" * 32:
        raise RuntimeError("Invalid or missing host registration identifier")
    aid = aid.lower()
    # Submit the additive action once. Cloud synchronization is asynchronous;
    # installation does not wait for group membership to appear in inventory.
    payload = {
        "ids": [group_id],
        "action_parameters": [{"name": "filter", "value": "(device_id:['{}'])".format(aid)}],
    }
    api(base, "/devices/entities/host-group-actions/v1?action_name=add-hosts", token, body=payload)


def main():
    fields = getattr(sys.stdin, "buffer", sys.stdin).read().decode("utf-8").split("\0")
    if len(fields) != 7 or fields[-1] != "":
        raise RuntimeError("Invalid private request format")
    action, client_id, secret, cloud, group_id, aid, _ = fields
    if action not in ("preflight", "enroll", "verify"):
        raise RuntimeError("Unknown group action")
    if not re.match(r"[0-9a-fA-F]{32}\Z", group_id):
        raise RuntimeError("Invalid group ID")
    if not client_id or not secret:
        raise RuntimeError("Missing API credentials")
    region, token = authenticate(client_id, secret, cloud)
    base = CLOUDS[region]
    group = validate_group(base, token, group_id)
    if action == "preflight":
        print("Group preflight OK: {} ({})".format(group["name"], group["group_type"]), file=sys.stderr)
        print(region)
    elif action == "verify":
        print("CLOUD={}".format(region))
        print("GROUP_NAME={} GROUP_TYPE={}".format(group["name"], group["group_type"]))
        diagnose(base, token, group_id, aid)
        print("GROUP=VERIFIED_HOST_FIELD {}".format(group["name"]))
    else:
        enroll(base, token, group_id, aid)
        print("GROUP=SUBMITTED {} (membership verification skipped)".format(group["name"]))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("GROUP=FAILED: {}".format(exc), file=sys.stderr)
        sys.exit(31)
FALCON_HOST_GROUP_CODE
)
join_misc1() {
    printf '%s\0%s\0%s\0%s\0%s\0%s\0' "$1" "$FALCON_CLIENT_ID" "$FALCON_CLIENT_SECRET" \
      "$FALCON_CLOUD" 'f21f4746723b4e4994c26d8b566fcab2' "${2:-}" | "$json_python" -c "$group_code"
}
printf 'SCRIPT_VERSION=2026-10-21.3\n'
case "${1:-install}" in
    install|--verify-group) ;;
    *) echo 'Usage: bash falcon-host-install.sh [--verify-group]'; exit 2 ;;
esac
if [[ "${1:-install}" == --verify-group ]]; then
    echo 'MODE=READ_ONLY_GROUP_CHECK'
    [[ -x /opt/CrowdStrike/falconctl ]] || { echo 'falconctl is not installed'; exit 21; }
    aid=$(/opt/CrowdStrike/falconctl -g --aid)
    aid_value=$(printf '%s\n' "$aid" | sed -n 's/^aid="*\([0-9a-fA-F]\{32\}\)"*\.*$/\1/p')
    join_misc1 verify "$aid_value"
    exit 0
fi
# Check credentials and target group before changing the host.
FALCON_CLOUD=$(join_misc1 preflight)
export FALCON_CLOUD
FALCON_BATCH_CHECK_ONLY=0
# Invoked over SSH by install-fleet.sh; do not put credentials in this file.
set +x
set -euo pipefail
umask 077
[[ $(id -u) -eq 0 ]] || { echo 'Root required; use root SSH or --sudo with sudo -n.' >&2; exit 10; }

printf 'HOST=%s\nKERNEL=%s\nARCH=%s\n' "$(hostname)" "$(uname -r)" "$(uname -m)"
if [[ -r /etc/os-release ]]; then
    grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' /etc/os-release || true
elif [[ -r /etc/redhat-release ]]; then
    cat /etc/redhat-release
fi
command -v systemctl >/dev/null || { echo 'Unsupported by this wrapper: systemctl missing.' >&2; exit 11; }

already_installed=0
if [[ -e /opt/CrowdStrike/falconctl ]]; then
    already_installed=1
elif command -v rpm >/dev/null && rpm -q falcon-sensor >/dev/null 2>&1; then
    already_installed=1
elif command -v dpkg-query >/dev/null && \
        [[ $(dpkg-query -W -f='${Status}' falcon-sensor 2>/dev/null || true) == 'install ok installed' ]]; then
    already_installed=1
fi

if [[ "$already_installed" -eq 1 ]]; then
    echo 'INSTALL=SKIPPED_EXISTING (no upgrade, restart or CID change)'
elif [[ "$FALCON_BATCH_CHECK_ONLY" -eq 1 ]]; then
    echo 'INSTALL=NEEDS_INSTALL'
    exit 3
else
    [[ -n "${FALCON_CLIENT_ID:-}" && -n "${FALCON_CLIENT_SECRET:-}" ]] || {
        echo 'Missing API credentials; refusing AWS SSM fallback.' >&2; exit 12;
    }
    command -v curl >/dev/null || { echo 'Install curl first.' >&2; exit 13; }
    work_dir=$(mktemp -d /tmp/falcon-batch.XXXXXXXX)
    trap 'rm -f -- "$work_dir/install.sh"; rmdir -- "$work_dir"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL --connect-timeout 20 --max-time 180 --retry 3 \
        -o "$work_dir/install.sh" \
        https://raw.githubusercontent.com/crowdstrike/falcon-scripts/v1.14.0/bash/install/falcon-linux-install.sh
    # Only documented settings are exported by the wrapper. Do not enable bash -x.
    unset FALCON_ACCESS_TOKEN GET_ACCESS_TOKEN PREP_GOLDEN_IMAGE FALCON_UNINSTALL
    unset FALCON_INSTALL_ONLY FALCON_DOWNLOAD_ONLY FALCON_DEBUG
    bash "$work_dir/install.sh" < /dev/null
    echo 'INSTALL=COMPLETED'
fi

if ! systemctl is-active --quiet falcon-sensor; then
    echo 'HEALTH=FAILED_SERVICE' >&2
    systemctl status falcon-sensor --no-pager -l || true
    exit 20
fi
echo 'SERVICE=active'
[[ -x /opt/CrowdStrike/falconctl ]] || { echo 'falconctl missing or not executable.' >&2; exit 21; }
/opt/CrowdStrike/falconctl -g --version

# A fresh installation may need time to register. Existing hosts are checked once.
attempts=1
if [[ "$already_installed" -eq 0 && "$FALCON_BATCH_CHECK_ONLY" -eq 0 ]]; then attempts=12; fi
health_ok=0
for ((attempt=1; attempt<=attempts; attempt++)); do
    rfm=$(/opt/CrowdStrike/falconctl -g --rfm-state 2>/dev/null || true)
    aid=$(/opt/CrowdStrike/falconctl -g --aid 2>/dev/null || true)
    normalized_rfm=$(printf '%s' "$rfm" | tr -d '[:space:]"')
    aid_value=$(printf '%s\n' "$aid" | sed -n 's/^aid="*\([0-9a-fA-F]\{32\}\)"*\.*$/\1/p')
    case "$normalized_rfm" in
        rfm-state=false|rfm-state=false.)
            if [[ -n "$aid_value" && "$aid_value" != 00000000000000000000000000000000 ]]; then
                health_ok=1; break
            fi ;;
    esac
    if [[ "$attempt" -lt "$attempts" ]]; then sleep 5; fi
done
printf 'RFM=%s\n' "${rfm:-unavailable}"
if [[ -n "$aid_value" && "$aid_value" != 00000000000000000000000000000000 ]]; then
    echo 'AID=present (redacted)'
else
    echo 'AID=pending_or_unavailable'
fi
[[ "$health_ok" -eq 1 ]] || { echo 'HEALTH=FAILED_OR_PENDING; check RFM, registration and logs.' >&2; exit 22; }

# The registration identifier stays in process memory and is not logged.
join_misc1 enroll "$aid_value"
unset FALCON_CLIENT_ID FALCON_CLIENT_SECRET aid aid_value
printf '完成：%s 已安装/健康检查通过，已提交 misc1 入组请求（跳过结果核验）\n' "$(hostname)"
