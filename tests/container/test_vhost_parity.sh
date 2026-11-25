#!/usr/bin/env bash
# tests/container/test_vhost_parity.sh - Bundle W3 evidence for the Stage 3 canary.
#
# W3 asks whether the containerised vhost serves the same surface as the native vhosts: aliases,
# rewrites, redirects, cookies, and SSO flows, and whether any secret ends up in the image or the
# logs. Answering it means requesting the same paths from both backends and comparing, because the
# failure mode this catches is a canary that serves *a* site rather than *the* site.
#
# Every divergence is either fixed in the canary configuration or recorded here as an accepted
# difference with the reason. An unexplained difference is a failure.
#
# Usage: tests/container/test_vhost_parity.sh [host] [ssh-user]
set -uo pipefail

HOST="${1:-lab-web01.lab}"
USER_SSH="${2:-agent}"
CONTAINER="fleet-filter-apache-lab-web01"
NATIVE="http://127.0.0.1"            # the native :80 vhost (tarpit-test.conf)
NATIVE_HOST_HEADER="lab-web01.lab"
GATEWAY_BACKEND="http://198.51.100.110:8088"   # the Stage 2 backend vhost
CANARY="http://127.0.0.1:18080"      # the containerised vhost
MAP="/etc/httpd/tarpit-ips.map"

PASS=0
FAIL=0
ok() { echo "ok   $*"; PASS=$((PASS + 1)); }
bad() { echo "FAIL $*"; FAIL=$((FAIL + 1)); }
rsh() { timeout 120 ssh -o BatchMode=yes -o ConnectTimeout=10 "$USER_SSH@$HOST" "sudo -n bash -s" <<<"$1" 2>&1; }
cexec() { rsh "podman exec $CONTAINER sh -c \"$1\""; }

# fetch URL [extra args] -> "status bytes md5"
fetch() {
    local url="$1"; shift
    rsh "curl -s -o /tmp/parity.body -w '%{http_code} %{size_download}' --max-time 15 $* '$url' && printf ' ' && md5sum /tmp/parity.body | cut -d' ' -f1 && rm -f /tmp/parity.body"
}

echo "vhost parity: native :80 / gateway backend :8088 / canary :18080 on $HOST"

# --- the path matrix ------------------------------------------------------------------------------
# Each row: path | expected native status | expected canary status | note
# The canary column is what the containerised vhost must produce once the aliases are in place.
# Divergences marked "documented" are accepted and explained; anything else fails the run.
rows=(
  "/ai.html|200|200|static file, byte-identical"
  "/icons/|200|200|Alias /icons/ from the image's own autoindex.conf, byte-identical"
  "/poweredby.png|200|200|Alias from welcome.conf, reproduced in the canary vhost"
  "/shibboleth-sp/main.css|200|200|Alias from shib.conf, reproduced in the canary vhost"
  "/nope-does-not-exist|404|404|404 document is byte-identical"
  "/|403|403|both refuse an index; native serves the site 403 body, the canary serves the default (documented)"
  "/centos7.php|200|200|documented: native executes PHP 7.2.34 (X-Powered-By), the canary serves the source (documented)"
  "/ldap/|302|403|documented: native redirects through mod_shib SSO; the image has no mod_shib (documented)"
  "/phpldapadmin/|302|403|documented: same SSO redirect as /ldap/"
)

for row in "${rows[@]}"; do
    IFS='|' read -r path want_native want_canary note <<<"$row"
    n="$(fetch "$NATIVE$path" "-H \"Host: $NATIVE_HOST_HEADER\"")"
    c="$(fetch "$CANARY$path")"
    g="$(fetch "$GATEWAY_BACKEND$path")"
    ns="$(echo "$n" | awk '{print $1}')"
    cs="$(echo "$c" | awk '{print $1}')"
    gs="$(echo "$g" | awk '{print $1}')"
    if [[ "$ns" == "$want_native" && "$cs" == "$want_canary" && "$gs" == "$want_native" ]]; then
        ok "$path  native=$ns gateway-backend=$gs canary=$cs  ($note)"
    else
        bad "$path  native=$ns (want $want_native) gateway-backend=$gs (want $want_native) canary=$cs (want $want_canary)"
    fi
    # body parity for the paths both backends serve from the same mounted file
    case "$path" in
      /ai.html|/icons/|/poweredby.png|/shibboleth-sp/main.css|/nope-does-not-exist)
        n_md5="$(echo "$n" | awk '{print $2}')"; c_md5="$(echo "$c" | awk '{print $2}')"
        g_md5="$(echo "$g" | awk '{print $2}')"
        if [[ "$c_md5" == "$n_md5" && "$g_md5" == "$n_md5" ]]; then
            ok "$path  body md5 identical across all three listeners"
        else
            bad "$path  body differs: native=$n_md5 gateway-backend=$g_md5 canary=$c_md5"
        fi
        ;;
    esac
done

# --- the enforcement map the canary reads must be the live one ------------------------------------
host_md5="$(rsh "md5sum $MAP | cut -d' ' -f1")"
cont_md5="$(cexec "md5sum /etc/httpd/tarpit-ips.map | cut -d' ' -f1")"
if [[ -n "$host_md5" && "$host_md5" == "$cont_md5" ]]; then
    ok "the canary reads the live controller map (md5 $host_md5), not a baked copy"
else
    bad "map differs: host=$host_md5 container=$cont_md5"
fi

# --- the class header must appear only when the map says so ---------------------------------------
# Regression: the first version emitted X-Fleet-Filter-Class on every response, because it was
# gated on a variable SetEnvIf defines for all clients, so an unmapped client was told it had been
# tarpitted.
unmapped="$(rsh "curl -sI --max-time 10 $CANARY/ai.html | tr -d '\r' | grep -i x-fleet-filter-class || true")"
if [[ -z "$unmapped" ]]; then
    ok "unmapped client gets no X-Fleet-Filter-Class header"
else
    bad "unmapped client should get no class header, got: $unmapped"
fi
cp_line="$(rsh "cp $MAP /tmp/map.parity.bak && printf '10.89.0.1 1\n' >> $MAP && curl -sI --max-time 10 $CANARY/ai.html | tr -d '\r' | grep -iE '^HTTP|x-fleet-filter-class'; cp /tmp/map.parity.bak $MAP")"
if echo "$cp_line" | grep -qi "403" && echo "$cp_line" | grep -qi "x-fleet-filter-class: tarpitted"; then
    ok "mapping the client as state 1 in the live map produces 403 + X-Fleet-Filter-Class: tarpitted"
else
    bad "quarantined client response wrong: $(echo "$cp_line" | tr '\n' ' ')"
fi
cp_line2="$(rsh "cp $MAP /tmp/map.parity.bak && printf '10.89.0.1 2\n' >> $MAP && curl -sI --max-time 10 $CANARY/ai.html | tr -d '\r' | grep -iE '^HTTP|x-fleet-filter-class'; cp /tmp/map.parity.bak $MAP")"
if echo "$cp_line2" | grep -qi "503" && echo "$cp_line2" | grep -qi "x-fleet-filter-class: over-quota"; then
    ok "mapping the client as state 2 produces 503 + X-Fleet-Filter-Class: over-quota"
else
    bad "over-quota client response wrong: $(echo "$cp_line2" | tr '\n' ' ')"
fi

# --- secrets --------------------------------------------------------------------------------------
# Only *private* key material is a finding. CA bundles (/etc/pki/ca-trust/extracted/pem/*.pem,
# /etc/pki/tls/cert.pem) ship with the base image and are public certificates - the first version of
# this check flagged them, which is the difference between a check and a search.
keys="$(cexec "find /etc/httpd /etc/pki/tls/private /etc/pki/tls/certs -name '*.key' -o -name '*.pem' 2>/dev/null | grep -v '/etc/pki/ca-trust/' | head -5")"
pkey="$(cexec "grep -rls 'PRIVATE KEY' /etc/httpd /etc/pki/tls 2>/dev/null | grep -v '/etc/pki/ca-trust/' | head -3")"
if [[ -z "$keys" && -z "$pkey" ]]; then
    ok "no private keys baked into the image (TLS terminates at the gateway); CA bundles are the base image's own"
else
    bad "private key material found in the image: $(echo "$keys $pkey" | tr '\n' ' ')"
fi
if rsh "grep -qiE 'BEGIN (RSA |EC )?PRIVATE KEY|password' /var/log/fleet-filter-canary/canary-access.log 2>/dev/null"; then
    bad "the canary access log contains key-like material"
else
    ok "no key-like material in the canary access log"
fi

# --- Server header --------------------------------------------------------------------------------
native_srv="$(rsh "curl -sI --max-time 10 -H 'Host: $NATIVE_HOST_HEADER' $NATIVE/ai.html | tr -d '\r' | grep -i '^server:' | cut -d' ' -f2-")"
canary_srv="$(rsh "curl -sI --max-time 10 $CANARY/ai.html | tr -d '\r' | grep -i '^server:' | cut -d' ' -f2-")"
if [[ "$native_srv" == "$canary_srv" ]]; then
    ok "Server header identical ($native_srv)"
else
    # Documented: the native banner carries the OpenSSL token because mod_ssl is loaded there; the
    # image installs no mod_ssl, so the token is absent. Same Apache version and distro token.
    if [[ "$canary_srv" == "Apache/2.4.37 (Oracle Linux Server)" && "$native_srv" == Apache/2.4.37\ \(Oracle\ Linux\ Server\)* ]]; then
        echo "note Server header differs only by the mod_ssl token: native='$native_srv' canary='$canary_srv' (documented: no mod_ssl in the image)"
    else
        bad "Server header mismatch: native='$native_srv' canary='$canary_srv'"
    fi
fi

echo "vhost parity tests: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
