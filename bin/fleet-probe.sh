#!/bin/sh
# Bundle K2 fleet probe - read-only, no state changes on the target.
#
# Purpose: emit one compact, parseable line describing the host's Apache exposure so a
# multi-host sweep produces a table instead of one multi-line dump per host. Every field
# degrades to a literal marker (`none` / `-`) rather than failing, because "package not
# installed" and "query failed" must both be distinguishable from "host unreachable" - a
# probe that errors out and a host that has no Apache are different answers, and conflating
# them is how a sweep silently loses half its population.
#
# Which hosts get probed is not this script's question. The host list comes from
# `web/installs.yaml` (see `bin/fleet-exposure.py`); it is never another project's inventory.
#
# Fields (pipe-separated, no value may contain a pipe):
#   os         distribution string (drives whether rpm or dpkg is the right query)
#   httpd      httpd / apache2 package nvra, or `none`
#   httpd_ver  httpd version as reported by rpm, or `-`
#   h2         mod_http2 package nvra, or `-` (rpm-only; the CVE-2026-119618 surface)
#   h2_ver     mod_http2 version, or `-`
#   ssl        mod_ssl package nvra, or `-`
#   ports      listening TCP ports among 80/443/8080/8443/8000 (what is actually exposed)
#   selinux    getenforce output where available (Stage 3 needs this per host)
#
# Two traps found by running this against the real fleet:
#   1. `rpm -q <pkg>` on a host lacking the package prints "package httpd is not
#      installed" on **stdout** and exits 1. Capturing stdout alone records that sentence
#      as if it were a version string, so `rpm_q` checks the exit status and rejects the
#      sentinel text.
#   2. Parsing the version out of an nvra is not reliable - `httpd-2.4.62-13.0.1.el9_8.9`
#      splits ambiguously between name and version. Ask rpm for `%{VERSION}` directly
#      (`rpm_qv`) instead of reconstructing it; that is why the version is a separate
#      field rather than derived downstream.

# rpm_q <package> -> prints the installed nvra, or prints nothing and returns non-zero.
rpm_q() {
    out="$(rpm -q "$1" 2>/dev/null)" || return 1
    case "$out" in
        "package "*" not installed"*) return 1 ;;
        "") return 1 ;;
    esac
    printf '%s' "$out"
}

# rpm_qv <package> -> prints the installed *version* only, or nothing if not installed.
rpm_qv() {
    out="$(rpm -q --qf '%{VERSION}' "$1" 2>/dev/null)" || return 1
    [ -n "$out" ] || return 1
    printf '%s' "$out"
}

if [ -r /etc/os-release ]; then
    . /etc/os-release
    os="$PRETTY_NAME"
else
    os="unknown"
fi
# os-release values can themselves contain quotes; strip them so the field separator
# stays unambiguous for the parser.
os="$(printf '%s' "$os" | tr -d '\"|')"

httpd="$(rpm_q httpd)"
httpd_ver="$(rpm_qv httpd)"
if [ -z "$httpd" ]; then
    # Debian/Ubuntu name the package apache2. dpkg-query prints just `apache2` with an
    # empty Version when the package is known but NOT installed, which is the dpkg
    # analogue of the rpm sentinel trap - the first version of this probe recorded estate-09 as
    # "apache2 installed" when `command -v apache2` proves there is no binary. Require an
    # installed status *and* a non-empty version, then confirm the binary exists.
    dpk_status="$(dpkg-query -W -f='${Status}' apache2 2>/dev/null)"
    dpk_ver="$(dpkg-query -W -f='${Version}' apache2 2>/dev/null)"
    case "$dpk_status" in
        *"install ok installed"*) ;;
        *) dpk_ver="" ;;
    esac
    if [ -n "$dpk_ver" ] && command -v apache2 >/dev/null 2>&1; then
        httpd="apache2-$dpk_ver"
        httpd_ver="$dpk_ver"
    fi
fi
[ -n "$httpd" ] || httpd="none"
[ -n "$httpd_ver" ] || httpd_ver="-"

h2="$(rpm_q mod_http2)";      [ -n "$h2" ] || h2="-"
h2_ver="$(rpm_qv mod_http2)"; [ -n "$h2_ver" ] || h2_ver="-"

ssl="$(rpm_q mod_ssl)";       [ -n "$ssl" ] || ssl="-"

ports="$(ss -ltnH 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un \
         | grep -E '^(80|443|8080|8443|8000)$' | paste -sd, -)"
[ -n "$ports" ] || ports="none"

sel="$(command -v getenforce >/dev/null 2>&1 && getenforce 2>/dev/null)"
[ -n "$sel" ] || sel="n/a"

printf 'os=%s|httpd=%s|httpd_ver=%s|h2=%s|h2_ver=%s|ssl=%s|ports=%s|selinux=%s\n' \
    "$os" "$httpd" "$httpd_ver" "$h2" "$h2_ver" "$ssl" "$ports" "$sel"
