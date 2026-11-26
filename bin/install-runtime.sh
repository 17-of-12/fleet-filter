#!/usr/bin/env bash
# install-runtime.sh - install the unattended scripts and units, and prove they match the repository.
#
# The failure this replaces: a bug is fixed in the repo, the installed copy at /usr/local/sbin keeps
# the old behaviour, and the timer runs the old code every thirty minutes. It looks like the fix did
# not work. Every script installed here is compared against the repository afterwards, and a
# difference is an installation failure, not a warning.

set -euo pipefail

REPO=${FLEET_FILTER_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
SBIN=${SBIN:-/usr/local/sbin}
UNITDIR=${UNITDIR:-/etc/systemd/system}
DRY_RUN=0

die() { echo "install-runtime: $*" >&2; exit 1; }
note() { echo "install-runtime: $*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --help|-h) sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

# script in bin/ -> installed name
SCRIPTS=(
    "cve-worker-drain.sh:fleet-filter-cve-worker-drain"
    "cve-worker.sh:fleet-filter-cve-worker"
    "cve-daily.sh:fleet-filter-cve-daily"
    "cve-dispatch.py:fleet-filter-cve-dispatch"
    "publish-policies.py:fleet-filter-publish-policies"
    "pr-review-worker.sh:fleet-filter-pr-review"
    "prs-needing-review.py:fleet-filter-prs-needing-review"
)
UNITS=(
    fleet-filter-cve-triage.service
    fleet-filter-cve-triage.timer
    fleet-filter-cve-worker.service
    fleet-filter-cve-worker.timer
    fleet-filter-policy-publish.service
    fleet-filter-policy-publish.timer
    fleet-filter-pr-review.service
    fleet-filter-pr-review.timer
)

install_one() {
    local source=$1 target=$2 mode=$3
    [ -f "$source" ] || die "missing source: $source"
    if [ "$DRY_RUN" -eq 1 ]; then
        note "would install $source -> $target ($mode)"
        return 0
    fi
    sudo install -m "$mode" "$source" "$target" || die "could not install ${target}"
    if ! cmp -s "$source" "$target"; then
        die "${target} does not match ${source} after install"
    fi
    note "installed ${target}"
}

for pair in "${SCRIPTS[@]}"; do
    install_one "${REPO}/bin/${pair%%:*}" "${SBIN}/${pair##*:}" 0755
done

for unit in "${UNITS[@]}"; do
    [ -f "${REPO}/systemd/${unit}" ] || continue
    install_one "${REPO}/systemd/${unit}" "${UNITDIR}/${unit}" 0644
done

if [ "$DRY_RUN" -eq 1 ]; then
    note "dry run: nothing installed, nothing to verify"
    exit 0
fi

sudo systemctl daemon-reload || die "daemon-reload failed"
note "units reloaded"

# The check that makes this worth running: what is installed is what was tested.
for pair in "${SCRIPTS[@]}"; do
    installed="${SBIN}/${pair##*:}"
    repo_copy="${REPO}/bin/${pair%%:*}"
    [ -f "$installed" ] || die "${installed} is missing"
    cmp -s "$repo_copy" "$installed" || die "${installed} differs from ${repo_copy}"
done
note "installed scripts match the repository"
