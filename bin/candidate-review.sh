#!/bin/bash
# Ask an agent whether a candidate is something this proxy can actually shield, and record the answer.
#
# The gap this fills: the triage funnel decides what has an exploitation signal, and the CVE worker
# assumes the answer is "yes, write a signature". Nothing in between says "this needs a
# pre-authenticated session", "this is a local privilege escalation wearing a network CVSS vector",
# or "there is no request shape because the bug is in a binary file format". Those judgements decide
# whether hours of exploit work should start at all, and they are exactly what a person used to do
# by reading the advisory.
#
# Two outcomes, both recorded:
#
#   accept   a request shape exists that this proxy can refuse. The item enters the work queue in
#            the same format bin/cve-dispatch.py writes, so the existing worker picks it up unchanged.
#   reject   not shieldable here, with a reason code. It does NOT go to blocked/ - blocked means the
#            loop tried and failed, and conflating "we chose not to" with "we could not" makes the
#            blocked directory lie.
#
# The reject reasons are a closed set on purpose, because "not a candidate" with no category is an
# opinion that cannot be reviewed later. The set is the line below and the parser honours it: a list
# in a comment is not an enforcement.
set -u -e -o pipefail

REPO="${FLEET_FILTER_REPO:-/home/user/projects/fleet-filter}"
QUEUE="${FLEET_FILTER_QUEUE:-/var/lib/fleet-filter/workqueue}"
DECISIONS="${FLEET_FILTER_DECISIONS:-/var/lib/fleet-filter/candidate-decisions.jsonl}"
LOG_DIR="${FLEET_FILTER_REVIEW_LOG:-/var/lib/fleet-filter/candidate-review}"
TIMEOUT="${CANDIDATE_REVIEW_TIMEOUT:-1800}"
REJECT_REASONS="needs-authentication local-only no-request-shape not-http already-covered"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
CANDIDATES="${1:-}"

usage() {
  cat <<'USAGE'
usage: candidate-review.sh <candidates.json> [--dry-run] [--replay <decisions.jsonl>]

  candidates.json  the queue from bin/cve-triage.py, or a list of {id, product, kev, epss}
  --replay FILE    use decisions already recorded instead of asking a session. This is how the chain
                   is tested, and how a decision is reapplied after a queue directory is lost - the
                   judgement was the expensive part and it is reproducible.

Decisions append to $FLEET_FILTER_DECISIONS (default /var/lib/fleet-filter/candidate-decisions.jsonl);
accepted items are written to $FLEET_FILTER_QUEUE (default /var/lib/fleet-filter/workqueue),
rejected ones never reach it.
USAGE
}

DRY_RUN=0
REPLAY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --replay) REPLAY="${2:-}"; [ -f "$REPLAY" ] || { echo "candidate-review: no such decisions file: $REPLAY" >&2; exit 2; }; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) CANDIDATES="$1"; shift ;;
  esac
done
if [ -z "$CANDIDATES" ] || [ ! -f "$CANDIDATES" ]; then
  usage
  exit 2
fi

mkdir -p "$LOG_DIR" "$QUEUE"
LOG="$LOG_DIR/$STAMP.log"
cd "$REPO" || exit 1

# The candidate list is small by construction; the prompt carries it inline so the session does not
# spend its budget rediscovering what the funnel already computed.
BRIEF=$(.venv/bin/python - "$CANDIDATES" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
items = data.get("queue", data) if isinstance(data, dict) else data
for item in items:
    print("- %s | %s | KEV=%s EPSS=%s | %s" % (
        item.get("id") or item.get("cve"), item.get("product", "?"),
        item.get("kev"), item.get("epss"), (item.get("description") or "")[:160]))
PY
)

read -r -d '' PROMPT <<PROMPT_END || true
You are reviewing CVE candidates for fleet-filter before any exploit work starts. fleet-filter is a
front proxy: it refuses HTTP requests whose shape matches a known exploit, before the request reaches
the origin server. A candidate is only worth a worker session if there is an HTTP request that this
proxy can recognise and refuse.

Candidates:

$BRIEF

For each one, decide accept or reject. Reject reasons are a closed set ($REJECT_REASONS):
  needs-authentication   the attacker must already be logged in; the proxy sees a legitimate session
  local-only             the bug is local or requires an existing foothold; not reachable by request
  no-request-shape       the exploit is in a file format, a background job, or a protocol this proxy
                         does not parse; there is nothing to match on
  not-http               the CVSS vector says network but the service is not HTTP/HTTPS
  already-covered        an existing signature in controller/signatures/signatures.yaml refuses it

Evidence rules: read the CVE description and, when a reference is available, the advisory. Do not
guess. If you cannot tell, the answer is accept - a worker session that concludes "not shieldable"
after looking at real exploit code costs an hour and produces a recorded reason; rejecting on a hunch
loses the candidate silently.

Output, and nothing else, one JSON object per line:
{"id": "CVE-...", "decision": "accept|reject", "reason": "<reason code or empty>", "why": "<one sentence>"}
PROMPT_END

{
  echo "== candidate review $STAMP"
  echo "== candidates: $CANDIDATES"
} >> "$LOG"

if [ "$DRY_RUN" = 1 ]; then
  echo "$PROMPT"
  exit 0
fi

if [ -n "$REPLAY" ]; then
  cp "$REPLAY" "$LOG"
  echo "== replayed decisions from $REPLAY" >> "$LOG"
  STATUS=0
else
  STATUS=0
  timeout "$TIMEOUT" pi -p "$PROMPT" 2>&1 | tee -a "$LOG" >/dev/null || STATUS=$?
fi

# Parse the decisions out of the transcript and file each one. A line that does not parse is treated
# as a missing decision, not as an accept: silence must not start work.
.venv/bin/python - "$LOG" "$QUEUE" "$DECISIONS" "$CANDIDATES" "$REJECT_REASONS" <<'PY'
import json, pathlib, sys, datetime
log, queue_dir, decisions_path, candidates_path, reasons_arg = sys.argv[1:6]
REJECT_REASONS = set(reasons_arg.split())
raw = pathlib.Path(log).read_text()
items = {i.get("id"): i for i in (json.load(open(candidates_path)).get("queue", [])
                                  if isinstance(json.load(open(candidates_path)), dict)
                                  else json.load(open(candidates_path)))}
seen = {}
for line in raw.splitlines():
    line = line.strip()
    if not line.startswith("{") or '"decision"' not in line:
        continue
    try:
        record = json.loads(line)
    except ValueError:
        continue
    if record.get("id") not in items:
        continue
    if record.get("decision") == "accept":
        # An accept needs no reason code; it needs the worker session that follows.
        seen[record["id"]] = record
    elif (record.get("decision") == "reject"
          and (record.get("reason") or "") in REJECT_REASONS):
        # A reject with an off-list reason is not a decision: the closed set exists so the ledger can
        # be argued with later, and `"reason": ""` on a reject is exactly the opinion that cannot be.
        seen[record["id"]] = record

with open(decisions_path, "a") as ledger:
    for cve_id, item in items.items():
        record = seen.get(cve_id) or {"id": cve_id, "decision": "missing",
                                      "reason": "", "why": "the review produced no decision"}
        ledger.write(json.dumps({**record, "at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(), "product": item.get("product"),
            "kev": item.get("kev"), "epss": item.get("epss")}) + "\n")
        if record["decision"] != "accept":
            print("  %-16s %-8s %s" % (cve_id, record["decision"], record.get("reason", "")))
            continue
        target = pathlib.Path(queue_dir) / (cve_id + ".json")
        target.write_text(json.dumps({
            "cve": cve_id, "product": item.get("product"), "kev": item.get("kev"),
            "epss": item.get("epss"), "matched_via": item.get("matched_via", "candidate-review"),
            "description": item.get("description", ""),
            "reference_code": item.get("poc") or [],
            "decision": "accepted by candidate review: " + record.get("why", ""),
            "definition_of_done": item.get("definition_of_done",
                "the exploit is demonstrated working without the control and failing through it, "
                "the evidence is a session an export can ship, and the ledger entry says which"),
        }, indent=2) + "\n")
        print("  %-16s accepted  %s" % (cve_id, record.get("why", "")))
PY

echo "== exit $STATUS at $(date -u +%Y%m%dT%H%M%SZ)" >> "$LOG"
exit "$STATUS"
