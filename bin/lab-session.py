#!/usr/bin/env python3
"""Record a full gateway-in-front experiment so it can be replayed and argued with later.

Purpose
-------
The first live run of something is the most informative data the project will ever get, and it is
usually lost to scrollback. This writes a **self-describing session directory**: every request with
its timing and the answer it got, the gateway's own log of its decisions, the claims it spooled, every
map render, and the victim's access log for the same seconds. Then `--replay` sends the same request
list at a different configuration and writes the same schema, so two sessions diff row by row instead
of being remembered.

Design notes
------------
* **Two client sources, on purpose.** `127.0.0.1` is the attacker and `127.0.0.2` is a bystander.
  Quarantine is per source, so a single-source session cannot show whether a tarpit hit the attacker
  only or took innocent traffic with it - which is the false-positive question the whole design turns
  on. `--interface` binds the client, so this needs no extra host.
* **curl, not urllib**, because the experiment needs real HTTP/2 with ALPN, and because `-w '%{json}'`
  reports timings measured inside the client rather than around the process.
* **The victim's log is sliced by byte offset**, recorded at session start, so the session contains
  exactly the requests it made and not a month of background noise from the lab.
* **Nothing is inferred after the fact.** The drain is run by the recorder, mid-session, and its output
  and the map before/after are recorded: the session shows the chain happening rather than asserting
  that it would.
* **`--replay` re-sends the recorded request spec**, not the current code's idea of a probe list - a
  replay that regenerates its input is a new experiment.

Usage
-----
    bin/lab-session.py --name front-2.4.49 --url https://127.0.0.1:8443 \\
        --victim operator@10.20.0.226:/var/lib/lib/ff-httpd/2.4.49 --drain
    bin/lab-session.py --replay data/lab/sessions/front-2.4.49 --url https://127.0.0.1:9443
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SESSIONS = os.path.join(REPO_ROOT, "data", "lab", "sessions")

BROWSER_UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")
ATTACKER = "127.0.0.1"
BYSTANDER = "127.0.0.2"
# A third source for signature A/B. Its own address because quarantine is per source: if the
# traversal came from the attacker, a policy that detects it would quarantine the attacker and every
# later row would change too, which turns a one-signature comparison into an unreadable diff.
SIGNATURE = "127.0.0.3"

# The probe list IS the experiment. Each entry is a request the recorder sends and later replays.
# `group` decides when the drain runs: everything before "after" is pre-drain, everything after it is
# answered with the map already rendered.
PROBES = (
    # First, from an otherwise unused source, so the A/B comparison sees exactly one changed row.
    {"group": "signature", "source": SIGNATURE, "method": "GET",
     "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd", "ua": "curl/8.18.0",
     "note": "CVE-2021-41773 encoded traversal: the signature A/B target"},
    {"group": "signature", "source": SIGNATURE, "method": "GET",
     "path": "/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/etc/passwd", "ua": "curl/8.18.0",
     "note": "CVE-2021-42013 double-encoded traversal"},
    {"group": "signature", "source": SIGNATURE, "method": "POST",
     "path": "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "ua": "curl/8.18.0",
     "data": "echo Content-Type: text/plain; echo; id",
     "note": "traversal to /bin/sh, the RCE shape"},
    {"group": "signature", "source": SIGNATURE, "method": "GET", "path": "/.env",
     "ua": "curl/8.18.0", "note": "control: a probe with no signature in the store"},

    {"group": "baseline", "source": BYSTANDER, "method": "GET", "path": "/",
     "ua": BROWSER_UA, "note": "bystander baseline: normal visit"},
    {"group": "baseline", "source": BYSTANDER, "method": "GET", "path": "/index.html",
     "ua": BROWSER_UA, "note": "bystander baseline: second request"},
    {"group": "baseline", "source": ATTACKER, "method": "GET", "path": "/nope-404",
     "ua": "curl/8.18.0", "note": "attacker, harmless: is the source clean before the exploit"},

    {"group": "exploit", "source": ATTACKER, "method": "GET", "path": "/h2probe-12075394",
     "ua": "curl/8.18.0", "note": "CVE-2026-119618 probe_path - the only enforced signature prefix"},
    {"group": "exploit", "source": ATTACKER, "method": "GET", "path": "/wp-json/batch/v1",
     "ua": "curl/8.18.0", "note": "CVE-2026-63030 enforced prefix"},
    {"group": "exploit", "source": ATTACKER, "method": "POST", "path": "/.env",
     "ua": "curl/8.18.0", "note": "credential probe, no signature"},
    {"group": "exploit", "source": BYSTANDER, "method": "GET", "path": "/",
     "ua": BROWSER_UA, "note": "bystander during exploitation: must stay fast"},

    {"group": "raw", "source": ATTACKER, "raw": "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
     "note": "h2c preface on a cleartext socket: logged as method PRI"},

    {"group": "after", "source": ATTACKER, "method": "GET", "path": "/h2probe-22222222",
     "ua": "curl/8.18.0", "note": "attacker after the drain: should be quarantined and dripped"},
    {"group": "after", "source": ATTACKER, "method": "GET", "path": "/",
     "ua": "curl/8.18.0", "note": "attacker after quarantine, benign path: is the whole source dripped"},
    {"group": "after", "source": BYSTANDER, "method": "GET", "path": "/",
     "ua": BROWSER_UA, "note": "bystander after the drain: must be untouched"},
)


def now():
    """UTC ISO-8601 with microseconds - the format every row in the session uses."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_bytes(data):
    """Hex digest, used for bodies and artifacts so a session can prove what it captured."""
    return hashlib.sha256(data).hexdigest()


def run(argv, **kwargs):
    """Run a subprocess and return (returncode, stdout, stderr) without raising on failure."""
    kwargs.setdefault("stdout", subprocess.PIPE)
    kwargs.setdefault("stderr", subprocess.PIPE)
    kwargs.setdefault("timeout", 120)
    try:
        proc = subprocess.run(argv, **kwargs)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.SubprocessError) as error:
        return 127, b"", str(error).encode()


def victim_log_offset(victim):
    """Byte length of the victim's access log right now, so the session can slice its own lines."""
    user_host, _, path = victim.partition(":")
    code, out, _ = run(["ssh", "-i", os.path.expanduser("~/.ssh/fleet_dispatch_key"),
                        "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
                        user_host, "sudo -n stat -c %%s %s/log/access_log" % path.rstrip("/")])
    return int(out.decode().strip()) if code == 0 and out.strip().isdigit() else 0


def victim_log_tail(victim, offset):
    """Read the victim's access log from `offset` to now."""
    user_host, _, path = victim.partition(":")
    log = "%s/log/access_log" % path.rstrip("/")
    code, out, err = run(["ssh", "-i", os.path.expanduser("~/.ssh/fleet_dispatch_key"),
                          "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "LogLevel=ERROR",
                          user_host, "sudo -n tail -c +%d %s" % (offset + 1, log)])
    return out.decode("utf-8", "replace") if code == 0 else "log read failed: %s" % err.decode()


def curl_request(url, probe, body_dir, seq, insecure=True):
    """Send one probe with curl and return the recorded row.

    Response headers go to a file because they carry the gateway's own verdict
    (`X-Fleet-Filter-Deception`), which is the difference between "the backend was slow" and "we
    decided to be slow".
    """
    body_path = os.path.join(body_dir, "%03d.body" % seq)
    header_path = os.path.join(body_dir, "%03d.headers" % seq)
    argv = ["curl", "-sS", "--path-as-is", "-o", body_path, "-D", header_path, "-w", "%{json}",
            "--max-time", "40", "--interface", probe["source"], "-X", probe["method"],
            "-H", "User-Agent: %s" % probe["ua"]]
    if insecure:
        argv.append("-k")
    for name in probe.get("headers", ()):
        argv += ["-H", name]
    if probe.get("data"):
        argv += ["--data-binary", probe["data"]]
    argv.append(url + probe["path"])

    started = now()
    code, out, err = run(argv)
    finished = now()

    metrics = {}
    try:
        metrics = json.loads(out.decode() or "{}")
    except ValueError:
        metrics = {"unparsed_writeout": out.decode("utf-8", "replace")[:200]}

    body = b""
    try:
        with open(body_path, "rb") as handle:
            body = handle.read()
    except OSError:
        pass
    headers = {}
    try:
        with open(header_path) as handle:
            for line in handle:
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip().lower()] = value.strip()
    except OSError:
        pass

    return {
        "seq": seq, "group": probe["group"], "note": probe["note"],
        "source": probe["source"], "method": probe["method"], "path": probe["path"],
        "url": url + probe["path"], "ua": probe["ua"],
        "started_at": started, "finished_at": finished,
        "curl_exit": code, "curl_error": err.decode("utf-8", "replace").strip()[:300],
        "status": metrics.get("http_code"), "http_version": metrics.get("http_version"),
        "time_total_s": metrics.get("time_total"), "time_starttransfer_s": metrics.get("time_starttransfer"),
        "size_download": metrics.get("size_download"), "remote_ip": metrics.get("remote_ip"),
        "request_body": (probe.get("data") or "")[:4096],
        "body_sha256": sha256_bytes(body), "body_bytes": len(body),
        "body_head": body[:160].decode("utf-8", "replace"),
        "deception": headers.get("x-fleet-filter-deception", ""),
        "server": headers.get("server", ""),
        "response_headers": headers,
    }


def raw_probe(url, probe, raw_dir, seq):
    """Send raw bytes on a cleartext socket and record what came back, hex-encoded.

    Some of the signature shapes are not expressible as an HTTP request (the RFC 7540 preface is the
    obvious one), so the session records bytes rather than pretending it can be a URL.
    """
    host, _, port = url.split("://", 1)[-1].partition(":")
    payload = probe["raw"].encode()
    started = now()
    received = b""
    error = ""
    try:
        with socket.create_connection((host, int(port or 80)), timeout=10) as connection:
            connection.sendall(payload)
            connection.settimeout(10)
            try:
                received = connection.recv(4096)
            except socket.timeout:
                received = b""
    except OSError as problem:
        error = str(problem)
    finished = now()

    with open(os.path.join(raw_dir, "%03d.sent.hex" % seq), "w") as handle:
        handle.write(payload.hex() + "\n")
    with open(os.path.join(raw_dir, "%03d.received.hex" % seq), "w") as handle:
        handle.write(received.hex() + "\n")

    return {
        "seq": seq, "group": probe["group"], "note": probe["note"], "source": "socket",
        "method": "RAW", "path": payload[:32].decode("latin-1").replace("\r", "\\r").replace("\n", "\\n"),
        "url": url, "ua": "", "started_at": started, "finished_at": finished,
        "curl_exit": 0 if not error else 1, "curl_error": error,
        "status": None, "http_version": None, "time_total_s": None, "time_starttransfer_s": None,
        "size_download": len(received), "remote_ip": None,
        "body_sha256": sha256_bytes(received), "body_bytes": len(received),
        "body_head": received[:160].hex(), "deception": "", "server": "", "response_headers": {},
    }


def wire_check(rows, victim_log):
    """Mark each HTTP row with whether the victim logged the path the row claims it sent.

    A recorder that trusts its own argv records intentions, not traffic: curl's default dot-segment
    squashing turned an encoded traversal into `/etc/passwd` on the wire while the row still said
    `/cgi-bin/.%2e/...`, and the first A/B run credited a signature for catching nothing. The log is
    the only witness, so the claim is only true if the log shows it.
    """
    targets = []
    for line in victim_log.splitlines():
        match = re.search(r'"([A-Z]+) (\S+)', line)
        if match:
            targets.append(match.group(2))
    if not victim_log.strip():
        # No log to compare against: every row would read as a mismatch, which is noise, not a
        # finding. Say the check did not run rather than that it failed.
        for row in rows:
            if row.get("method") != "RAW":
                row["wire_ok"] = None
                row["wire_note"] = "no victim log available"
        return rows
    for row in rows:
        if row.get("method") == "RAW":
            continue
        row["wire_targets_seen"] = sorted({target for target in targets if target == row["path"]})
        if row["path"] in targets:
            row["wire_ok"] = True
        elif row.get("deception"):
            # Answered by the gateway's own profile: the victim was never contacted, so its log is
            # right to be silent. Treating that as a mismatch would flag every detection as a
            # recording failure and train the reader to ignore the check.
            row["wire_ok"] = None
            row["wire_note"] = "answered inline, backend not contacted"
        else:
            row["wire_ok"] = False
            row["wire_note"] = "proxied but absent from the victim log"
    return rows


def drain(session_dir, gw_state):
    """Run the controller's spool drain and snapshot the map before and after."""
    map_path = gw_state["map"]
    before = ""
    if os.path.exists(map_path):
        with open(map_path) as handle:
            before = handle.read()
    # The controller's --db/--map are top-level options, so they must precede the subcommand;
    # passing them after `drain-spool` exits 2 and renders nothing, which is how the first recorded
    # session ended up with an empty map and a drain that looked like a config typo.
    argv = [sys.executable, os.path.join(REPO_ROOT, "controller", "adaptive-tarpit.py"),
            "--db", gw_state["db"], "--map", map_path,
            "drain-spool", "--spool", gw_state["spool"], "--render"]
    code, out, err = run(argv, timeout=180)
    after = ""
    if os.path.exists(map_path):
        with open(map_path) as handle:
            after = handle.read()
    with open(os.path.join(session_dir, "drain.log"), "w") as handle:
        handle.write("# argv: %s\n# exit: %d\n\n%s\n%s\n" % (" ".join(argv), code,
                                                             out.decode("utf-8", "replace"),
                                                             err.decode("utf-8", "replace")))
    with open(os.path.join(session_dir, "map-before.txt"), "w") as handle:
        handle.write(before)
    with open(os.path.join(session_dir, "map-after.txt"), "w") as handle:
        handle.write(after)
    return {"exit": code, "output": out.decode("utf-8", "replace").strip()[-500:],
            "map_before": before, "map_after": after}


def snapshot_spool(session_dir, spool_dir):
    """Copy every claim in the spool into the session, so the evidence survives the drain."""
    target = os.path.join(session_dir, "spool")
    os.makedirs(target, exist_ok=True)
    copied = []
    if not os.path.isdir(spool_dir):
        return copied
    for name in sorted(os.listdir(spool_dir)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(spool_dir, name)) as source:
            content = source.read()
        with open(os.path.join(target, name), "w") as destination:
            destination.write(content)
        copied.append(name)
    return copied


def manifest(args, session_dir):
    """Record what produced this session: commit, policy, store, tool versions, hosts."""
    def git(*argv):
        """Run a git command in the repo and return its stdout, or "" when it fails."""
        code, out, _ = run(["git", "-C", REPO_ROOT] + list(argv))
        return out.decode().strip() if code == 0 else ""

    info = {
        "recorded_at": now(), "name": args.name, "url": args.url, "victim": args.victim,
        "git_head": git("rev-parse", "HEAD"), "git_short": git("rev-parse", "--short", "HEAD"),
        "git_dirty": bool(git("status", "--porcelain")),
        "policy_path": args.policy, "policy_sha256": "", "store_sha256": "",
        "gateway_binary": args.gateway, "gateway_version": git(),
    }
    for key, path in (("policy_sha256", args.policy),
                      ("store_sha256", os.path.join(REPO_ROOT, "controller", "signatures",
                                                    "signatures.yaml"))):
        try:
            with open(path, "rb") as handle:
                info[key] = sha256_bytes(handle.read())
        except OSError:
            pass
    for argv in (["curl", "-V"], ["--version"]):
        code, out, _ = run([args.gateway] + argv if argv[0] == "--version" else argv)
        if code == 0:
            info.setdefault("tool_versions", {})[" ".join(argv)] = out.decode().splitlines()[0]
    code, out, _ = run(["ssh", "-i", os.path.expanduser("~/.ssh/fleet_dispatch_key"), "-o",
                        "BatchMode=yes", "-o", "ConnectTimeout=8", args.victim.split(":")[0],
                        "sudo -n podman ps --format '{{.Names}} {{.Image}} {{.Status}}'"])
    info["victim_containers"] = out.decode().strip().splitlines() if code == 0 else []
    return info


def main(argv=None):
    """Record one session, or replay a recorded one against a different URL."""
    parser = argparse.ArgumentParser(description="Record a gateway-in-front session")
    parser.add_argument("--name", default="")
    parser.add_argument("--probes", default="",
                        help="JSON file with the probe list; the default matrix is for the Apache "
                             "victims, and a different target (WordPress) needs its own experiment "
                             "without editing this script")
    parser.add_argument("--url", default="https://127.0.0.1:8443")
    parser.add_argument("--victim", default="")
    parser.add_argument("--no-victim-log", action="store_true",
                        help="the target has no access log we can read (a container serving from "
                             "stdout); skip the victim slice instead of pretending it is empty")
    parser.add_argument("--policy", default=os.path.join(REPO_ROOT, "var", "lab-gw", "policy.toml"))
    parser.add_argument("--gateway", default=os.path.expanduser(
        "~/.cache/fleet-filter-gateway/target/release/fleet-filter-gateway"))
    parser.add_argument("--gateway-log", default=os.path.join(REPO_ROOT, "var", "lab-gw", "gateway.log"))
    parser.add_argument("--spool", default=os.path.join(REPO_ROOT, "var", "lab-gw", "spool"))
    parser.add_argument("--map", default=os.path.join(REPO_ROOT, "var", "lab-gw", "tarpit-ips.map"))
    parser.add_argument("--db", default=os.path.join(REPO_ROOT, "var", "lab-gw", "state.db"))
    parser.add_argument("--drain", action="store_true", help="run the spool drain mid-session")
    parser.add_argument("--settle", type=float, default=0.0,
                        help="seconds to wait after the drain, to outlive the gateway's memo window "
                             "so a quarantine in the 'after' group can only be the map's doing")
    parser.add_argument("--replay", default="", help="replay a recorded session directory")
    parser.add_argument("--reset-map", action="store_true",
                        help="with --replay: delete the map first, because a replay inherits the "
                             "quarantine state the previous run left behind and a comparison that "
                             "starts from a different state is not a comparison")
    args = parser.parse_args(argv)

    if args.replay:
        return replay(args)

    name = args.name or "front-%s" % datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    session_dir = os.path.join(SESSIONS, name)
    for sub in ("bodies", "raw", "spool", "victim"):
        os.makedirs(os.path.join(session_dir, sub), exist_ok=True)

    probes = PROBES
    if args.probes:
        with open(args.probes) as handle:
            probes = json.load(handle)
    offset = victim_log_offset(args.victim) if args.victim else 0
    gateway_offset = os.path.getsize(args.gateway_log) if os.path.exists(args.gateway_log) else 0
    gw_state = {"map": args.map, "spool": args.spool, "db": args.db}
    rows, drains = [], []
    seq = 0
    for probe in probes:
        if probe["group"] == "after" and args.drain and not drains:
            copied = snapshot_spool(session_dir, args.spool)
            drains.append(dict(drain(session_dir, gw_state), claims_copied=copied))
            if args.settle:
                time.sleep(args.settle)
        seq += 1
        if "raw" in probe:
            rows.append(raw_probe(args.url, probe, os.path.join(session_dir, "raw"), seq))
        else:
            rows.append(curl_request(args.url, probe, os.path.join(session_dir, "bodies"), seq))

    claims = snapshot_spool(session_dir, args.spool)
    victim_log = victim_log_tail(args.victim, offset) if args.victim else ""
    rows = wire_check(rows, victim_log)
    with open(os.path.join(session_dir, "requests.jsonl"), "w") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    with open(os.path.join(session_dir, "victim", "access.log"), "w") as handle:
        handle.write(victim_log)

    gateway_log = ""
    try:
        with open(args.gateway_log) as handle:
            handle.seek(gateway_offset)
            gateway_log = handle.read()
    except OSError:
        pass
    with open(os.path.join(session_dir, "gateway.log"), "w") as handle:
        handle.write(gateway_log)

    info = manifest(args, session_dir)
    info.update({"requests": len(rows), "claims_in_spool": len(claims), "drains": drains,
                 "groups": sorted({row["group"] for row in rows})})
    with open(os.path.join(session_dir, "session.json"), "w") as handle:
        json.dump(info, handle, indent=2, sort_keys=True)

    print("session: %s" % session_dir)
    print("%3s %-9s %-6s %-32s %5s %7s %8s %s"
          % ("seq", "group", "src", "path", "stat", "seconds", "bytes", "deception"))
    for row in rows:
        print("%3d %-9s %-6s %-32s %5s %7s %8s %s" % (
            row["seq"], row["group"], row["source"].split(".")[-1], row["path"][:32],
            row["status"], row["time_total_s"], row["size_download"], row["deception"]))
    mismatched = [row["seq"] for row in rows if row.get("wire_ok") is False]
    print("claims spooled: %d | victims lines: %d | drains: %d | wire mismatches: %s"
          % (len(claims), len(victim_log.splitlines()), len(drains), mismatched or "none"))
    return 0


def replay(args):
    """Re-send a recorded session's request list at a new URL and record the same schema."""
    source_dir = args.replay
    if args.reset_map and os.path.exists(args.map):
        os.remove(args.map)
        print("map cleared: %s" % args.map)
    with open(os.path.join(source_dir, "requests.jsonl")) as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    name = "%s-replay-%s" % (os.path.basename(source_dir.rstrip("/")),
                             datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    session_dir = os.path.join(SESSIONS, name)
    for sub in ("bodies", "raw", "spool", "victim"):
        os.makedirs(os.path.join(session_dir, sub), exist_ok=True)

    offset = victim_log_offset(args.victim)
    copied = snapshot_spool(session_dir, args.spool)
    results = []
    for row in rows:
        probe = {"group": row["group"], "source": row["source"], "method": row["method"],
                 "path": row["path"], "ua": row["ua"], "note": row["note"],
                 "data": row.get("request_body") or None}
        if row["method"] == "RAW":
            results.append(raw_probe(args.url, dict(probe, raw=row["body_head"].encode().decode("latin-1")),
                                     os.path.join(session_dir, "raw"), row["seq"]))
        else:
            results.append(curl_request(args.url, probe, os.path.join(session_dir, "bodies"), row["seq"]))

    victim_log = victim_log_tail(args.victim, offset) if args.victim else ""
    results = wire_check(results, victim_log)
    with open(os.path.join(session_dir, "requests.jsonl"), "w") as handle:
        for row in results:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    with open(os.path.join(session_dir, "victim", "access.log"), "w") as handle:
        handle.write(victim_log)
    info = manifest(args, session_dir)
    # Every session.json carries the same keys, so a diff between a recording and a replay is a
    # diff of behaviour and not of schema.
    info.update({"replayed_from": os.path.abspath(source_dir), "requests": len(results),
                 "claims_in_spool": len(copied), "drains": [],
                 "groups": sorted({row["group"] for row in results})})
    with open(os.path.join(session_dir, "session.json"), "w") as handle:
        json.dump(info, handle, indent=2, sort_keys=True)

    print("replay: %s" % session_dir)
    for original, again in zip(rows, results):
        print("%3d %-32s %5s -> %5s  %6.3fs -> %6s  %s" % (
            original["seq"], original["path"][:32], original["status"], again["status"],
            float(original["time_total_s"] or 0), again["time_total_s"], again["deception"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
