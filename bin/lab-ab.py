#!/usr/bin/env python3
"""A/B two rule sets against the same recorded session and show exactly what changed.

Purpose
-------
"Does this signature help?" is answerable only by sending the same requests at two configurations
and diffing. Doing that by hand means remembering the old numbers, and remembering is how a change
gets credited with an improvement it did not make. This runs each variant on its own port with its
own map and spool, replays one recorded session at each, and prints the rows that differ.

Design notes
------------
* **The rule set is a render, not an edit.** Each variant is a policy file produced by
  `bin/render-gateway-detection.py --exclude/--only`, so an A/B run leaves the signature store
  untouched and `git status` clean. The variant's provenance line records which rule set it was.
* **State is reset per variant.** A fresh map, spool and store directory per run: a replay otherwise
  inherits the quarantine the previous variant created, and the second variant would look stricter
  only because it ran second.
* **Isolation is a separate client address.** The recorded session sends signature probes from their
  own source, so a variant that detects them changes those rows and nothing else - a diff that
  ripples through every row cannot be read.
* **The replay itself is `bin/lab-session.py --replay`**, so there is one implementation of "send the
  recorded requests" and an A/B result is the same artifact as a normal session.

Usage
-----
    bin/lab-ab.py --session data/lab/sessions/ab-baseline \\
        --variant baseline=var/lab-gw/policy-baseline.toml \\
        --variant with-traversal=var/lab-gw/policy-traversal.toml
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_GATEWAY = os.path.expanduser("~/.cache/fleet-filter-gateway/target/release/fleet-filter-gateway")


def wait_for_port(host, port, timeout=10.0):
    """Poll a TCP port until it accepts, so a reply is never sent at a gateway still starting."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def prepare_variant(name, policy_path, port, run_root):
    """Materialise one variant: its own state directories and a policy bound to its own port."""
    root = os.path.join(run_root, name)
    for sub in ("spool", "tls"):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    map_path = os.path.join(root, "tarpit-ips.map")
    if os.path.exists(map_path):
        os.remove(map_path)

    with open(policy_path) as handle:
        text = handle.read()
    # Rewrite only the keys that have to differ between variants; everything else - the backend, the
    # detection set, the deception profiles - stays exactly as the policy file states it.
    lines = []
    for line in text.split("\n"):
        if line.startswith("bind = "):
            line = 'bind = "127.0.0.1:%d"' % port
        elif line.startswith("map = "):
            line = 'map = "%s"' % map_path
        elif line.startswith("dir = "):
            line = 'dir = "%s"' % os.path.join(root, "spool")
        lines.append(line)
    rendered = os.path.join(root, "policy.toml")
    with open(rendered, "w") as handle:
        handle.write("\n".join(lines))
    return {"name": name, "root": root, "policy": rendered, "port": port, "map": map_path,
            "spool": os.path.join(root, "spool"), "db": os.path.join(root, "state.db"),
            "source_policy": os.path.abspath(policy_path)}


def port_free(port):
    """True when nothing is listening, so a leftover process cannot answer in our gateway's place."""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.3):
            return False
    except OSError:
        return True


def run_variant(gateway, variant, session, extra_args=()):
    """Start a gateway for one variant, replay the session against it, stop it, return the session dir."""
    log_path = os.path.join(variant["root"], "gateway.log")
    if not port_free(variant["port"]):
        # This bit once: a gateway left over from an earlier run held the port, `wait_for_port`
        # returned happily, and the replay was answered by a process with a stale 300 s detection
        # memo. The A/B reported a difference between rule sets that was really a difference between
        # two processes. Refusing to run is the only honest option.
        return None, ("port %d is already in use - a leftover gateway would answer the replay "
                      "instead of this variant" % variant["port"])
    with open(log_path, "w") as log:
        process = subprocess.Popen([gateway, "--policy", variant["policy"]],
                                   stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_for_port("127.0.0.1", variant["port"]):
            if process.poll() is not None:
                with open(log_path) as handle:
                    return None, "gateway exited: %s" % handle.read()[-400:]
            return None, "gateway did not listen on %d" % variant["port"]
        # The port being open is not proof it is *our* gateway; the log line is.
        with open(log_path) as handle:
            startup = handle.read()
        if "listening on 127.0.0.1:%d" % variant["port"] not in startup:
            return None, "the process on %d is not this variant's gateway" % variant["port"]
        argv = [sys.executable, os.path.join(REPO_ROOT, "bin", "lab-session.py"),
                "--replay", session, "--url", "https://127.0.0.1:%d" % variant["port"],
                "--policy", variant["policy"], "--map", variant["map"], "--spool", variant["spool"],
                "--db", variant["db"], "--gateway-log", log_path,
                "--reset-map"] + list(extra_args)
        proc = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        output = proc.stdout.decode("utf-8", "replace")
        # lab-session names the replay session directory in its first line.
        target = ""
        for line in output.splitlines():
            if line.startswith("replay: "):
                target = line[len("replay: "):].strip()
                break
        return target, ("" if proc.returncode == 0 else output[-600:])
    finally:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()


def load_rows(session_dir):
    """Read a session's request rows, keyed by sequence number."""
    path = os.path.join(session_dir, "requests.jsonl")
    if not os.path.exists(path):
        return {}
    with open(path) as handle:
        return {row["seq"]: row for row in (json.loads(line) for line in handle if line.strip())}


def verdict(row):
    """The two things that decide whether the answer changed: status and deception profile."""
    return "%s/%s" % (row.get("status"), (row.get("deception") or "none").split(";")[0])


def main(argv=None):
    """Replay one session against several rule sets and report the rows that differ."""
    parser = argparse.ArgumentParser(description="A/B rule sets against a recorded session")
    parser.add_argument("--session", required=True, help="recorded session directory to replay")
    parser.add_argument("--variant", action="append", required=True, metavar="NAME=POLICY",
                        help="a rule set to try; repeat for each arm (at least two)")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY)
    parser.add_argument("--port-base", type=int, default=8500)
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)

    variants = []
    for index, spec in enumerate(args.variant):
        name, _, policy = spec.partition("=")
        if not policy:
            sys.stderr.write("--variant needs NAME=POLICY, got %r\n" % spec)
            return 2
        variants.append(prepare_variant(name, policy, args.port_base + index,
                                        os.path.join(REPO_ROOT, "var", "ab")))

    results = {}
    for variant in variants:
        session_dir, error = run_variant(args.gateway, variant, args.session)
        if session_dir is None:
            sys.stderr.write("%s: %s\n" % (variant["name"], error))
            return 1
        results[variant["name"]] = (session_dir, load_rows(session_dir), variant)

    base_name = variants[0]["name"]
    base_rows = results[base_name][1]
    sequences = sorted(base_rows)
    notes = {seq: base_rows[seq].get("note", "") for seq in sequences}
    paths = {seq: base_rows[seq].get("path", "") for seq in sequences}

    header = "%-4s %-34s %s" % ("seq", "path", " ".join("%-22s" % name for name in results))
    print(header)
    print("-" * len(header))
    differences = []
    for seq in sequences:
        cells = []
        for name, (_, rows, _) in results.items():
            row = rows.get(seq)
            cells.append("%-22s" % (verdict(row) if row else "missing"))
        changed = len({c.strip() for c in cells}) > 1
        if changed:
            differences.append(seq)
        print("%-4d %-34s %s%s" % (seq, paths[seq][:34], " ".join(cells), "  <-- differs" if changed else ""))

    print("\ndiffering rows: %s" % (", ".join(str(seq) for seq in differences) or "none"))
    for seq in differences:
        print("  seq %d: %s" % (seq, notes[seq]))

    out_dir = args.out or os.path.join(REPO_ROOT, "var", "ab",
                                       "ab-%s" % time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
    os.makedirs(out_dir, exist_ok=True)
    summary = {
        "session": os.path.abspath(args.session), "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                              time.gmtime()),
        "variants": {v["name"]: {"policy": v["source_policy"], "sessions": results[v["name"]][0],
                                 "rows": {str(seq): verdict(results[v["name"]][1].get(seq, {}))
                                          for seq in sequences}}
                     for v in variants},
        "differing_rows": {str(seq): notes[seq] for seq in differences},
    }
    with open(os.path.join(out_dir, "summary.json"), "w") as handle:
        json.dump(summary, handle, indent=2, sort_keys=True)
    print("\nsummary: %s" % os.path.join(out_dir, "summary.json"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
