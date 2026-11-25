# Bundle S validation — policy-as-data on a live gateway (S6)

Host: `lab-web01.lab` · Date: 2026-11-14 (UTC) · Binary: `fleet-filter-gateway 0.1.0`
sha256 `955c9f0332c966be85eb7c04f1c9142c6606fcfde60d8074450f5ca4e13d64db` (EL8 image build,
rustc 1.92.0-1.module+el8.10.0+90888+4ecfbbd1, recorded in
`data/artifacts/fleet-filter-gateway-0.1.0-8bccbac.json`)

Policy under test: `gateway/policies/lab-web01.toml`, deployed to
`/etc/fleet-filter-gateway/policy.toml` (0644 root:fleet-filter-gw, md5 `3c544ec2559af5784137eddf26a9eede`),
sha256 `fa965ac447cc1322d8c5f4093484f04df424d20a1e5636ca13072c3ea2af0635`.
Pre-change backups on the host: `/root/backups/20261114T194338Z-bundle-s-deploy/`.

Every claim below is a command and its captured output. Where a claim could not be exercised on
this host, it says so instead of being inferred.

---

## S1 — bundle format: versioned, hashed, schema-validated

The deployed binary parses the deployed file and reports its identity. Run as the service account,
not as root, so "the service can read this" is what is actually being tested:

```
$ sudo -u fleet-filter-gw /usr/local/bin/fleet-filter-gateway \
      --policy /etc/fleet-filter-gateway/policy.toml --show-policy
policy version=lab-web01-s1 mode=serve posture=standard bind=198.51.100.111:8443
backend=http://198.51.100.110:8088 tls=yes alpn=h2+http/1.1 on_quarantined=proxy
sha256=fa965ac447cc1322d8c5f4093484f04df424d20a1e5636ca13072c3ea2af0635
```

The hash is over the parsed content, not the file bytes, so a comment edit does not change the
policy identity while a value edit does (see the S2 swap, where the sha changes with the version).

Schema coverage exercised by this bundle: `[policy]` (schema_version 1, mode), `[listener]`
(bind, tls_cert, tls_key, alpn), `[limits]` (five caps - `max_connections`,
`max_connections_per_source`, `max_body_bytes`, `max_headers`, and `header_read_timeout_secs`
added 2026-11-15 as an optional key defaulting to 30 so pre-existing bundles still parse),
`[routing]` (backend, forward_headers),
`[quarantine]` (map, ttl, memo ttl, fallback, on_quarantined), `[spool]` (dir, min_interval,
max_entries), `[detection]` (prefixes, signature references), `[posture]` (active profile, method
allowlist, header/content-type allowlists, URL-shape bounds, TLS floor, admission cap).

The JSON example below is the s1-era bundle as it was first reported; the key added on 2026-11-15
changes the content hash, so the live answer on lab-web01 now differs and is collected with the
same command rather than by editing this record.

## S4 — per-host installed-policy version reporting

`--show-policy-json` is the machine-readable answer the fleet report collects over SSH, and it does
not require the service to be running:

```
$ sudo -u fleet-filter-gw /usr/local/bin/fleet-filter-gateway \
      --policy /etc/fleet-filter-gateway/policy.toml --show-policy-json
{"schema_version":"1","version":"lab-web01-s1","generated_at":"2026-11-14T19:40:00Z",
 "source_commit":"ff6039d","sha256":"fa965ac447cc1322d8c5f4093484f04df424d20a1e5636ca13072c3ea2af0635",
 "mode":"serve","posture":"standard","bind":"198.51.100.111:8443","backend":"http://198.51.100.110:8088",
 "alpn":"h2,http/1.1","tls_floor":"1.2","max_connections":"512","max_connections_per_source":"16",
 "max_body_bytes":"8388608","max_headers":"100","quarantine_map":"/etc/httpd/tarpit-ips.map",
 "quarantine_fallback":"allow","on_quarantined":"proxy",
 "spool_dir":"/var/lib/fleet-filter-gateway/spool","spool_min_interval":"300","spool_max_entries":"10000",
 "detect_prefixes":"/h2probe-","signatures":"CVE-2026-119618:probe_path",
 "methods":"GET,HEAD,POST,PUT,DELETE,OPTIONS,PATCH","header_names":"","content_types":"",
 "max_path_bytes":"4096","max_query_bytes":"4096","max_path_segments":"128"}
```

Two answers exist and they mean different things, which matters during a rollout:

* `--show-policy` describes the **file** on disk. If the file is corrupt it says so
  (`Error: "unknown table `[bogus]` in policy bundle"`) instead of reporting a policy the host is
  not running.
* the **running** policy is the one named in the journal's `policy reload ...` line (S2 below).
  During the corrupt-file test the file was invalid while the process was still serving `s2`, and
  both facts were separately observable.

The systemd unit was changed at the same time to pass only `--policy` and `--author`: precedence in
the binary is flag > bundle > default, so leaving the old `--bind/--backend/--tls-*/--max-connections`
flags in place would have silently overridden the bundle for every field they named, and
`--show-policy` would have described a policy the process was not using.

## S2 — hot reload, atomic swap, keep-last-known-good

Accepted swap (file replaced, `SIGHUP`, no restart):

```
$ sudo systemctl kill --signal=SIGHUP fleet-filter-gateway
policy reload ok: policy version=lab-web01-s1 mode=serve posture=standard bind=198.51.100.111:8443
 backend=http://198.51.100.110:8088 tls=yes alpn=h2+http/1.1 on_quarantined=proxy
 sha256=fa965ac447cc1322d8c5f4093484f04df424d20a1e5636ca13072c3ea2af0635
 -> policy version=lab-web01-s2 mode=serve posture=standard bind=198.51.100.111:8443
 backend=http://198.51.100.110:8088 tls=yes alpn=h2+http/1.1 on_quarantined=proxy
 sha256=af4289b4744b315c9ac5213bfe6875b73842dc24618adb0272eb7f1c9e8db5f0
```

Rejected update (bundle gains an unknown table; the process must keep the previous policy):

```
$ sudo systemctl kill --signal=SIGHUP fleet-filter-gateway
policy reload rejected: unknown table `[bogus]` in policy bundle (keeping policy version=lab-web01-s2
 mode=serve posture=standard bind=198.51.100.111:8443 backend=http://198.51.100.110:8088 tls=yes
 alpn=h2+http/1.1 on_quarantined=proxy sha256=af4289b4744b315c9ac5213bfe6875b73842dc24618adb0272eb7f1c9e8db5f0)

$ systemctl is-active fleet-filter-gateway
active
$ curl -k --interface 198.51.100.111 -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" https://198.51.100.111:8443/
HTTP 403 in 0.049214s
```

The candidate is built and validated (parsed, schema-checked, TLS loaded) before the swap, so the
rejection is a decision about the file, not a crash: the service stayed `active` and kept serving in
49 ms. The swap itself is one `Arc` store, so a connection in flight is served entirely by the
configuration it was accepted with — never by a half-applied pair.

## S3 — posture profiles

`GET` on the standard profile passes; a method outside the allowlist is answered locally and names
the rule that fired, which is what makes a rejection debuggable from the client side alone:

```
$ curl -i -X PROPFIND -k --interface 198.51.100.111 https://198.51.100.111:8443/
HTTP/2 405
server: fleet-filter-gateway/0.1.0
content-type: text/plain; charset=utf-8
x-fleet-filter-posture: method_not_allowed
content-length: 110
```

Profile rules exercised on this host: method allowlist (above), TLS floor and ALPN (S1/S4 output
shows `tls_floor=1.2`, `alpn=h2,http/1.1`, and the listener is built from those values), and the
request path itself (h1 and h2 both served, so URI checks ran on both protocol shapes).

Not exercised here, and not claimed: header-name allowlist and Content-Type allowlist are empty in
this bundle (`header_names=""`, `content_types=""`), so their reject branches were only covered by
unit tests, and `admission_cap_per_authority = 0` means the per-authority cap is disabled. The
empty-value configuration is the honest choice for a test listener: turning them on would reject
normal browser traffic on a host whose job is to keep serving the Stage 1 content.

## S5 — kill switch without a restart

Bundle switched to `mode = "paused"`, reloaded with `SIGHUP`, then two requests issued (a normal
path and a detection path). Backend log and spool were counted before and after:

```
$ sudo systemctl kill --signal=SIGHUP fleet-filter-gateway
policy reload ok: policy version=lab-web01-s2 mode=serve ... -> policy version=lab-web01-s1 mode=paused ...

$ curl -k --interface 198.51.100.111 -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" https://198.51.100.111:8443/
HTTP 503 in 0.050218s
$ curl -i -k --interface 198.51.100.111 https://198.51.100.111:8443/h2probe-8888888
HTTP/2 503
server: fleet-filter-gateway/0.1.0
content-type: text/plain; charset=utf-8
x-fleet-filter-posture: paused

backend access log lines: 899 -> 899 (delta 0)   # contacted no backend
gateway spool files:      1 -> 1   (delta 0)     # filed no claim
```

Restoring `mode = "serve"` the same way brought the backend back on the next request:

```
$ sudo systemctl kill --signal=SIGHUP fleet-filter-gateway
policy reload ok: policy version=lab-web01-s1 mode=paused ... -> policy version=lab-web01-s1 mode=serve ...
$ curl -k --interface 198.51.100.111 -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n" https://198.51.100.111:8443/
HTTP 403 in 0.048303s
backend access log lines: 899 -> 900 (delta 1)
```

This is the mitigation-speed property S5 exists for: pausing the gateway took one file write and one
signal, and it did not stop the listener or drop the socket.

## S5 (rings) — what is and is not derived

The bundle now carries the version string that a ring report groups on (`lab-web01-s1`), and the
inventory already separates `.test.lab` / `.dev.example.edu` from production
(`~/projects/ansible-estate/inventories/production/hosts.yaml`, 132 hosts, measured in Bundle
K2). What is **not** done: no host other than lab-web01 has a gateway installed, so the ring
sequence (test → dev → production batches) has one member in the first ring and cannot be exercised
until Stage 2 is offered to a second host. Recording that as a gap rather than closing it on paper.

## Regression check against the pre-Bundle-S binary

Same request, three paths, one body — the Bundle S rewrite did not change what the gateway returns:

```
$ curl -s --http1.1 -k --interface 198.51.100.111 -o /dev/null -w "%{http_code} %{size_download}" https://198.51.100.111:8443/
403 3539   md5 3ded5567f8a88938b83c2cd0c544f3c6
$ curl -s --http2    -k --interface 198.51.100.111 -o /dev/null -w "%{http_code} %{size_download}" https://198.51.100.111:8443/
403 3539   md5 3ded5567f8a88938b83c2cd0c544f3c6
$ curl -s http://198.51.100.110:8088/            # direct Apache, for comparison
403 3539   md5 3ded5567f8a88938b83c2cd0c544f3c6
```

## Gaps and follow-ups

1. **Rings need a second host.** S5's ring ordering is defined but only lab-web01 runs Stage 2, so
   the promotion path is untested (see above).
2. **Header and Content-Type allowlists are unexercised in production shape.** Their empty
   configuration is deliberate; enabling them on a real vhost is the test, and it belongs with the
   first production-ring host rather than being simulated here.
3. **`--show-policy` reads the file, not the process.** A host whose unit points at a different path
   than the one being queried will report that file's version. The fix is procedural (always query
   the path in the unit) and mechanical later (have the unit export `Environment=POLICY=...`), not a
   code change worth making before a second host exists.
4. **Bundle T (inline deception) is still open**, so `on_quarantined = proxy` remains the only
   quarantined-client behaviour in use; `reject` is implemented and unit-tested but not exercised on
   a live quarantined client in this bundle.
