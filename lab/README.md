# Lab victims

Deliberately vulnerable Apache images, one per CVE the project claims to defend against. They exist
so a signature is validated against a real victim instead of a fixture.

| Image | Version | CVE | Listener |
|---|---|---|---|
| `ff-httpd:2.4.66` | httpd 2.4.66 | CVE-2026-23918 - mod_http2 double free on early reset (fixed 2.4.67) | 8080 h2c, 8443 TLS/h2 |
| `ff-httpd:2.4.62` | httpd 2.4.62 | CVE-2026-119618 shape - mod_http2 `assign_headers` race (affects 2.4.55-2.4.70, fixed 2.4.71) | 8080/8443 |
| `ff-httpd:2.4.49` | httpd 2.4.49 | CVE-2021-41773 - path traversal with CGI (fixed 2.4.50/2.4.51) | 8080/8443 (or 8081/8444 beside another) |

## Build and run

```sh
# on the victim host, once per version
sudo podman build --build-arg HTTPD_VERSION=2.4.66 -t ff-httpd:2.4.66 lab/apache

# state is per version, not per host: the TLS identity and the access log must not be shared, or two
# victims interleave into one log and a captured line cannot be attributed to a version
sudo mkdir -p /var/lib/ff-httpd/2.4.66/{tls,log}
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=ff-httpd-2.4.66" \
     -keyout /var/lib/ff-httpd/2.4.66/tls/server.key -out /var/lib/ff-httpd/2.4.66/tls/server.crt
sudo chmod 600 /var/lib/ff-httpd/2.4.66/tls/server.key

# host networking, so the config's Listen directives are the host's ports
sudo podman run -d --name ff-httpd-2.4.66 --network host \
     -e LISTEN_PORT=8080 -e TLS_PORT=8443 \
     -v /var/lib/ff-httpd/2.4.66:/state:Z ff-httpd:2.4.66

# labelled traffic for the per-line model: every request carries its label in the User-Agent, so the
# label is recovered from the log rather than guessed by a human
bin/lab-capture.py --host <victim-address> --port 8080 --state /var/lib/ff-httpd/2.4.66 \
     --ffuf /path/to/ffuf --out data/lab/traffic-8080-<victim-address>.jsonl
```

Two versions on one host: give the second instance `LISTEN_PORT=8081 TLS_PORT=8444` and a different
`--name`.

## What each victim proves

* **2.4.66 / 2.4.62** - HTTP/2 request shapes. `Protocols h2 h2c http/1.1` and `H2Direct on` are the
  advisory workaround reversed: a victim that removed h2 cannot be exploited, and the point is to
  have one that can.
* **2.4.49** - the reliable app-level target: a `ScriptAlias` with `Require all granted` and
  `mod_cgid`, which is the documented precondition for CVE-2021-41773. Use it to give the deception
  path something real to answer, and as the base for the WordPress target.

## Safety

Victims are reachable only from the lab network, run as a container on a VM this project owns, and
carry no data. They are still exploit targets - assume one is compromised while it exists, and
rebuild from the image rather than trusting it afterwards.
