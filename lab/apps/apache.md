# Apache httpd runbooks

## Versions

- Path traversal in 2.4.49/2.4.50 (`CVE-2021-41773` / `-42013`) does not exist in 2.4.66 - the
  version is the vulnerability for these, and a "victim" on a current release proves nothing.
- `httpd:2.4.66` is the fleet's `ff-apache` image and the base for CGI/FastCGI shapes.
- Check `mod_cgi` / `mod_cgid` presence: traversal-to-RCE needs CGI enabled, traversal-to-read does
  not. A build without it can only demonstrate file disclosure.

## Build

```bash
podman run -d --name <name> -p <port>:80 \
  -v "$PWD/lab/apache/httpd.conf:/usr/local/apache2/conf/httpd.conf:ro" \
  -v "$PWD/lab/src:/usr/local/apache2/htdocs:ro" \
  docker.io/library/httpd:2.4.49
```

`Require all granted` on `/` (not just `DocumentRoot`) is what makes traversal reachable at all.

## Verification

- Traversal: request the encoded dot-dot spelling and show `/etc/passwd` content, then the same
  request against a patched twin returning 400 or 403.
- CGI: `/cgi-bin/printenv` proves the handler is live before blaming a payload.

## Walls

- `%2e` capitalisation: the signature store matches literal lowercase spellings; uppercase is a known
  gap. Do not "fix" a failing PoC by lowercasing it without recording that the shipped signature has
  the same limit.
- h2 CVEs (mod_http2) need HTTP/2 negotiated - curl over TLS with `--http2`, not plain HTTP/1.1.
