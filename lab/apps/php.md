# PHP runbooks

## Versions and images

- `docker.io/library/php:8.4.26-apache` builds a full Apache+mod_php target from one image; the
  fleet's `ff-php` is the same image family.
- PHP's security releases land most months (8.4.x), so **check the affected range against the
  version in the image before building anything**. A victim outside the range cannot reproduce the
  bug however the payload is shaped - that mistake was made once with a WordPress build and once
  would have been made with a PHP one.

## Preconditions the advisory assumes

- **Serializer state is not the image default.** `ff-php` runs with `session.serialize_handler = php`
  globally. Bugs that need `php_serialize` or `php_binary` written and `php` read require a victim
  whose ini says so, plus an application that switches the handler at runtime
  (`ini_set('session.serialize_handler', 'php')` before `session_start()`). See `lab/php-115560/`.
- `upload_progress.*` is disabled in most base images; enable it explicitly for upload-progress bugs.
- `use_strict_mode=0` is required for an attacker-chosen session id to be adopted.

## Build

```bash
podman run -d --name <name> --network <net> -p <port>:80 \
  -v "$PWD/lab/conf/99-vuln.ini:/usr/local/etc/php/conf.d/99-vuln.ini:ro" \
  -v "$PWD/lab/src:/var/www/html:ro" \
  docker.io/library/php:8.4.26-apache
```

Two containers from one image, differing by one ini line, gives the mitigated twin - the control arm -
which is required evidence, not an optional extra.

## Verification

- The request that proves it: run the PoC and show it working (`uid=33` is the apache user).
- The negative control: the same request with the ini line flipped must fail. If it does not, the
  "vulnerability" is the application's behaviour, not the bug.

## Walls

- `php://input` does not see multipart bodies. A bug in multipart parsing needs a different probe.
- FastCGI bugs need a literal `SCRIPT_FILENAME` no front end rewrites; nginx in front of FPM is the
  way to make that unavoidable.
- A 404 from a REST route is often a rewrite/permalinks problem, not a missing route.
