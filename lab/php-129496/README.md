# CVE-2026-129496 lab victim

A victim that runs **the PHP the fleet actually deployed** in the configuration the advisory
names, so the CVE can be reproduced at all - and a patched twin so "the fix stops it" is a
measured fact rather than a version number.

| | |
|---|---|
| CVE | CVE-2026-129496 - Timezone cache use-after-free can lead to remote code execution. NVD (2026-11-19, `security@php.net`) / GHSA-gr4f-wgx5-jpfv: affected **< 8.2.36, 8.3.* < 8.3.37, 8.4.* < 8.4.28, 8.5.* < 8.5.13**, NTS builds only |
| Base image | `docker.io/library/php:8.4.26-apache` - **the fleet's own deployed PHP** (`ff-php` runs this exact image, and 8.4.26 < 8.4.28 is inside the range); `php:8.4.28-apache` is the patched twin |
| Reference code | https://github.com/abraxas/php-tzcache-rce and https://github.com/evenomn/CVE-2026-129496 (the two labs that reproduce against real mod_php; `poc.py` here ports their request builder and crash detection), https://github.com/googlesky/CVE-2026-129496 (C-harness reproduction, source of the `/check` spelling), https://github.com/cveForge/CVE-2026-129496 (generic scanner, documented in `poc.py` header) |
| PoC | `poc.py` in this directory - request builder + crash classification ported from the references, plus a `check` mode that reads the victim's own `phpinfo()` and refuses wrong victims the way the references do |
| Deployed as | `ff-php-129496` on `ff-apache02` (10.20.0.226):8101 (vulnerable), `ff-php-129496-mit`:8102 (vendor-mitigated ini twin), `ff-php-129496-patched`:8103 (same app/ini on patched php:8.4.28-apache) |

## Why this victim had to be built

Step 0 of the skill - confirm the deployed version is in range before building anything -
has an unusual answer here: **it is**. The fleet's `ff-php` is `php:8.4.26-apache` and the
advisory range is `8.4.* before 8.4.28`, so the fleet's own engine is an affected version
(unlike CVE-2026-129474, whose range was 8.5-only and needed an out-of-fleet version).
For `cveForge`'s contradictory banner ("Affected Version < 8.4.5 / Patch 8.4.5 / 8.3.19")
see the note in `poc.py`'s header - the vendor record is what the lab is built against, and
the other three references agree with the vendor.

Being in range is not sufficient for this CVE, and this is the same rule that moved
lab/php-115560 off `ff-php`: **the bug needs a configuration, and `ff-php` does not have
it.** The advisory's first sentence limits the bug to "non-thread-safe builds [in which] a
diagnostic written to a file-based error_log during module startup [...] causes the timezone
cache to be allocated in startup memory that is freed while a reference to it is kept".
`ff-php` runs a valid timezone (no startup diagnostic) and logs through Apache (not PHP's
file log), so on `ff-php` the freed pointer never exists and a null result would prove
nothing. Adding the pair to `ff-php` would also mutate the victim every recorded PHP2SHELL
run is measured against. The pair therefore gets its own container - built from the **same
base image `ff-php` runs**, so the version-check row of the checklist is verified against
the fleet's own version number and not a nearby one.

Three containers come from one Containerfile, so the comparisons are facts about the build:

- `:8101` - `php:8.4.26-apache` + `conf/99-vuln.ini`: the two lines the advisory names
  (`error_log = /var/log/php-error.log`, `date.timezone = Not/AZone`) plus `memory_limit =
  2M`, the value the reference labs set so a normal-sized POST aborts the request the way
  the exploit needs. Serves the lab app whose front controller is the reference's own
  two-line page plus the worker pid.
- `:8102` - the same base and app with `conf/99-mitigated.ini`: one line differs,
  `date.timezone = Etc/UTC` - the first mitigation the vendor's fix text names ("correct
  the setting that prints at startup"). With a resolvable zone, startup emits no diagnostic,
  the cache is never allocated on the freed heap, and the same oversized POST must be
  answered instead of killing the worker: the causality control for the entry.
- `:8103` - `php:8.4.28-apache` with `conf/99-vuln.ini`: the fixed engine with the same
  vulnerable ini. This is the fix side of the pair (the fix, commit `cb20015e`, formats
  startup log timestamps in UTC outside a live request instead of touching the cache), and
  the PoC's own range check refuses it as "out of range" the way the references' does.

## The application and why it looks like this

The reference app (abraxas/lab/www/index.php) is one line:
`echo "CVE-2026-129496-ALIVE " . PHP_SAPI;` - the app's content cannot matter, because the
exploit kills the worker during request parsing, before any application code of the *next*
request-shape runs. Two lab additions and one mapping, each with a reason:

- **the app echoes `getmypid()`** - the references answer "did the worker die" with
  `docker exec` + a `/proc` scan (evenomn `Target.alive()`); over HTTP the app can answer
  it itself (ask before, ask after, compare pids). The recorded A/B and the direct run read
  this line instead of needing exec access to the container.
- **`src/info.php`** (`phpinfo()`) is the `check` mode's read surface - the same thing
  lab/php-129474/poc.py built, because scraping phpinfo is how the references fingerprint a
  victim they cannot exec into.
- **`FallbackResource /index.php`** in `conf/apache-lab.conf` makes every non-file path -
  `/check` included - run the front controller. `/check` is the path the googlesky harness
  serves (and the store variant carries, next to `/index.php`); as a real-file-only app it
  would 404 at Apache and never reach the vulnerable PHP. `AllowOverride None` on this
  image rules out the `.htaccess` a real vhost would use, the fact lab/php-129474 recorded.

## Changes made to the reference code, and why

| change | reason |
|---|---|
| `poc.py` is a port, not a copy | no single reference ships a stdlib-only script that works against an arbitrary host: abraxas's script is docker-exec-bound to its own compose project, evenomn's exploits via `docker exec` too, googlesky's targets a C harness. The ported pieces (each named in the docstring): abraxas `POST_BODY` + `send()` + the check refusal wording; evenomn `http_post()`'s reset classification and report shape; murrez's `RE_WORKER_FAULT`/`RE_OOM_109618` as carried by lab/php-129474/poc.py. |
| the token is `base64("u:\0")`, not a forged payload | the RCE demonstrations put the forged destructor table in the **Authorization header** (evenomn `forge()`); the crash itself does not read the token. The header is still sent - the reference request always carries it, and the store's shape documents it - but a lab that did the forging would need the addresses of that particular container, which is the reference's own "known addresses, lab-proven" caveat, not something the gateway A/B needs. |
| `display_errors = On` (abraxas ships `Off`) | the patched/mitigated twins' answer is their evidence ("HTTP 500 + `Allowed memory size of 2097152 bytes exhausted`"); with display_errors Off the body is empty and the response proves less. Same reasoning recorded in lab/php-129474/conf/99-vuln.ini. |
| one Containerfile, three tags (`ARG PHP_VERSION` + `ARG LAB_INI`) | the twins differ by exactly one base version or one ini line - the sibling labs' pattern (lab/php-115560, lab/php-129474), copied so no comparison can be blamed on a hand-edited Dockerfile. |
| `--size` defaults to 3 MiB | abraxas' `POST_BODY` constant (their container's `memory_limit=2M`, `post_max_size=8M`), so the default request is byte-compatible with their exploit's body. |

## Running it

```sh
cd lab/php-129496
podman build --build-arg PHP_VERSION=8.4.26 --build-arg LAB_INI=conf/99-vuln.ini      -t localhost/ff-php-129496:8.4.26-vuln .
podman build --build-arg PHP_VERSION=8.4.26 --build-arg LAB_INI=conf/99-mitigated.ini -t localhost/ff-php-129496:8.4.26-mit .
podman build --build-arg PHP_VERSION=8.4.28 --build-arg LAB_INI=conf/99-vuln.ini      -t localhost/ff-php-129496:8.4.28-patched .
podman run -d --name ff-php-129496          -p 8101:80 localhost/ff-php-129496:8.4.26-vuln
podman run -d --name ff-php-129496-mit      -p 8102:80 localhost/ff-php-129496:8.4.26-mit
podman run -d --name ff-php-129496-patched  -p 8103:80 localhost/ff-php-129496:8.4.28-patched
python3 poc.py check    --target http://10.20.0.226:8101   # the vulnerable pair, from the victim itself
python3 poc.py exploit  --target http://10.20.0.226:8101   # the reference request: reset + new worker pid
python3 poc.py exploit  --target http://10.20.0.226:8103   # the patched twin: HTTP 500, app answered
```
