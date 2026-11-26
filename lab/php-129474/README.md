# CVE-2026-129474 lab victim

A victim that runs the PHP version and the application shape the advisory names, so the CVE can be
reproduced at all: every PHP this fleet already runs is **outside** the affected range.

| | |
|---|---|
| CVE | CVE-2026-129474 - use-after-free in magic method backtraces (`__call()`/`__callStatic()`), can lead to RCE. NVD (2026-11-19, `security@php.net`) / GHSA-8mjj-2r7p-4hg2: affected **>= 8.5.0, < 8.5.13**, patched in 8.5.13 |
| Base image | `docker.io/library/php:8.5.12-apache` - inside the affected range; `php:8.5.13-apache` is the patched twin |
| Reference code | https://github.com/cveForge/CVE-2026-129474 (the work item's `reference_code`) and https://github.com/murrez/php2shell/blob/a8e24f4efab57f67384909d9408e42a74b973bfb/poc.py#L808-L816 (an NVD-listed reference; `build_backtrace_json_probe_body` is the request builder `poc.py` here ports) |
| PoC | `poc.py` in this directory - request builder and response parser ported from the NVD-cited reference at the pinned commit, plus a `check` mode that reads the victim's own `phpinfo()` |
| Deployed as | `ff-php-129474` on `ff-apache02` (10.20.0.226):8098 (vulnerable), `ff-php-129474-mit`:8099 (the ini mitigation twin), `ff-php-129474-patched`:8100 (same app on patched 8.5.13) |

## Why this victim had to be built

The fleet's PHP estate is `8.4.26` (`ff-php`, `ff-fpm`; the two `ff-php-115560` containers carry the
same version). The vendor advisory - `security@php.net` via NVD and GHSA-8mjj-2r7p-4hg2 - states the
affected range as `>= 8.5.0, < 8.5.13`: **8.4.x is not affected** by this CVE. The same rule that
invalidated an out-of-range WordPress victim for CVE-2026-63030 applies here ("fix the victim, do not
push harder on the wrong one"), and the work item's own first task line asks for this confirmation
before anything is built.

The reference repository the item cites contradicts the vendor: `cveForge/CVE-2026-129474` prints
"Affected Version < 8.4.5 / Patch 8.4.5 / 8.3.19" in its README. Its `poc.py` is a generic
deserialization scanner (POSTs `data=O:8:"stdClass":...` to `/api/data` and looks for `unserialize()`
error strings) that carries the same banner across its CVE repos; the vendor record - which names the
mechanism, `__call()`/`__callStatic()` backtrace collection, and one fixed version, 8.5.13 - is what
the lab is built against. The NVD reference list also cites `murrez/php2shell`, whose
`php_version_in_129474_remote_range()` agrees with the vendor (`major == 8 and minor == 5`, patched at
8.5.13) and whose probe builder is the request this lab reproduces.

Three containers come from one Containerfile, so the comparisons are facts about the build:

- `:8098` - `php:8.5.12-apache` + `conf/99-vuln.ini`: the shipped defaults restated explicitly
  (`fatal_error_backtraces = On`, `zend.exception_ignore_args = Off` - the state the advisory says
  triggers the bug) and the app below.
- `:8099` - the same base and app with `conf/99-mitigated.ini` (`zend.exception_ignore_args = On`,
  the setting `php.ini-production` ships and the advisory names as preventing the bug). Running the
  request here is the causality control: the effect has to depend on that one line, not on the image.
- `:8100` - `php:8.5.13-apache` (the patched release) with `conf/99-vuln.ini`: proves the difference
  between it and `:8098` is the fix itself.

## The application and why it looks like this

The advisory's trigger is a *method call handled by `__call()`/`__callStatic()` whose arguments are
collected for a fatal-error backtrace*. That is an application property, and the NVD-cited reference
says the same ("Full RCE requires app `__call`/`__callStatic` + ini `fatal_error_backtraces` /
`ignore_args`"). The reference probe walks the app's API routes:

- the routes themselves (`/api/import`, `/import`, `/api/imports`, `/api/v1/import`,
  `/rest/V1/guest-carts/estimate-shipping-methods`, `/graphql` - `BACKTRACE_JSON_PROBE_PATHS`,
  `poc.py:96-105` of the pinned reference) exist only as **routes**, never as methods: `Api` defines
  no `import()`, so every dispatch of that route goes through `Api::__callStatic` and the request
  body rides into the call as the argument array the backtrace will later collect;
- the base image's Apache (`/etc/apache2`, `AllowOverride None` for `/var/www`) cannot honour an
  `.htaccess`, so the route-not-file mapping is installed as `conf/apache-lab.conf`
  (`FallbackResource /index.php` in `conf-enabled`) instead of the FrontController `.htaccess` a real
  vhost would carry;
- the endpoint's work is a normalisation copy of the received payload (`str_repeat($body, 4)` - four
  working copies per ingestion is ordinary format overhead, not a lab trick) and the app documents
  `memory_limit = 2M` for its API pool. A ~640 KiB probe body therefore normalises to ~2.6 MiB and
  the endpoint dies mid-work - the "fatal error ... while an application enters such a call" the
  advisory requires. A small GET of `/index.php` (a real file, served directly) never allocates and
  never fatals: that request is what the benign control uses.

## Changes made to the reference code, and why

| change | reason |
|---|---|
| app written from the advisory's mechanism instead of copied | the two reference repos ship no lab app (`cveForge` ships only a scanner; `murrez` ships one 5,815-line scanner + tests). The 115560 lab had a reference `lab/src` to copy; here the equivalent is the reference's own constants (`BACKTRACE_JSON_PROBE_PATHS`, the probe body builder) instantiated as real routes. |
| `ARG PHP_VERSION` + `ARG LAB_INI` in one Containerfile | three tags (vuln / mit / patched) from one file: `8.5.12-vuln`, `8.5.12-mit`, `8.5.13-patched` differ by exactly one base version or one ini line, never by a hand-edited Dockerfile. |
| `conf/apache-lab.conf` instead of `.htaccess` | the 8.5 base image installs Debian system Apache with `AllowOverride None`; an `.htaccess` FrontController rule would be read by nobody (measured - `/usr/local/etc/apache2` does not even exist on this image). |

## Running it

```sh
cd lab/php-129474
podman build --build-arg PHP_VERSION=8.5.12 --build-arg LAB_INI=conf/99-vuln.ini     -t localhost/ff-php-129474:8.5.12-vuln .
podman build --build-arg PHP_VERSION=8.5.12 --build-arg LAB_INI=conf/99-mitigated.ini -t localhost/ff-php-129474:8.5.12-mit .
podman build --build-arg PHP_VERSION=8.5.13 --build-arg LAB_INI=conf/99-vuln.ini     -t localhost/ff-php-129474:8.5.13-patched .
podman run -d --name ff-php-129474          -p 8098:80 localhost/ff-php-129474:8.5.12-vuln
podman run -d --name ff-php-129474-mit      -p 8099:80 localhost/ff-php-129474:8.5.12-mit
podman run -d --name ff-php-129474-patched  -p 8100:80 localhost/ff-php-129474:8.5.13-patched
python3 poc.py check   --target http://10.20.0.226:8098        # preconditions from the victim's own phpinfo
python3 poc.py exploit --target http://10.20.0.226:8098        # the reference probe, all paths
```
