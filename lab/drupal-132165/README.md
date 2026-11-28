# CVE-2026-132165 lab victim

A victim that runs **the Drupal the vendor ships** at **the version the advisory names**, in the
state the advisory describes the attack against: an *installed* site whose `core/install.php` is
still reachable - plus the fixed `11.4.13` as the twin, because for this CVE the fix and the
mitigation are different documents and the lab needs to be able to tell them apart.

| | |
|---|---|
| CVE | CVE-2026-132165 - Missing Authentication for Critical Function in Drupal core (CWE-306), a.k.a. **Fail2Install**. NVD (2026-11-26, `mlhess@drupal.org`): affected **0.0.0 .. 10.6.22, 11.0.0 .. 11.3.22, 11.4.0 .. 11.4.13** (`lessThan` semantics: fixed in 10.6.22 / 11.3.22 / 11.4.13). CISA KEV 2026-11-24 (action due 2026-11-27), EPSS 0.0838 |
| Advisory | https://www.drupal.org/sa-core-2026-017 (Highly critical, 18/25; update: exploited on live sites since 2026-11-19 19:00 UTC); public write-up naming the bug: https://www.stepsecurity.io/blog/fail2install-cve-2026-132165; fix commit: https://github.com/drupal/drupal/commit/a15a19b74bb9f16f75a44ed39219049283de2381 |
| Base image | `docker.io/library/drupal:11.4.12` - the affected release on the 11.4 line, the exact image + version the public write-up reproduced on ("Apache with MySQL", its best configuration); `drupal:11.4.13` is the fixed twin. No Containerfile: the image *is* the artifact under test, and the lab's state is what a real deployment adds to it (below) |
| Database | `docker.io/library/mariadb:11.4` with `--max-connections=25` and two databases (`drupal_v`, `drupal_p`). The write-up's measurement: at a default connection pool the installer re-entry is infrequent, at a 25-connection pool it "reopened readily" - the lab builds the configuration their own reproduction calls reliable |
| PoC | `poc.py` in this directory - the vendor's own three-request check set (`/core/install.php`, `/install.php`, `/core/install.php/foo`) plus the write-up's exact attacker request (`GET /core/install.php?langcode=en&profile=standard`), with the reference harnesses' answer taxonomy (`app-answer` / `gateway-inline` / `gateway-upstream-error`) carried over verbatim from `lab/php-129496/poc.py` so the two PHP CVEs and this one report in the same vocabulary |
| Deployed as | `ff-drupal-132165` on `ff-apache02` (10.20.0.226):8104 (vulnerable, site name `FleetLabV`) and `ff-drupal-132165-patched`:8105 (fixed twin, site name `FleetLabP`), with `ff-drupal-db` (MariaDB, not published - same convention as `ff-wp-db`) on a dedicated `ff-drupal` podman network. Provisioning: `provision.sh` (it is the record of the exact commands, including the two drush installs); the drush-generated `settings.php` files are captured in `conf/` |

## Why this victim had to be built

Step 0 of the skill: the NVD record names `drupal/drupal` (which is in `config/web-surface.yaml`
but was never deployed here), and no Drupal container existed on any victim host - the work-queue
decision says as much ("no Drupal signature exists in the store yet"). The fix is to run the
affected version, and the affected version is only meaningful together with the **installed**
state: the CVE is about an installer that should have stopped serving on an installed site. An
uninstalled `drupal` image serves the installer trivially (that is what an empty site is), which
would prove nothing about the CVE - so the lab installs Drupal properly via `drush site:install
standard` against a real MariaDB and the PoC then measures what an installed 11.4.12 answers.

The patched twin exists because for this CVE *the fix does not remove the reachable installer*.
An installed 11.4.13 answers `GET /core/install.php` with the same page title - the fix stops the
installer from *re-entering* under a database race; the vendor's separate recommendation ("block
`/core/install.php` on every Drupal site today", their guide's `curl -I` checks) exists because
the route keeps serving either way. The two-victim pair measures that distinction instead of
arguing it, the way `lab/php-129496` measures the fix side of its pair.

| | |
|---|---|
| `:8104` vulnerable | `drupal:11.4.12` (in NVD's 11.4.0..11.4.12 range), installed against `drupal_v` |
| `:8105` patched | `drupal:11.4.13`, installed against `drupal_p` - same image layout, same provisioning path |

## The provisioning details that are part of the evidence

- **docroot layout.** The 11.4 official image is the `/opt/drupal/web` layout (`/var/www/html`
  is a symlink to it); this is the `web/modules/x.php` layout the write-up's file-placement path
  describes, and it was verified, not assumed: the image's own `/opt/drupal/web/core/scripts/drupal`
  header line was the first thing read.
- **installer provenance.** `dr install` on the 11.4 image (the canonical launcher) cannot take a
  `--db-url` and refuses a docroot that already has a `settings.php`; the install therefore went
  through `drush` (the tool the vendor's own update docs use), installed via the `/usr/local/bin/composer`
  the image ships. The only filesystem changes inside the containers are `vendor/` (composer),
  `sites/default/{settings.php,services.yml}` (drush) and - with `-plant` - `modules/x.php`.
- **the planted file.** `conf/planted-x.php` (`<?php echo 40+2;`) reproduces StepSecurity's
  isolated `.htaccess` test on this image: direct `/modules/x.php` → `403` (the stock deny), while
  `/modules/x.php/core/x.php` → `200` and *executes* (`42` comes back) because the stock exception
  only inspects the URL's tail - and it is unchanged in the fixed releases. The A/B run records this
  on the vulnerable container; it is documented in the run's summary, not made a signature variant
  (the gateway's prefix projection cannot enumerate arbitrary filenames).
- **the race we did not re-run.** The write-up's exploit needs the site's database to refuse the
  installer's early checks while accepting later ones - produced by saturating the (here 25-slot)
  pool. The measured *reopened installer* variant of the response ("Database configuration"
  instead of "Drupal already installed") is their published measurement at 12% per request under
  flood; our harness records the deterministic half (the request the exploit is, and what it
  gets), and `gw-ab.py` records the gateway half. The `not_covered` section of the run's
  summary states exactly this boundary.

## Reproduce

```sh
./provision.sh              # from a machine with ssh to 10.20.0.226 (fleet dispatch key)
./provision.sh -plant       # also place modules/x.php for the .php/core/ route test
python3 poc.py check   --target http://10.20.0.226:8104 --expect-site FleetLabV
python3 poc.py exploit --target http://10.20.0.226:8104
```
