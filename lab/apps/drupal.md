# Drupal runbook

## Versions and images

- `docker.io/library/drupal:11.4.x` ships the `/opt/drupal/web` docroot layout (`/var/www/html`
  is a symlink to it). Confirm the layout from the image before placing files: it is what the
  `web/modules/x.php` class of paths depends on.
- Drupal advisories enumerate exact ranges with `lessThan` semantics (SA-CORE-2026-017:
  0.0.0..10.6.22, 11.0.0..11.3.22, 11.4.0..11.4.13). **The fix and the mitigation are different
  documents on this product**: a fixed release can keep the vulnerable route reachable. Check the
  advisory's *mitigation* section, not only the version line, before concluding a patched
  installation is not exploitable.

## Preconditions the advisory assumes

- **The site must be *installed*.** An uninstalled `drupal` image serves the installer trivially -
  that is what an empty site is - and proves nothing about installer-state bugs. Install properly
  before testing: the image's canonical `dr install` cannot take a `--db-url` and refuses a docroot
  that already has a `settings.php`, so go through drush (installed via the
  `/usr/local/bin/composer` the image ships):
  `composer create-project drush/drush && drush site:install standard --db-url=... -y`.
- **Database pool size is a reproduction parameter** for reinstall-race exploits: the Fail2Install
  write-up measured ~12% re-entry per request only with the pool saturated (25-connection MariaDB).
  A default pool makes their exploit rare, not absent.
- The stock `.htaccess` deny on non-core `.php` files only inspects the URL's tail:
  `/modules/x.php` → 403 but `/modules/x.php/core/x.php` → 200 *and executes*. Unchanged in the
  fixed releases - if a test relies on file placement, test both spellings.

## Build

```bash
lab/drupal-132165/provision.sh          # the record of the exact podman + drush commands
```

Run the same provisioning against a second database for the fixed twin (`11.4.13`) - for this CVE
the pair measures that the fix does not remove the reachable installer, which is what makes the
gateway rule (not the vendor patch) the thing that stops reachability.

## Verification

- The request that proves it: `GET /core/install.php?langcode=en&profile=standard` on the
  *installed* site answers 200 `Drupal already installed` - anonymous, on a site that finished
  installing. The vendor's check set adds `curl -I /core/install.php` and
  `curl -I /core/install.php/foo`; the root `/install.php` answers the site's own 301 to the core
  location (capture it without `-L` - the 301 *is* the finding).
- The negative control for file-placement claims: the same file directly (`403`) vs through the
  PATH_INFO path (`200` + body).

## Walls

- **A patched twin answers identically.** If you expect the fixed release to 404 the installer, you
  will record a false "not vulnerable": the fix closes the reinstall race, the route keeps serving
  (measured on 11.4.12 and 11.4.13 side by side).
- `dr install` failing on "already has a settings.php" is not a broken image - it means a previous
  install left state; an installed site answering `/core/install.php` is the CVE's premise, not a
  misconfiguration.
- The full exploit needs the DB pool race; a single request without the flood gets "Drupal already
  installed", not the reinstall form. That response is the attack surface, not a null result - the
  race frequency is the exploit's delivery rate, and the missing-authentication class stands without
  it.
