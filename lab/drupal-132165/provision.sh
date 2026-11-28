#!/usr/bin/env bash
# provision.sh - build the CVE-2026-132165 victim pair on ff-apache02, exactly as run 2026-11-28.
#
# The victim is the vendor's own artifact: the official Docker image `drupal:11.4.12` (the
# affected 11.4.x release the public write-up tested, NVD range 11.4.0..11.4.13 lessThan, so 11.4.12 is that range's last affected release) plus
# its fixed twin `drupal:11.4.13`. No Containerfile: unlike the PHP CVE labs, where the fleet
# needed ini-level preconditions baked next to the engine image, this CVE's lab state is the
# official image plus an installed site - and the install leaves marks inside the container, so
# the script records the whole provisioning, not just the image tag. The settings.php files drush
# generated are captured in conf/ (settings-vuln.php, settings-patched.php).
#
# The database mirrors the public write-up's best reproduction configuration: a MariaDB with
# max-connections=25. Their measurement: at the default pool the re-race is infrequent, at a
# 25-connection pool "the installer reopened readily". Two databases, one per site (drupal_v,
# drupal_p), so the two Drupal containers are separate installs rather than a multisite.
#
# Run from anywhere with ssh access as root-capable user `operator` on 10.20.0.226
# (the fleet dispatch key, sudo -n).
set -euo pipefail

HOST=${HOST:-10.20.0.226}
SSH="ssh -o BatchMode=yes operator@$HOST"
P="sudo -n podman"

# 1. network + database ---------------------------------------------------------------
$SSH "podman network create ff-drupal 2>/dev/null || true"
cat > /tmp/init-drupal-dbs.sql <<'SQL'
CREATE DATABASE IF NOT EXISTS drupal_p DEFAULT CHARACTER SET utf8mb4;
GRANT ALL PRIVILEGES ON drupal_p.* TO 'drupal'@'%';
FLUSH PRIVILEGES;
SQL
scp -q -o BatchMode=yes /tmp/init-drupal-dbs.sql operator@$HOST:/tmp/
$SSH "$P run -d --name ff-drupal-db --network ff-drupal \
  -e MYSQL_ROOT_PASSWORD=dr00tLab -e MYSQL_DATABASE=drupal_v -e MYSQL_USER=drupal -e MYSQL_PASSWORD=drupalpass \
  -v /tmp/init-drupal-dbs.sql:/docker-entrypoint-initdb.d/init.sql:ro \
  docker.io/library/mariadb:11.4 --max-connections=25 >/dev/null"

# 2. the two Drupal containers ----------------------------------------------------------
#    Ports continue the ff-apache02 sequence (ff-php-129496-patched was 8103).
$SSH "$P run -d --name ff-drupal-132165 --network ff-drupal -p 8104:80 \
  docker.io/library/drupal:11.4.12 >/dev/null"
$SSH "$P run -d --name ff-drupal-132165-patched --network ff-drupal -p 8105:80 \
  docker.io/library/drupal:11.4.13 >/dev/null"

# 3. settings.php ------------------------------------------------------------------------
#    The image's docroot is /opt/drupal/web (/var/www/html is the symlink); shipping an
#    installed site means writing the settings file that points at the site's database.
#    conf/settings-vuln.php and conf/settings-patched.php are the files drush generated,
#    captured back from the containers; feeding them in reproduces the same installs.
#    Note on the two extra copies below: each pair also lands a PHP file on services.yml,
#    which is YAML - that state is not loadable as it stands, and the site only works
#    because step 4's drush site:install regenerates services.yml afterwards. Recorded as
#    the run did it; the settings.php copy is the one the install actually reads.
cd "$(dirname "$0")"
scp -q -o BatchMode=yes conf/settings-vuln.php operator@$HOST:/tmp/settings-v.php
scp -q -o BatchMode=yes conf/settings-patched.php operator@$HOST:/tmp/settings-p.php
$SSH "$P cp /tmp/settings-v.php ff-drupal-132165:/opt/drupal/web/sites/default/settings.php
       $P cp /tmp/settings-v.php ff-drupal-132165:/opt/drupal/web/sites/default/services.yml
       $P cp /tmp/settings-p.php ff-drupal-132165-patched:/opt/drupal/web/sites/default/settings.php
       $P cp /tmp/settings-p.php ff-drupal-132165-patched:/opt/drupal/web/sites/default/services.yml
       $P exec ff-drupal-132165 chown -R www-data:www-data /opt/drupal/web/sites/default
       $P exec ff-drupal-132165-patched chown -R www-data:www-data /opt/drupal/web/sites/default"

# 4. install ------------------------------------------------------------------------------
#    The image ships composer but no drush. `dr install` (the canonical 11.4 launcher) cannot
#    take a --db-url and refuses a directory that already has settings.php, so the install is
#    done with drush - the tool the vendor's own update documentation uses - installed via
#    composer, the same way a real site adds it. `vendor/bin/drush site:install standard`
#    installs the standard profile against the pre-configured database and rewrites
#    settings.php into drush's canonical form (the conf/ files above).
$SSH "$P exec -w /opt/drupal ff-drupal-132165 composer require drush/drush --no-interaction --no-progress >/dev/null
       $P exec -w /opt/drupal ff-drupal-132165-patched composer require drush/drush --no-interaction --no-progress >/dev/null"
$SSH "$P exec -w /opt/drupal ff-drupal-132165 vendor/bin/drush -y site:install standard \
        --site-name=FleetLabV --account-name=admin --account-pass='LabPass2026!' --uri=http://127.0.0.1:8104"
$SSH "$P exec -w /opt/drupal ff-drupal-132165-patched vendor/bin/drush -y site:install standard \
        --site-name=FleetLabP --account-name=admin --account-pass='LabPass2026!' --uri=http://127.0.0.1:8105"

# 5. the planted-file artefact for the .php/core/ code-execution route (optional, -plant)
#    StepSecurity's isolated test of the unchanged .htaccess quirk: a .php in web/modules is
#    403'd by the stock .htaccess, but /modules/x.php/core/x.php passes its exception and runs.
#    Documented in conf/planted-x.php; recreate with:
if [ "${1:-}" = "-plant" ]; then
  scp -q -o BatchMode=yes conf/planted-x.php operator@$HOST:/tmp/x.php
  $SSH "$P cp /tmp/x.php ff-drupal-132165:/opt/drupal/web/modules/x.php
         $P exec ff-drupal-132165 chown www-data:www-data /opt/drupal/web/modules/x.php"
fi

# 6. verify -------------------------------------------------------------------------------
for port in 8104 8105; do
  $SSH "curl -s -o /dev/null -w 'GET :$port/                 -> %{http_code}\n'             http://$HOST:$port/
        curl -s -o /dev/null -w 'GET :$port/core/install.php  -> %{http_code}\n'             http://$HOST:$port/core/install.php
        curl -s -o /dev/null -w 'GET :$port/install.php       -> %{http_code} (301 to core on 8+)\n' http://$HOST:$port/install.php
        curl -s -o /dev/null -w 'GET :$port/core/install.php/foo -> %{http_code}\n'          http://$HOST:$port/core/install.php/foo"
done
