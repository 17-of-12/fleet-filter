# WordPress runbooks

## Versions

- Core advisories are narrow: CVE-2026-63030 affects 6.9.x < 6.9.5 and 7.0.x < 7.0.2. A 6.8.2 victim
  was built first and could never be vulnerable - check the range before building.
- Plugin and theme CVEs outnumber core ones and name a plugin version, not a WordPress version. The
  plugin must be installed at the affected version; the core version is irrelevant to those.

## Build

```bash
podman exec ff-wp-db mariadb -uroot -p*** -e \
  "CREATE DATABASE IF NOT EXISTS wp694; GRANT ALL ON wp694.* TO wp@'%'; FLUSH PRIVILEGES;"
podman run -d --name ff-wp-694 --network ff-wp -p 8094:80 \
  -e WORDPRESS_DB_HOST=ff-wp-db:3306 -e WORDPRESS_DB_USER=wp ... wordpress:6.9.4
```

## Preconditions

- **Permalinks.** A REST route answers 404 until permalinks are set to anything but "plain"; that
  reads exactly like a missing endpoint and cost time on 63030.
- The installer must be completed (`wp core install`) or every admin-ajax and REST call redirects.

## Verification

- The request, then the control with the route disabled.
- Record the plugin/theme version and how it was installed - "from the dashboard" is not reproducible.

## Walls

- A 404 is usually permalinks, not absence.
- WordPress core rotates the REST nonce; a 403 on `/wp-json/` is often that, not the bug.
