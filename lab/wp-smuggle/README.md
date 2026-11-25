# WordPress victims for CVE-2026-63030

Two builds, because the first one was the wrong version and it took a version check to notice.

| host | version | in range for 63030? | state |
|---|---|---|---|
| ff-wp (10.20.0.226:8090) | 6.8.2 | **no** - affects 6.9.x < 6.9.5 and 7.0.x < 7.0.2 | installed, but cannot be vulnerable |
| ff-wp-694 (10.20.0.226:8094) | 6.9.4 | yes | installed, batch route live |

## Install commands (needed again after a rebuild)

```bash
# database for the second victim
podman exec ff-wp-db mariadb -uroot -p*** -e \
  "CREATE DATABASE IF NOT EXISTS wp694; GRANT ALL ON wp694.* TO wp@'%'; FLUSH PRIVILEGES;"

podman run -d --name ff-wp-694 --network ff-wp -p 8094:80 \
  -e WORDPRESS_DB_HOST=ff-wp-db:3306 -e WORDPRESS_DB_USER=wp \
  -e WORDPRESS_DB_PASSWORD=*** -e WORDPRESS_DB_NAME=wp694 \
  docker.io/library/wordpress:6.9.4

V=$(podman inspect ff-wp-694 --format '{{range .Mounts}}{{.Name}}{{end}}')
ENVS="-e WORDPRESS_DB_HOST=ff-wp-db:3306 -e WORDPRESS_DB_USER=wp -e WORDPRESS_DB_PASSWORD=*** -e WORDPRESS_DB_NAME=wp694"
podman run --rm --network ff-wp $ENVS -v $V:/var/www/html docker.io/library/wordpress:cli \
  wp core install --url=http://10.20.0.226:8094 --title=lab694 --admin_user=admin \
  --admin_password=*** --admin_email=admin@example.invalid --skip-email
podman run --rm --network ff-wp $ENVS -v $V:/var/www/html docker.io/library/wordpress:cli \
  wp rewrite structure '/%postname%/' --hard
```

Two traps, both of which look like "not vulnerable":

* a container started on the default network cannot resolve `ff-wp-db`; it must join the `ff-wp`
  network. The wp-cli container needs the same, plus the `WORDPRESS_DB_*` environment, because
  `wp-config.php` reads those at runtime.
* `/wp-json/batch/v1` 404s on GET and 400s on POST with a body naming the allowed methods. The route
  is POST/PUT/PATCH/DELETE only; a GET is not evidence that it is absent.

## Where the 63030 attempt stops

The batch route answers 207 on 6.9.4 and an injected `author__not_in` inside an inner
`POST /wp/v2/posts` is reached, but that inner request returns `rest_cannot_create` - it needs
authentication. The route-confusion exploit must use an inner route that is reachable unauthenticated,
which is what the published write-up specifies and what has not been extracted yet.
