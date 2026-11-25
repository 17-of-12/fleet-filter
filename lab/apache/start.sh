#!/bin/sh
# Generate the lab's TLS identity once, then hand the process over to httpd.
#
# Why at start rather than at build: the key stays out of the image and out of git, and each host
# gets its own so a client cannot mistake one lab host for another by certificate.
set -eu
CERT_DIR=/state/tls
if [ ! -s "$CERT_DIR/server.crt" ] || [ ! -s "$CERT_DIR/server.key" ]; then
    # The host prepares /state/tls before the container starts (see lab/README.md). Failing loudly
    # beats starting a TLS listener with no certificate and blaming the exploit later.
    echo "start.sh: no certificate in $CERT_DIR - create server.crt/server.key on the host first" >&2
    exit 1
fi
# Ports are environment-driven so one host can run several victim versions side by side without a
# second config file: the container uses host networking, so the listener is the only thing that
# collides.
LISTEN_PORT="${LISTEN_PORT:-8080}"
TLS_PORT="${TLS_PORT:-8443}"
CONF=/tmp/httpd.conf
sed -e "s/^Listen 8080$/Listen ${LISTEN_PORT}/" \
    -e "s/^Listen 8443$/Listen ${TLS_PORT}/" \
    -e "s/<VirtualHost \*:8443>/<VirtualHost *:${TLS_PORT}>/" \
    /usr/local/apache2/conf/httpd.conf > "$CONF"
echo "start.sh: listening ${LISTEN_PORT} (h2c) and ${TLS_PORT} (h2/tls)"
exec httpd -DFOREGROUND -f "$CONF"
