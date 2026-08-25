#!/bin/sh
# Renders config.js from config.template.js using the VITE_API_URL environment
# variable, then hands off to nginx. This is what lets a single built image be
# pointed at a different backend URL per environment (e.g. via docker-compose.yml)
# without rebuilding -- see src/services/api.ts for how the frontend reads
# window.__APP_CONFIG__.
#
# Written to /run/frontend-config/config.js, NOT into /usr/share/nginx/html/ alongside
# the static build output -- this is the only file this image ever writes at runtime,
# and keeping it out of the (otherwise fully static) html root is what makes the
# container able to run with a read-only root filesystem (see nginx.conf's `location =
# /config.js` alias and README "Container Hardening"). /run is writable by default in
# most container runtimes and, under `--read-only`, only needs a small tmpfs mount
# (e.g. `--tmpfs /run`) rather than the entire html directory.
set -eu

: "${VITE_API_URL:=http://localhost:8000}"
export VITE_API_URL

mkdir -p /run/frontend-config
envsubst '${VITE_API_URL}' \
    < /usr/share/nginx/html/config.template.js \
    > /run/frontend-config/config.js

exec nginx -g 'daemon off;'
