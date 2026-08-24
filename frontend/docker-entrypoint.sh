#!/bin/sh
# Renders /usr/share/nginx/html/config.js from config.template.js using the
# VITE_API_URL environment variable, then hands off to nginx. This is what lets a
# single built image be pointed at a different backend URL per environment (e.g. via
# docker-compose.yml) without rebuilding -- see src/services/api.ts for how the
# frontend reads window.__APP_CONFIG__.
set -eu

: "${VITE_API_URL:=http://localhost:8000}"
export VITE_API_URL

envsubst '${VITE_API_URL}' \
    < /usr/share/nginx/html/config.template.js \
    > /usr/share/nginx/html/config.js

exec nginx -g 'daemon off;'
