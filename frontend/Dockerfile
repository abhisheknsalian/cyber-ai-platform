# syntax=docker/dockerfile:1
#
# Production-style image for the React frontend ONLY (Phase 6.2). Two stages:
#   1. builder -- a Node image that installs exactly what package-lock.json pins
#      (npm ci) and runs the existing, unmodified `npm run build`.
#   2. runtime -- nginx:alpine serving the static build output. No Node.js, no
#      source files, no dev tooling in the final image.
#
# The backend URL is injected at container *startup* (not baked in at build time) --
# see docker-entrypoint.sh and config.template.js -- so this same image works against
# any backend without rebuilding.

FROM node:22-alpine AS builder

WORKDIR /app

# Only the lockfile + package.json first, so this layer only invalidates when a
# dependency actually changes, not on every source edit. npm ci installs exactly
# what package-lock.json pins (reproducible, unlike `npm install`).
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build


FROM nginx:1.27-alpine AS runtime

# envsubst (from gettext) is used by docker-entrypoint.sh to render config.js from
# config.template.js at container startup.
RUN apk add --no-cache gettext

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

COPY --from=builder /app/dist /usr/share/nginx/html
COPY config.template.js /usr/share/nginx/html/config.template.js

EXPOSE 80

# Static-file availability only (nginx serving index.html) -- there is no backend
# call involved, so this can't reflect backend/Ollama health, only that the frontend
# itself is up. wget is already present in nginx:alpine (busybox). Targets
# 127.0.0.1 explicitly, not localhost: nginx.conf only binds IPv4 (0.0.0.0:80), but
# the container's /etc/hosts resolves "localhost" to ::1 first, so
# `wget http://localhost/` fails with "Connection refused" even though the server is
# up (found live while verifying Phase 6.3).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget --quiet --spider http://127.0.0.1/ || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
