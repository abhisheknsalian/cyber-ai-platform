// Local-dev / non-Docker fallback: no runtime override, so src/services/api.ts falls
// back to import.meta.env.VITE_API_URL. In the Docker/nginx image this exact file is
// overwritten at container startup -- see frontend/docker-entrypoint.sh.
window.__APP_CONFIG__ = {};
