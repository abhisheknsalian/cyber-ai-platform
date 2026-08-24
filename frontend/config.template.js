// Template for the runtime config.js, substituted by docker-entrypoint.sh at
// container startup via envsubst. Lives outside public/ so the npm build never
// touches it -- it is copied directly into the nginx image by frontend/Dockerfile.
window.__APP_CONFIG__ = {
  VITE_API_URL: "${VITE_API_URL}"
};
