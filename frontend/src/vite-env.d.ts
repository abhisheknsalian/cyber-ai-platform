/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

/** Populated at container startup by the Docker/nginx runtime (see
 * frontend/docker-entrypoint.sh); absent in local dev and left undefined by the
 * static frontend/public/config.js fallback. */
interface AppRuntimeConfig {
  readonly VITE_API_URL?: string;
}

declare interface Window {
  __APP_CONFIG__?: AppRuntimeConfig;
}
