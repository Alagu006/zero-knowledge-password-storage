/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly ZKM_AUTO_LOCK_MINUTES?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
