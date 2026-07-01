/// <reference types="vite/client" />

// Side-effect CSS package (bare specifier resolves to @wardnet/styles/styles.css).
declare module "@wardnet/styles";

interface ImportMetaEnv {
  /** When "true", start the MSW mock layer instead of hitting the real `/v1`. */
  readonly VITE_ENABLE_MSW?: string;
  /** When "true", expose the dev-only Demo state switcher. */
  readonly VITE_ENABLE_DEMO?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
