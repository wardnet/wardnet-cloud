import * as React from "react";

export type Theme = "light" | "dark";

const STORAGE_KEY = "wardnet-theme";

function readInitialTheme(): Theme {
  const stored = localStorage.getItem(STORAGE_KEY);
  return stored === "dark" ? "dark" : "light";
}

/** Applies `data-theme` to <html> so Radix portals inherit the theme. */
function applyTheme(theme: Theme) {
  document.documentElement.setAttribute("data-theme", theme);
}

/**
 * Theme state synced to <html data-theme> and localStorage. Light is the
 * default; the toggle flips light ⇄ dark.
 */
export function useTheme() {
  const [theme, setTheme] = React.useState<Theme>(readInitialTheme);

  React.useEffect(() => {
    applyTheme(theme);
    localStorage.setItem(STORAGE_KEY, theme);
  }, [theme]);

  const toggle = React.useCallback(
    () => setTheme((t) => (t === "dark" ? "light" : "dark")),
    [],
  );

  return { theme, toggle } as const;
}
