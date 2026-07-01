import * as React from "react";
import { Card, Logo, ThemeToggle } from "@wardnet/ui";
import { useThemeContext } from "../../theme/ThemeContext";
import s from "./AuthShell.module.css";

/**
 * Centered 384px auth layout (matches the admin apps' auth card): theme-toggle
 * FAB, centered Logo, a Card holding the screen body, and an optional footer
 * beneath the card.
 */
export function AuthShell({
  children,
  footer,
}: {
  children: React.ReactNode;
  footer?: React.ReactNode;
}) {
  const { theme, toggle } = useThemeContext();
  return (
    <div className={s.shell}>
      <div className={s.fab}>
        <ThemeToggle theme={theme} onToggle={toggle} />
      </div>
      <div className={s.column}>
        <div className={s.logo}>
          <Logo height={48} variant={theme === "dark" ? "dark" : "light"} />
        </div>
        <Card>
          <div className={s.cardBody}>{children}</div>
        </Card>
        {footer && <div className={s.footer}>{footer}</div>}
      </div>
    </div>
  );
}
