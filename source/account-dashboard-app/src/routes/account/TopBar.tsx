import { ChevronDown } from "lucide-react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  Logo,
  Text,
  ThemeToggle,
} from "@wardnet/ui";
import { clsx } from "clsx";
import type { MeView } from "../../api/contract";
import { useSession } from "../../auth/AuthProvider";
import { DEMO_ENABLED } from "../../config/env";
import { useThemeContext } from "../../theme/ThemeContext";
import { Skeleton } from "../../components/feedback";
import { DemoSwitcher } from "./DemoSwitcher";
import s from "./AccountLayout.module.css";

const TABS = [
  { to: "/overview", label: "Overview" },
  { to: "/subscription", label: "Subscription" },
  { to: "/security", label: "Security" },
];

function displayName(email: string): string {
  const local = email.split("@")[0] ?? "Account";
  return local.charAt(0).toUpperCase() + local.slice(1);
}

export function TopBar({ me }: { me?: MeView }) {
  const navigate = useNavigate();
  const { theme, toggle } = useThemeContext();
  const { signOut } = useSession();

  const name = me ? displayName(me.email) : "";
  const initial = me ? me.email.charAt(0).toUpperCase() : "";

  async function onSignOut() {
    await signOut();
    navigate("/signin");
  }

  return (
    <header className={s.topbar}>
      <div className={s.topbarInner}>
        <span className={s.brand}>
          <Logo height={20} variant={theme === "dark" ? "dark" : "light"} />
        </span>
        <nav className={s.nav}>
          {TABS.map((tab) => (
            <NavLink
              key={tab.to}
              to={tab.to}
              className={({ isActive }) =>
                clsx(s.navLink, isActive && s.navLinkActive)
              }
            >
              {tab.label}
            </NavLink>
          ))}
        </nav>
        <span className={s.spacer} />
        <div className={s.right}>
          {DEMO_ENABLED && <DemoSwitcher />}
          <ThemeToggle theme={theme} onToggle={toggle} />
          {me ? (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className={s.avatar} aria-label="Account menu">
                  <span className={s.avatarBadge}>{initial}</span>
                  <span className={s.avatarName}>{name}</span>
                  <ChevronDown size={14} aria-hidden />
                </button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end" style={{ minWidth: 220 }}>
                <div className={s.menuMeta}>
                  <Text variant="body-strong">{name}</Text>
                  <Text variant="caption" color="ink-3">
                    {me.email}
                  </Text>
                </div>
                <DropdownMenuSeparator />
                {TABS.map((tab) => (
                  <DropdownMenuItem
                    key={tab.to}
                    onSelect={() => navigate(tab.to)}
                  >
                    {tab.label}
                  </DropdownMenuItem>
                ))}
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  variant="destructive"
                  onSelect={() => void onSignOut()}
                >
                  Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          ) : (
            <Skeleton width={120} height={34} radius={999} />
          )}
        </div>
      </div>
    </header>
  );
}
