import * as React from "react";
import type { UseQueryResult } from "@tanstack/react-query";
import { Button, Card, CardContent, Text } from "@wardnet/ui";
import s from "./feedback.module.css";

/** Shimmer placeholder block. */
export function Skeleton({
  width,
  height = 14,
  radius,
  style,
}: {
  width?: number | string;
  height?: number | string;
  radius?: number | string;
  style?: React.CSSProperties;
}) {
  return (
    <span
      className={s.skeleton}
      style={{ width, height, borderRadius: radius, ...style }}
      aria-hidden
    />
  );
}

/** A card-shaped skeleton with a few shimmer lines. */
export function CardSkeleton({ lines = 3 }: { lines?: number }) {
  return (
    <Card>
      <CardContent>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <Skeleton width="40%" height={16} />
          {Array.from({ length: lines }, (_, i) => (
            <Skeleton key={i} width={`${90 - i * 12}%`} />
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

/** Centered error card with a Retry affordance. */
export function ErrorCard({
  message = "Something went wrong loading this.",
  onRetry,
}: {
  message?: string;
  onRetry?: () => void;
}) {
  return (
    <Card>
      <CardContent>
        <div className={s.errorCard}>
          <Text variant="body" color="ink-2">
            {message}
          </Text>
          {onRetry && (
            <Button variant="ghost" size="sm" onClick={onRetry}>
              Retry
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/** Centered empty-state with an icon glyph + copy. */
export function EmptyState({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode;
  title: string;
  description?: React.ReactNode;
}) {
  return (
    <div className={s.empty}>
      <span className={s.emptyIcon}>{icon}</span>
      <Text variant="body-strong" color="ink-2">
        {title}
      </Text>
      {description && (
        <Text variant="caption" color="ink-3">
          {description}
        </Text>
      )}
    </div>
  );
}

/**
 * Render-prop wrapper that maps a TanStack Query result to the four UI states:
 * loading (skeleton), error (card + Retry), empty (when `isEmpty` matches), and
 * ready (children).
 */
export function QueryStates<T>({
  result,
  skeleton,
  isEmpty,
  empty,
  children,
}: {
  result: UseQueryResult<T>;
  skeleton?: React.ReactNode;
  isEmpty?: (data: T) => boolean;
  empty?: React.ReactNode;
  children: (data: T) => React.ReactNode;
}) {
  if (result.isPending) return <>{skeleton ?? <CardSkeleton />}</>;
  if (result.isError)
    return <ErrorCard onRetry={() => void result.refetch()} />;
  if (isEmpty?.(result.data) && empty !== undefined) return <>{empty}</>;
  return <>{children(result.data)}</>;
}
