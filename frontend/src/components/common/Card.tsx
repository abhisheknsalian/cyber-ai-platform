import type { ComponentPropsWithoutRef } from "react";

type CardGlow = "none" | "accent" | "malicious" | "benign" | "warning";

interface CardOwnProps {
  glow?: CardGlow;
}

type CardProps = CardOwnProps & ComponentPropsWithoutRef<"div">;

const GLOW_STYLES: Record<CardGlow, string> = {
  none: "border-border shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03),0_1px_3px_-1px_rgba(0,0,0,0.5)]",
  accent:
    "border-accent/40 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03),0_0_0_1px_var(--color-accent-soft),0_0_24px_-8px_var(--color-accent)]",
  malicious:
    "border-malicious/40 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03),0_0_24px_-10px_var(--color-malicious)]",
  benign: "border-benign/30 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03),0_0_24px_-12px_var(--color-benign)]",
  warning: "border-warning/30 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.03),0_0_24px_-12px_var(--color-warning)]",
};

/** The app's one card primitive: a raised surface with a technical, low-key border
 * rather than a soft "toy" shadow. `glow` is reserved for states that genuinely need
 * to draw the eye (an active threat, a healthy result) -- most cards use "none".
 * Forwards every other native <div> prop (role, aria-*, onClick, ...) unchanged. */
export function Card({ children, className = "", glow = "none", ...rest }: CardProps) {
  return (
    <div
      className={`rounded-md border bg-surface-raised transition-shadow duration-300 ${GLOW_STYLES[glow]} ${className}`}
      {...rest}
    >
      {children}
    </div>
  );
}
