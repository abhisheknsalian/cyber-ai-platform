import { AlertTriangle } from "lucide-react";

import { Card } from "./Card";

interface ConfirmDialogProps {
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  /** True while the confirmed action is in flight -- disables both buttons and
   * relabels the confirm button so a slow request can't be double-submitted by a
   * second click. */
  pending?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

/** A single blocking confirmation modal for destructive actions -- this app has no
 * other modal today, so this is deliberately the one dialog primitive rather than a
 * generic dialog system. Renders nothing unless mounted by the caller (callers
 * conditionally render it, matching how every other conditional section of this app
 * is written) rather than taking an `open` prop. */
export function ConfirmDialog({ title, description, confirmLabel, cancelLabel = "Cancel", pending = false, onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      role="presentation"
      onClick={() => !pending && onCancel()}
    >
      <Card
        className="w-full max-w-sm border-malicious/30 p-5"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0 text-malicious-strong" strokeWidth={1.75} />
          <div>
            <p id="confirm-dialog-title" className="text-sm font-semibold text-text">
              {title}
            </p>
            <p className="mt-1.5 text-sm text-text-muted">{description}</p>
          </div>
        </div>

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            disabled={pending}
            className="rounded-md border border-border-strong px-3 py-1.5 text-xs font-medium text-text-muted transition-colors hover:border-accent/50 hover:text-text disabled:cursor-not-allowed disabled:opacity-40"
          >
            {cancelLabel}
          </button>
          <button
            type="button"
            onClick={onConfirm}
            disabled={pending}
            className="rounded-md bg-malicious px-3 py-1.5 text-xs font-semibold text-surface transition-colors hover:bg-malicious-strong disabled:cursor-not-allowed disabled:opacity-40"
          >
            {pending ? "Deleting..." : confirmLabel}
          </button>
        </div>
      </Card>
    </div>
  );
}
