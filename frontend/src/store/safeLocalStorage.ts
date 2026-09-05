import type { PersistStorage, StorageValue } from "zustand/middleware";

/** Wraps localStorage so a corrupted/foreign value at a given key can never crash the
 * app: JSON.parse failures and any read/write error (private browsing, quota,
 * disabled storage) are swallowed and treated as "nothing persisted". A value that
 * parses but doesn't match `isValidShape` is dropped the same way, and the bad key is
 * proactively removed so it doesn't keep failing on every load.
 *
 * Shared by every Zustand store in this app that persists to localStorage (see
 * networkDetectionStore.ts and investigationHistoryStore.ts) so this defensive
 * wrapping exists in exactly one place. */
export function createSafeStorage<T>(isValidShape: (value: unknown) => value is T): PersistStorage<T> {
  return {
    getItem: (name) => {
      let raw: string | null;
      try {
        raw = localStorage.getItem(name);
      } catch {
        return null;
      }
      if (!raw) return null;

      try {
        const parsed = JSON.parse(raw) as StorageValue<T>;
        if (typeof parsed !== "object" || parsed === null || !("state" in parsed)) {
          throw new Error("malformed persisted value");
        }
        if (!isValidShape(parsed.state)) {
          throw new Error("persisted state does not match the expected shape");
        }
        return parsed;
      } catch {
        try {
          localStorage.removeItem(name);
        } catch {
          // Storage is unavailable entirely -- nothing more we can do.
        }
        return null;
      }
    },
    setItem: (name, value) => {
      try {
        localStorage.setItem(name, JSON.stringify(value));
      } catch {
        // Quota exceeded / storage disabled -- this write simply won't survive a
        // reload this time. Not fatal to the running app.
      }
    },
    removeItem: (name) => {
      try {
        localStorage.removeItem(name);
      } catch {
        // Nothing more we can do.
      }
    },
  };
}
