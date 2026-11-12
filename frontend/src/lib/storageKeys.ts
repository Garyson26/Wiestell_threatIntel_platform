/**
 * localStorage keys, and the move from the names they had before the product rename.
 *
 * MIGRATION ADDED 2026-11-12. Until then these were `sentinel_token` and
 * `sentinel_user_activities`. Renaming a key without moving its value signs out everyone
 * holding a live token (tokens last 12 hours) and, worse, discards every analyst's
 * activity history, which has no expiry. `migrateLegacyStorage` copies each value across
 * on first read and deletes the old key. If both exist, the new key's value is kept.
 *
 * Remove `LEGACY_KEYS`, `migrateLegacyStorage` and `removeLegacy` (and reduce
 * `removeStorage` to a plain removeItem) once it is reasonable to assume every user has
 * loaded the app since 2026-11-12.
 */

export const TOKEN_KEY = 'wiestell_token';
export const ACTIVITIES_KEY = 'wiestell_user_activities';

const LEGACY_KEYS: ReadonlyArray<readonly [current: string, legacy: string]> = [
  [TOKEN_KEY, 'sentinel_token'],
  [ACTIVITIES_KEY, 'sentinel_user_activities'],
];

let migrated = false;

/**
 * Runs once per page load, on the first read of either key, rather than in an effect:
 * React runs a child's effects before its parent's, so a page's first request can go out
 * before AuthProvider's effect would have moved the token.
 */
export function migrateLegacyStorage(): void {
  if (migrated || typeof window === 'undefined') return;
  migrated = true;
  for (const [current, legacy] of LEGACY_KEYS) {
    try {
      const old = localStorage.getItem(legacy);
      if (old === null) continue;
      if (localStorage.getItem(current) === null) {
        localStorage.setItem(current, old);
      }
      // Only reached if the copy succeeded (setItem throws when storage is full), so a
      // failed copy leaves the old value in place rather than losing it.
      localStorage.removeItem(legacy);
    } catch {
      // Storage unavailable (private mode, blocked by policy): nothing to migrate.
    }
  }
}

export function readStorage(key: string): string | null {
  if (typeof window === 'undefined') return null;
  migrateLegacyStorage();
  return localStorage.getItem(key);
}

/**
 * Removes the old name of `key`. Anything that CLEARS a key must call this too. The
 * migration removes old keys, but one can come back: a tab still running the previous
 * build writes `sentinel_token`, or a copy failed because storage was full. If logout
 * cleared only the new name, the next page load would migrate that leftover across and
 * sign the user back in, or restore activity history logout is meant to discard.
 */
export function removeLegacy(key: string): void {
  if (typeof window === 'undefined') return;
  for (const [current, legacy] of LEGACY_KEYS) {
    if (current === key) localStorage.removeItem(legacy);
  }
}

/** Removes `key` under both its current and its old name. */
export function removeStorage(key: string): void {
  if (typeof window === 'undefined') return;
  localStorage.removeItem(key);
  removeLegacy(key);
}
