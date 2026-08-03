/**
 * Carries the email address from /forgot-password to /reset-password without
 * putting it in the URL.
 *
 * It used to travel as `/reset-password?email=<address>`. Scoping Google Tag
 * Manager away from the auth pages stops gtag reporting that address in
 * `page_location`, but GTM was never the only reader of a query string. The
 * address also landed in:
 *
 *   - browser history, which persists after logout and is readable by anyone
 *     with the device;
 *   - the `Referer` header sent to every external origin the page loads, which
 *     is how it reaches third parties even with no analytics present;
 *   - access logs, in nginx and any proxy in front of the app, retained
 *     indefinitely and usually shipped somewhere central.
 *
 * `Referrer-Policy` addresses only the second, and only for origins that honour
 * it. So the value moves out of the URL entirely.
 *
 * `sessionStorage`, not `localStorage`: this should not outlive the tab. And not
 * a POST body — /reset-password is a client-rendered page reached by client
 * navigation, not a form target.
 *
 * The consumer clears the value on read and falls back to its own email input if
 * nothing is stored, so a direct link, a new tab or a resumed flow still works.
 */

const STORAGE_KEY = 'wiestell:password-reset-email';

export function storeResetEmail(email: string): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(STORAGE_KEY, email);
  } catch {
    // Private browsing or a storage quota error. The reset page falls back to
    // asking for the address, so failing silently is the correct degradation.
  }
}

/** Reads and removes the stored address. Returns '' when there is nothing. */
export function consumeResetEmail(): string {
  if (typeof window === 'undefined') return '';
  try {
    const value = window.sessionStorage.getItem(STORAGE_KEY);
    if (value) window.sessionStorage.removeItem(STORAGE_KEY);
    return value || '';
  } catch {
    return '';
  }
}
