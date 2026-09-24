import { z } from 'zod';

/** GET /auth/me — §11 "{ id, email, displayName, avatarUrl }". */
export const authUserSchema = z.object({
  id: z.string(),
  email: z.string(),
  displayName: z.string(),
  avatarUrl: z.string().nullable(),
});
export type AuthUser = z.infer<typeof authUserSchema>;

/** GET /auth/google/callback (JSON mode) — §11 "{ accessToken, user }". */
export const authTokenResponseSchema = z.object({
  accessToken: z.string(),
  user: authUserSchema,
});
export type AuthTokenResponse = z.infer<typeof authTokenResponseSchema>;

/** POST /auth/refresh — §11 "{ accessToken }". */
export const refreshResponseSchema = z.object({ accessToken: z.string() });

/**
 * Where the OAuth flow hands the tokens back to. `extension` redirects to
 * the extension's chrome.identity URL (https://<id>.chromiumapp.org/),
 * `dashboard` to the backend-served dashboard. Omitted = the plain JSON
 * response from §11.
 */
export const AUTH_CLIENTS = ['extension', 'dashboard'] as const;
export type AuthClient = (typeof AUTH_CLIENTS)[number];
