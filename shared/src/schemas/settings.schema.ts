import { z } from 'zod';

/**
 * §23.1 user settings. Persisted server-side (user_settings.settings) so they
 * follow the account, and mirrored into chrome.storage.local so the service
 * worker can read them without a network call.
 *
 * `.strict()` enforces §23.4 "Unknown keys rejected".
 */
export const userSettingsSchema = z
  .object({
    autoScan: z.boolean(),
    showRiskBadge: z.boolean(),
    warningNotifications: z.boolean(),
    passwordBreachDetection: z.boolean(),
    trackerDetection: z.boolean(),
    aiExplanation: z.boolean(),
    aiChat: z.boolean(),
    storeScanHistory: z.boolean(),
    storePagePaths: z.boolean(),
    contributeThreatIntel: z.boolean(),
    /** §30.2 "A setting allows local scanning with local checks only — never a backend lookup". */
    scanLocalAddresses: z.boolean(),
    /** §29.1 "user may choose 30 / 90 / 365 / forever" — null = forever. */
    scanRetentionDays: z.union([z.literal(30), z.literal(90), z.literal(365)]).nullable(),
  })
  .strict();
export type UserSettings = z.infer<typeof userSettingsSchema>;

/** §23.1 defaults (every toggle ON) and §29.1 default retention of 90 days. */
export const DEFAULT_USER_SETTINGS: UserSettings = {
  autoScan: true,
  showRiskBadge: true,
  warningNotifications: true,
  passwordBreachDetection: true,
  trackerDetection: true,
  aiExplanation: true,
  aiChat: true,
  storeScanHistory: true,
  storePagePaths: true,
  contributeThreatIntel: true,
  scanLocalAddresses: false,
  scanRetentionDays: 90,
};

/** PATCH /users/me/settings — partial update, still strict. */
export const settingsPatchSchema = userSettingsSchema.partial().strict();
export type SettingsPatch = z.infer<typeof settingsPatchSchema>;

export const exclusionBodySchema = z.object({ domain: z.string().min(1).max(253) }).strict();

export const settingsResponseSchema = z.object({
  settings: userSettingsSchema,
  excludedDomains: z.array(z.string()),
  updatedAt: z.string(),
});
export type SettingsResponse = z.infer<typeof settingsResponseSchema>;

/** Merges a stored (possibly older, partial) settings blob over the defaults
 * so a setting added in a later release gets its default rather than undefined. */
export function withSettingsDefaults(stored: unknown): UserSettings {
  const parsed = settingsPatchSchema.safeParse(stored);
  return { ...DEFAULT_USER_SETTINGS, ...(parsed.success ? parsed.data : {}) };
}
