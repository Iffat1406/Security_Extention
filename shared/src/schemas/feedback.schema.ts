import { z } from 'zod';

/** §22.3 scan_feedback.feedback_type. */
export const FEEDBACK_TYPES = ['FALSE_POSITIVE', 'FALSE_NEGATIVE', 'HELPFUL', 'NOT_HELPFUL'] as const;
export const feedbackTypeSchema = z.enum(FEEDBACK_TYPES);

/** §22.3 scan_feedback.status. */
export const FEEDBACK_STATUSES = ['NEW', 'REVIEWING', 'CONFIRMED', 'REJECTED'] as const;
export const feedbackStatusSchema = z.enum(FEEDBACK_STATUSES);

/** POST /scans/:id/feedback. `reason` is free text, 500-char cap, never rendered as HTML (§22.3). */
export const feedbackBodySchema = z
  .object({
    feedbackType: feedbackTypeSchema,
    reportedSignal: z.string().max(48).nullable().optional(),
    reason: z.string().max(500).optional(),
  })
  .strict();
export type FeedbackBody = z.infer<typeof feedbackBodySchema>;

/** POST /admin/feedback/:id/resolve. */
export const feedbackResolveSchema = z
  .object({ status: z.enum(['REVIEWING', 'CONFIRMED', 'REJECTED']) })
  .strict();
