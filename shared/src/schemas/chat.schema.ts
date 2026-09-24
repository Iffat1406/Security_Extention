import { z } from 'zod';

/** Length cap on a user chat message (§26.5 "message stored and length-capped"). */
export const MAX_CHAT_MESSAGE_LENGTH = 1000;

/** POST /scans/:scanId/chat — §11 "Body: { message }". */
export const chatMessageBodySchema = z
  .object({ message: z.string().trim().min(1).max(MAX_CHAT_MESSAGE_LENGTH) })
  .strict();

export const chatMessageSchema = z.object({
  role: z.enum(['user', 'assistant']),
  content: z.string(),
  createdAt: z.string(),
});
export type ChatMessage = z.infer<typeof chatMessageSchema>;
