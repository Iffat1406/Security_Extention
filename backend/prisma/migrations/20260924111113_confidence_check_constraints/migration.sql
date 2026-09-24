-- Prisma's schema language can't express CHECK constraints, so the ranges the
-- spec defines are enforced here at the database layer.

-- §22.1 / §22.2 "NUMERIC(3,2) 0.00–1.00" — NUMERIC(3,2) alone would allow 9.99.
ALTER TABLE "domains"
  ADD CONSTRAINT "domains_reputation_confidence_range" CHECK ("reputation_confidence" >= 0 AND "reputation_confidence" <= 1),
  ADD CONSTRAINT "domains_counters_non_negative" CHECK ("scan_count" >= 0 AND "unique_user_count" >= 0);

ALTER TABLE "threat_indicators"
  ADD CONSTRAINT "threat_indicators_confidence_range" CHECK ("confidence" >= 0 AND "confidence" <= 1),
  -- §22.2 "suppressed_reason — Required when suppressed_at is set".
  ADD CONSTRAINT "threat_indicators_suppression_reason" CHECK ("suppressed_at" IS NULL OR ("suppressed_reason" IS NOT NULL AND length("suppressed_reason") > 0));

-- §10 scan_chats.role "user | assistant".
ALTER TABLE "scan_chats"
  ADD CONSTRAINT "scan_chats_role_values" CHECK ("role" IN ('user', 'assistant'));
