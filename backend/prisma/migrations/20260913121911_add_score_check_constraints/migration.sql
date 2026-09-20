-- Prisma's schema language has no declarative CHECK-constraint syntax for
-- this Prisma version, so the 0-100 bound from §10/§25.1 is added by hand
-- here rather than left unenforced at the database layer.
ALTER TABLE "scan_results"
  ADD CONSTRAINT "scan_results_security_score_range" CHECK ("security_score" IS NULL OR ("security_score" >= 0 AND "security_score" <= 100)),
  ADD CONSTRAINT "scan_results_privacy_score_range" CHECK ("privacy_score" IS NULL OR ("privacy_score" >= 0 AND "privacy_score" <= 100)),
  ADD CONSTRAINT "scan_results_overall_score_range" CHECK ("overall_score" IS NULL OR ("overall_score" >= 0 AND "overall_score" <= 100));
