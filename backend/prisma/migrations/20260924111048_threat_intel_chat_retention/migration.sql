/*
  Warnings:

  - Made the column `user_id` on table `scan_results` required. This step will fail if there are existing NULL values in that column.

*/
-- CreateEnum
CREATE TYPE "Reputation" AS ENUM ('UNKNOWN', 'CLEAN', 'SUSPICIOUS', 'MALICIOUS');

-- CreateEnum
CREATE TYPE "IndicatorType" AS ENUM ('PHISHING', 'MALWARE', 'SCAM', 'SUSPICIOUS_DOMAIN', 'LOOKALIKE', 'TRACKER_HEAVY', 'FINGERPRINTING', 'VULNERABLE_JS', 'MIXED_CONTENT', 'EXPIRED_CERT', 'REDIRECT_ABUSE');

-- CreateEnum
CREATE TYPE "IndicatorSource" AS ENUM ('SAFE_BROWSING', 'VIRUSTOTAL', 'SCANNER', 'COMMUNITY', 'ADMIN');

-- CreateEnum
CREATE TYPE "IndicatorSeverity" AS ENUM ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "FeedbackType" AS ENUM ('FALSE_POSITIVE', 'FALSE_NEGATIVE', 'HELPFUL', 'NOT_HELPFUL');

-- CreateEnum
CREATE TYPE "FeedbackStatus" AS ENUM ('NEW', 'REVIEWING', 'CONFIRMED', 'REJECTED');

-- CreateEnum
CREATE TYPE "ExternalService" AS ENUM ('SAFE_BROWSING', 'VIRUSTOTAL', 'WHOIS');

-- DropForeignKey
ALTER TABLE "refresh_tokens" DROP CONSTRAINT "refresh_tokens_user_id_fkey";

-- DropForeignKey
ALTER TABLE "scan_results" DROP CONSTRAINT "scan_results_user_id_fkey";

-- DropForeignKey
ALTER TABLE "user_settings" DROP CONSTRAINT "user_settings_user_id_fkey";

-- DropIndex
DROP INDEX "idx_scan_results_user_id";

-- AlterTable
ALTER TABLE "refresh_tokens" ADD COLUMN     "authenticated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP;

-- AlterTable
ALTER TABLE "scan_results" ADD COLUMN     "ai_advice" TEXT,
ADD COLUMN     "evidence_hash" VARCHAR(64),
ADD COLUMN     "fingerprint_data" JSONB,
ADD COLUMN     "lookalike_data" JSONB,
ADD COLUMN     "redirect_data" JSONB,
ADD COLUMN     "virus_total_data" JSONB,
ALTER COLUMN "user_id" SET NOT NULL;

-- AlterTable
ALTER TABLE "users" ADD COLUMN     "deleted_at" TIMESTAMPTZ(6),
ADD COLUMN     "deletion_requested_at" TIMESTAMPTZ(6),
ADD COLUMN     "last_export_at" TIMESTAMPTZ(6);

-- CreateTable
CREATE TABLE "scan_chats" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "scan_id" UUID NOT NULL,
    "user_id" UUID NOT NULL,
    "role" VARCHAR(20) NOT NULL,
    "content" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_chats_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "domains" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "domain" VARCHAR(255) NOT NULL,
    "first_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "scan_count" INTEGER NOT NULL DEFAULT 0,
    "unique_user_count" INTEGER NOT NULL DEFAULT 0,
    "latest_security_score" INTEGER,
    "reputation" "Reputation" NOT NULL DEFAULT 'UNKNOWN',
    "reputation_confidence" DECIMAL(3,2) NOT NULL DEFAULT 0,
    "domain_age_days" INTEGER,
    "is_allowlisted" BOOLEAN NOT NULL DEFAULT false,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "domains_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_indicators" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "domain_id" UUID NOT NULL,
    "type" "IndicatorType" NOT NULL,
    "source" "IndicatorSource" NOT NULL,
    "severity" "IndicatorSeverity" NOT NULL,
    "confidence" DECIMAL(3,2) NOT NULL,
    "evidence" JSONB NOT NULL DEFAULT '{}',
    "first_detected_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_detected_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "observation_count" INTEGER NOT NULL DEFAULT 1,
    "suppressed_at" TIMESTAMPTZ(6),
    "suppressed_reason" TEXT,

    CONSTRAINT "threat_indicators_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_feedback" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "scan_id" UUID,
    "user_id" UUID NOT NULL,
    "domain" VARCHAR(255) NOT NULL,
    "feedback_type" "FeedbackType" NOT NULL,
    "reported_signal" VARCHAR(48),
    "reason" VARCHAR(500),
    "status" "FeedbackStatus" NOT NULL DEFAULT 'NEW',
    "resolved_by" UUID,
    "resolved_at" TIMESTAMPTZ(6),
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "scan_feedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "reputation_cache" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "domain" VARCHAR(255) NOT NULL,
    "service" "ExternalService" NOT NULL,
    "result" JSONB NOT NULL,
    "checked_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "reputation_cache_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "daily_stats" (
    "date" DATE NOT NULL,
    "scans_total" INTEGER NOT NULL DEFAULT 0,
    "scans_completed" INTEGER NOT NULL DEFAULT 0,
    "scans_partial" INTEGER NOT NULL DEFAULT 0,
    "scans_failed" INTEGER NOT NULL DEFAULT 0,
    "unique_domains" INTEGER NOT NULL DEFAULT 0,
    "avg_security_score" DOUBLE PRECISION,
    "avg_privacy_score" DOUBLE PRECISION,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "daily_stats_pkey" PRIMARY KEY ("date")
);

-- CreateTable
CREATE TABLE "ai_usage" (
    "month" VARCHAR(7) NOT NULL,
    "calls" INTEGER NOT NULL DEFAULT 0,
    "input_tokens" BIGINT NOT NULL DEFAULT 0,
    "output_tokens" BIGINT NOT NULL DEFAULT 0,
    "estimated_cost_usd" DECIMAL(10,4) NOT NULL DEFAULT 0,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ai_usage_pkey" PRIMARY KEY ("month")
);

-- CreateIndex
CREATE INDEX "idx_chats_scan_created" ON "scan_chats"("scan_id", "created_at");

-- CreateIndex
CREATE INDEX "idx_chats_user_created" ON "scan_chats"("user_id", "created_at");

-- CreateIndex
CREATE INDEX "idx_chats_created" ON "scan_chats"("created_at");

-- CreateIndex
CREATE UNIQUE INDEX "domains_domain_key" ON "domains"("domain");

-- CreateIndex
CREATE INDEX "idx_domains_reputation" ON "domains"("reputation", "reputation_confidence" DESC);

-- CreateIndex
CREATE INDEX "idx_indicators_domain_type" ON "threat_indicators"("domain_id", "type");

-- CreateIndex
CREATE INDEX "idx_indicators_last_detected" ON "threat_indicators"("last_detected_at" DESC);

-- CreateIndex
CREATE UNIQUE INDEX "uq_indicator_domain_type_source" ON "threat_indicators"("domain_id", "type", "source");

-- CreateIndex
CREATE INDEX "idx_feedback_domain_status" ON "scan_feedback"("domain", "status");

-- CreateIndex
CREATE INDEX "idx_feedback_user_created" ON "scan_feedback"("user_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "uq_feedback_scan_user" ON "scan_feedback"("scan_id", "user_id");

-- CreateIndex
CREATE UNIQUE INDEX "uq_reputation_cache_domain_service" ON "reputation_cache"("domain", "service");

-- CreateIndex
CREATE INDEX "idx_audit_action_created" ON "audit_logs"("action", "created_at" DESC);

-- CreateIndex
CREATE INDEX "idx_audit_created" ON "audit_logs"("created_at");

-- CreateIndex
CREATE INDEX "idx_refresh_tokens_expires" ON "refresh_tokens"("expires_at");

-- CreateIndex
CREATE INDEX "idx_scan_user_domain" ON "scan_results"("user_id", "registrable_domain");

-- CreateIndex
CREATE INDEX "idx_scan_evidence_hash" ON "scan_results"("evidence_hash", "scanned_at" DESC);

-- CreateIndex
CREATE INDEX "idx_users_deletion_requested" ON "users"("deletion_requested_at");

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_settings" ADD CONSTRAINT "user_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_chats" ADD CONSTRAINT "scan_chats_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scan_results"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_chats" ADD CONSTRAINT "scan_chats_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "threat_indicators" ADD CONSTRAINT "threat_indicators_domain_id_fkey" FOREIGN KEY ("domain_id") REFERENCES "domains"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_feedback" ADD CONSTRAINT "scan_feedback_scan_id_fkey" FOREIGN KEY ("scan_id") REFERENCES "scan_results"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_feedback" ADD CONSTRAINT "scan_feedback_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "scan_feedback" ADD CONSTRAINT "scan_feedback_resolved_by_fkey" FOREIGN KEY ("resolved_by") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;
