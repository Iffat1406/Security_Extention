-- CreateExtension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- CreateEnum
CREATE TYPE "ScanStatus" AS ENUM ('PENDING', 'SCANNING', 'PARTIAL', 'COMPLETED', 'FAILED', 'NOT_SUPPORTED');

-- CreateEnum
CREATE TYPE "RiskBand" AS ENUM ('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateTable
CREATE TABLE "users" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "google_id" VARCHAR(255) NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "display_name" VARCHAR(255) NOT NULL,
    "avatar_url" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_seen_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "is_active" BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "scan_results" (
    "id" UUID NOT NULL DEFAULT gen_random_uuid(),
    "user_id" UUID,
    "registrable_domain" VARCHAR(255) NOT NULL,
    "host" VARCHAR(255) NOT NULL,
    "path" VARCHAR(200),
    "scan_status" "ScanStatus" NOT NULL DEFAULT 'PENDING',
    "scanned_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "started_at" TIMESTAMPTZ(6),
    "completed_at" TIMESTAMPTZ(6),
    "safe_browsing_data" JSONB,
    "ssl_data" JSONB,
    "headers_data" JSONB,
    "tracker_data" JSONB,
    "password_breach_data" JSONB,
    "domain_age_data" JSONB,
    "js_vuln_data" JSONB,
    "mixed_content_data" JSONB,
    "check_status" JSONB,
    "security_score" INTEGER,
    "privacy_score" INTEGER,
    "overall_score" INTEGER,
    "risk_band" "RiskBand",
    "risk_evidence" JSONB,
    "risk_engine_version" VARCHAR(16),
    "scanner_version" VARCHAR(16),
    "schema_version" INTEGER NOT NULL DEFAULT 1,
    "ai_explanation" TEXT,

    CONSTRAINT "scan_results_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_settings" (
    "user_id" UUID NOT NULL,
    "settings" JSONB NOT NULL DEFAULT '{}',
    "excluded_domains" TEXT[],
    "updated_at" TIMESTAMPTZ(6) NOT NULL,

    CONSTRAINT "user_settings_pkey" PRIMARY KEY ("user_id")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_google_id_key" ON "users"("google_id");

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "idx_scan_results_user_id" ON "scan_results"("user_id");

-- CreateIndex
CREATE INDEX "idx_scan_registrable_scanned" ON "scan_results"("registrable_domain", "scanned_at" DESC);

-- CreateIndex
CREATE INDEX "idx_scan_user_scanned" ON "scan_results"("user_id", "scanned_at" DESC);

-- CreateIndex
CREATE INDEX "idx_scan_status_scanned" ON "scan_results"("scan_status", "scanned_at");

-- AddForeignKey
ALTER TABLE "scan_results" ADD CONSTRAINT "scan_results_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_settings" ADD CONSTRAINT "user_settings_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
