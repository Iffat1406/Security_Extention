-- Safe Browsing / VirusTotal verdicts are URL-level, so the cache key becomes
-- the normalised URL (host + redacted path, no query string) rather than the
-- registrable domain. See the ReputationCache comment in schema.prisma.
DROP INDEX "uq_reputation_cache_domain_service";
ALTER TABLE "reputation_cache" RENAME COLUMN "domain" TO "cache_key";
ALTER TABLE "reputation_cache" ALTER COLUMN "cache_key" TYPE VARCHAR(512);
CREATE UNIQUE INDEX "uq_reputation_cache_key_service" ON "reputation_cache"("cache_key", "service");
