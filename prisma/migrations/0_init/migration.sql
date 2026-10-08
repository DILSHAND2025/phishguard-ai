-- CreateTable
CREATE TABLE IF NOT EXISTS "email_cases" (
    "id" TEXT NOT NULL,
    "caseId" TEXT NOT NULL,
    "subject" TEXT NOT NULL DEFAULT '(No Subject)',
    "sender" TEXT NOT NULL DEFAULT 'unknown@sender.local',
    "recipient" TEXT NOT NULL DEFAULT 'unknown@recipient.local',
    "receivedAt" TIMESTAMP(3),
    "analyzedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "threatScore" INTEGER NOT NULL DEFAULT 0,
    "priority" TEXT NOT NULL DEFAULT 'Low',
    "classification" TEXT NOT NULL DEFAULT 'Legitimate',
    "confidence" DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    "phishingProbability" DOUBLE PRECISION,
    "legitimateProbability" DOUBLE PRECISION,
    "riskSummary" TEXT,
    "originalFilename" TEXT,
    "emailHash" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "headers" JSONB,
    "iocs" JSONB,
    "geoIntelligence" JSONB,
    "authenticationResults" JSONB,
    "attachmentFindings" JSONB,
    "evidenceFusion" JSONB,
    "recommendations" JSONB,
    "timeline" JSONB,
    "forensicMetadata" JSONB,

    CONSTRAINT "email_cases_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX IF NOT EXISTS "email_cases_caseId_key" ON "email_cases"("caseId");
CREATE INDEX IF NOT EXISTS "email_cases_threatScore_idx" ON "email_cases"("threatScore" DESC);
CREATE INDEX IF NOT EXISTS "email_cases_createdAt_idx" ON "email_cases"("createdAt" DESC);
CREATE INDEX IF NOT EXISTS "email_cases_priority_idx" ON "email_cases"("priority");
CREATE INDEX IF NOT EXISTS "email_cases_classification_idx" ON "email_cases"("classification");
CREATE INDEX IF NOT EXISTS "email_cases_status_idx" ON "email_cases"("status");
CREATE INDEX IF NOT EXISTS "email_cases_emailHash_idx" ON "email_cases"("emailHash");
