# MAVERICK — Cybersecurity Intelligence & Incident Response Platform
**Smart India Hackathon 2026**

MAVERICK is an enterprise-grade Autonomous Security Operations Center (SOC) email perimeter defense and forensic case management platform. It combines static RFC 822 parser heuristics, deep-learning NLP (TF-IDF + Logistic Regression), multi-hop GeoIP/ASN infrastructure mapping, SPF/DKIM/DMARC authentication diagnostics, static attachment payload inspection, and Multi-Layer Evidence Fusion.

---

## Database Architecture (PostgreSQL + Prisma ORM)

MAVERICK utilizes **PostgreSQL** with **Prisma ORM** for persistent, auditable email case investigation records.

### Case Database Model (`email_cases`)
- **Primary Identifiers**: `id` (UUID), `caseId` (`MAV-2026-XXXXXXXX`), `emailHash` (SHA-256)
- **Metadata**: `subject`, `sender`, `recipient`, `receivedAt`, `analyzedAt`, `originalFilename`
- **Assessment & Scoring**: `threatScore` (0–100, indexed DESC), `priority` (`Critical` | `High` | `Medium` | `Low`), `classification` (`Phishing` | `Suspicious` | `Legitimate`), `confidence`
- **Machine Learning**: `phishingProbability`, `legitimateProbability`
- **Structured Forensic JSON**:
  - `headers`: Full RFC 822 envelope headers
  - `iocs`: Extracted and enriched Indicators of Compromise
  - `geoIntelligence`: Originating IP, ASN, transit hops, and network roles
  - `authenticationResults`: SPF, DKIM, and DMARC verification details
  - `attachmentFindings`: Static file signatures, hashes, and payload indicators
  - `evidenceFusion`: Itemized 6-layer evidence ledger and factor breakdown
  - `recommendations`: Actionable SOC playbooks and containment directives
  - `timeline`: Sequential chain-of-custody audit timestamps
  - `forensicMetadata`: Correlated threat actor cluster / campaign links
- **Lifecycle & Auditing**: `status` (`active` | `archived` | `closed`), `createdAt`, `updatedAt`

---

## Environment Configuration

Configure your environment variables in `.env` (refer to `.env.example`):

```bash
# PostgreSQL Connection URL
DATABASE_URL=postgresql://user:password@localhost:5432/maverick_soc?schema=public

# Optional Threat Intelligence Feeds
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=

# Google OAuth (Optional)
VITE_GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_ID=
```

> **Security Notice**: Never commit live credentials or database passwords to source control.

---

## Database Setup & Migrations

Run database generation and schema migration:

```bash
# Generate Prisma Client
npm run db:generate

# Push schema directly to database (Development)
npm run db:push

# Deploy migrations (Production / CI/CD)
npm run db:migrate
```

---

## Priority Queue & Scoring Architecture

All cases in MAVERICK are prioritized based on the **authoritative Evidence Fusion threat score (0–100)**:

| Threat Score | SOC Priority | Visual Indicator | Action Threshold |
|---|---|---|---|
| **80 – 100** | **Critical** | 🔴 Red | Immediate containment & mailbox isolation |
| **60 – 79**  | **High**     | 🟠 Orange | Automated SOC alert & user credential review |
| **30 – 59**  | **Medium**   | 🟡 Amber | Sandbox quarantine & URL sinkholing |
| **0 – 29**   | **Low**      | 🟢 Green | Benign communication baseline |

- Cases list API (`GET /api/cases`) sorts by `threatScore DESC`, then `createdAt DESC` by default, ensuring analysts always inspect highest-risk incidents first.

---

## Duplicate Email Handling

- Each email is hashed using **SHA-256** on its raw header and body content (`emailHash`).
- If an email is re-scanned:
  - MAVERICK detects the duplicate record via `emailHash`.
  - Re-opens the case if archived (`status: 'active'`).
  - Updates the investigation record with latest threat intelligence without creating redundant duplicate rows.
  - Returns the original Case ID (`MAV-2026-XXXXXXXX`) with `isDuplicate: true`.

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/cases` | Retrieves case queue sorted by `threatScore DESC` with filters (`priority`, `classification`, `status`, `page`, `limit`, `search`) |
| `POST` | `/api/cases` | Saves analyzed email investigation record |
| `GET` | `/api/cases/:caseId` | Retrieves complete stored investigation for reopening |
| `PATCH` | `/api/cases/:caseId` | Soft archives or updates case status (`{ "status": "archived" }`) |
| `GET` | `/api/cases/stats` | Returns real database metrics (`totalCases`, `critical`, `high`, `medium`, `low`, `topThreats`) |
| `POST` | `/api/predict` | ML inference microservice |
| `POST` | `/api/email-authentication` | RFC 822 authentication diagnostics (SPF/DKIM/DMARC) |
| `POST` | `/api/attachment/analyze` | Static binary attachment forensics |
| `POST` | `/api/forensic-report/pdf` | Compiles certifiable PDF forensic dossier |
| `GET` | `/api/health` | Gateway health check & DB status |

---

## Running Locally

```bash
# Install dependencies
npm install

# Run complete test suite (113 baseline + 19 database tests)
npm test

# Run frontend development server
npm run dev

# Run backend intelligence gateway
npm run server
```
