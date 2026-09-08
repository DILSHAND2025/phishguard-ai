# MAVERICK Intelligence & Machine Learning Backend Container
# Smart India Hackathon 2026
FROM python:3.11-slim

# Install system utilities and Node.js 20 LTS
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg \
    ca-certificates \
    && mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" | tee /etc/apt/sources.list.d/nodesource.list \
    && apt-get update \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python ML dependencies first (cached layer)
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Install Node.js dependencies (cached layer)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy entire application code
COPY . .

# Set execution permissions and strip carriage returns
RUN sed -i 's/\r$//' ./scripts/start-backend.sh && chmod +x ./scripts/start-backend.sh

# Environment defaults
ENV PORT=10000
ENV NODE_ENV=production
ENV PYTHONUNBUFFERED=1

# Expose intelligence gateway and ML ports
EXPOSE 10000 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:${PORT}/api/health || exit 1

# Start both ML engine and Node Intelligence Gateway
CMD ["./scripts/start-backend.sh"]
