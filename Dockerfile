# ===================================================================
#  Build stage
# ===================================================================
FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json tsconfig.json ./
RUN npm ci

COPY src/ ./src/
RUN npm run build

# ===================================================================
#  Production stage
# ===================================================================
FROM node:22-alpine

WORKDIR /app

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy built artifacts and production dependencies
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json tsconfig.json ./
COPY webdavtos3.config.example.json ./

# Expose the default gateway port
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:9000/healthz || exit 1

# Drop privileges
USER appuser

ENTRYPOINT ["node", "dist/main.js"]