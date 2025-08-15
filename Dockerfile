# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build application
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install dumb-init for proper signal handling
RUN apk add --no-cache dumb-init

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Copy package files
COPY package*.json ./

# Install production dependencies only
RUN npm ci --omit=dev && \
    npm cache clean --force

# Copy built application
COPY --from=builder /app/dist ./dist
COPY package.json ./

# Switch to non-root user
USER nodejs

# Set default environment variables for TCB
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    USE_SECRET_STORE=false

# Expose port
EXPOSE 3000

# Health check for TCB
# initialDelaySeconds must be >= app startup time
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health/ready', (r) => r.statusCode === 200 ? process.exit(0) : process.exit(1))"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start application
CMD ["node", "dist/index.tcb.js"]