# frontend/Dockerfile

FROM node:20-slim AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci

FROM node:20-slim AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:20-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Bring in everything including the build output (.next)
COPY --from=builder /app ./

EXPOSE 8080

# One image, two modes:
# - ENV=local  -> next dev
# - otherwise  -> next start (Cloud Run / prod)
CMD ["sh", "-c", "if [ \"$ENV\" = \"local\" ]; then npm run dev; else npx next start -H 0.0.0.0 -p ${PORT:-8080}; fi"]
