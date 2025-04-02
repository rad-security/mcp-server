FROM node:22.12-alpine AS builder

# Accept version as build arg
ARG VERSION=0.0.0

# Copy source files
COPY . /app

WORKDIR /app

# Generate version file
RUN echo "export const VERSION = \"${VERSION}\";" > src/version.ts

# Install all dependencies (including dev dependencies for build)
RUN --mount=type=cache,target=/root/.npm npm install

# Run build
RUN npm run build

# Install only production dependencies for the final image
RUN --mount=type=cache,target=/root/.npm-production npm ci --ignore-scripts --omit-dev

FROM node:22-alpine AS release

COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json
COPY --from=builder /app/package-lock.json /app/package-lock.json

ENV NODE_ENV=production

WORKDIR /app

RUN npm ci --ignore-scripts --omit-dev

ENTRYPOINT ["node", "dist/index.js"]
