FROM node:22-alpine AS builder

# Accept version as build arg
ARG VERSION=0.0.0

# Copy source files
COPY . /app

WORKDIR /app

# Generate version file
RUN echo "export const VERSION = \"${VERSION}\";" > src/version.ts

# Install all dependencies (including dev dependencies for build)
RUN --mount=type=cache,target=/root/.npm npm ci

# Run build
RUN npm run build

# Prune to production dependencies for the final image
RUN --mount=type=cache,target=/root/.npm-production npm ci --ignore-scripts --omit=dev

FROM node:22-alpine AS release

# Copy the already-pruned production dependencies rather than reinstalling, so
# the final image needs no package manager at runtime.
COPY --from=builder /app/node_modules /app/node_modules
COPY --from=builder /app/dist /app/dist
COPY --from=builder /app/package.json /app/package.json

# Drop npm from the runtime image. The entrypoint only needs `node`, and npm
# bundles its own dependency tree (tar, sigstore, brace-expansion, ...) which
# would otherwise show up as vulnerabilities in image scans.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack \
    /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg

ENV NODE_ENV=production

WORKDIR /app

# Run unprivileged (the node image ships a non-root `node` user).
USER node

ENTRYPOINT ["node", "dist/index.js"]
