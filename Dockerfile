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

# Pick up Alpine security patches published since the base image was cut. The tag floats, but the
# image itself is rebuilt far less often than its packages are patched — openssl (libssl3 /
# libcrypto3) sat eighteen findings behind, four of them critical, on an otherwise unchanged base.
#
# Then remove the package manager and everything only it needs. Node bundles its own OpenSSL and
# zlib (`ldd /usr/local/bin/node` shows only musl, libstdc++ and libgcc), so the system libssl3,
# libcrypto3 and zlib exist only to serve apk-tools and busybox's ssl_client. Removing them takes
# their CVEs out of the image, including NVD entries that have no Alpine fix yet.
RUN apk upgrade --no-cache \
    && apk --no-cache --purge del apk-tools libapk ssl_client libssl3 libcrypto3 zlib

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
