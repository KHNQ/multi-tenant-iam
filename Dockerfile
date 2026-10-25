# The gateway, the failover IdP and the administration console, in one image.
# Base images come from Docker Hub only. Build where there is network access,
# then move the image to an offline server:
#   docker build -t iam-failover-idp:1.1 .
#   docker save iam-failover-idp:1.1 | gzip > iam-failover-idp-1.1.tar.gz
#   (on the server)  docker load < iam-failover-idp-1.1.tar.gz

FROM node:22-bookworm-slim AS console
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM node:22-bookworm-slim AS dependencies
WORKDIR /app
COPY package.json package-lock.json ./
# argon2 and bcrypt ship prebuilt binaries for linux-x64/arm64 (glibc).
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app
COPY --from=dependencies /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY --from=console /build/frontend/dist ./frontend/dist
RUN mkdir -p /app/.run /app/logs && chown node:node /app/.run /app/logs
USER node
EXPOSE 3000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health/ready').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "src/main.reg.js"]
