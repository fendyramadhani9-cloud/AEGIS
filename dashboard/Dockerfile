# syntax=docker/dockerfile:1
# ============================================================================
# AEGIS Dashboard UI — Multi-Stage Build (Node 20 Alpine -> Nginx 1.27 Alpine)
# Listens on Dedicated Tactical Port 1708 (Zero Port 80 usage)
# Final runtime RAM usage: ~8-14 MB
# ============================================================================

FROM node:20-alpine AS builder

WORKDIR /build

COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

COPY . .
RUN npm run build

# ----------------------------------------------------------------------------
# Stage 2: Ultra-lightweight Nginx Alpine runtime (~10 MB RAM) on port 1708
# ----------------------------------------------------------------------------
FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /build/dist /usr/share/nginx/html

EXPOSE 1708

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:1708/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
