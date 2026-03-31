# Varaksha Frontend — Next.js 15 static export served by Nginx
# Used in docker-compose; production deployment is Cloudflare Pages (no Docker needed)

FROM node:20-alpine AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --frozen-lockfile

COPY . .
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL

RUN npm run build

# ── Serve with Nginx ──────────────────────────────────────────────────────────
FROM nginx:alpine AS runtime
COPY --from=builder /app/out /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 3000
CMD ["nginx", "-g", "daemon off;"]
