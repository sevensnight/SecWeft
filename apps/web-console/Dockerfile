FROM node:26.8.2-alpine AS build

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable && corepack prepare pnpm@10.30.1 --activate

WORKDIR /workspace
COPY package.json pnpm-workspace.yaml pnpm-lock.yaml turbo.json ./
COPY packages ./packages
COPY apps/web-console ./apps/web-console
ARG VITE_AUTH_MODE=compatibility
ARG VITE_OIDC_AUTHORITY=
ARG VITE_OIDC_CLIENT_ID=vulnlab-web-console
ARG VITE_OIDC_SCOPE="openid profile email"
ARG VITE_OIDC_ACR_VALUES=
ENV VITE_AUTH_MODE=$VITE_AUTH_MODE
ENV VITE_OIDC_AUTHORITY=$VITE_OIDC_AUTHORITY
ENV VITE_OIDC_CLIENT_ID=$VITE_OIDC_CLIENT_ID
ENV VITE_OIDC_SCOPE=$VITE_OIDC_SCOPE
ENV VITE_OIDC_ACR_VALUES=$VITE_OIDC_ACR_VALUES
RUN pnpm install --frozen-lockfile \
    && pnpm generate:api \
    && pnpm --filter @vulnlab/web-console build \
    && find apps/web-console/dist -type f -name '*.map' -delete

FROM nginxinc/nginx-unprivileged:1.27.5-alpine
COPY apps/web-console/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=101:101 /workspace/apps/web-console/dist /usr/share/nginx/html
USER 101:101
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
