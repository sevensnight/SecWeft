FROM caddy:2.11.4-alpine

RUN setcap -r /usr/bin/caddy \
    && addgroup -S -g 1000 caddy \
    && adduser -S -D -H -u 1000 -G caddy caddy
COPY apps/api-gateway/Caddyfile /etc/caddy/Caddyfile
USER 1000:1000
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/gateway-healthz || exit 1
ENTRYPOINT ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
