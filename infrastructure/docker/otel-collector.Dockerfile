FROM otel/opentelemetry-collector-contrib:0.123.0 AS collector

FROM alpine:3.24.1
RUN apk add --no-cache ca-certificates curl \
    && addgroup -S -g 10001 otel \
    && adduser -S -D -H -u 10001 -G otel otel
COPY --from=collector /otelcol-contrib /otelcol-contrib
USER 10001:10001
EXPOSE 4317 4318 8888 8889 13133
ENTRYPOINT ["/otelcol-contrib"]
