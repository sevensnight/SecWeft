FROM python:3.12-alpine
WORKDIR /app
COPY app.py /app/app.py
RUN adduser -D -u 10001 labuser
USER labuser
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=2s --retries=5 CMD wget -q -O /dev/null http://127.0.0.1:8080/
CMD ["python", "/app/app.py"]
