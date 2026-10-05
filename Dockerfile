# Runtime image for the TAR attestation service.
# The application itself uses only the Python standard library; pytest is
# included because the same image backs the one-shot "verify" service.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY tests ./tests
COPY scripts ./scripts

RUN python -m compileall -q app && chown -R nobody:nogroup /app

EXPOSE 8080

HEALTHCHECK --interval=10s --timeout=3s --start-period=3s --retries=3 \
    CMD python -c "import http.client,sys; r=http.client.HTTPConnection('127.0.0.1',int('${PORT}')); r.request('GET','/health'); sys.exit(0 if r.getresponse().status==200 else 1)"

USER nobody

CMD ["python", "-m", "app.server"]
