FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

# Create a non-root user for security compliance
RUN groupadd -r ctiuser && useradd -r -g ctiuser ctiuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
RUN mkdir -p /app/output && chown -R ctiuser:ctiuser /app

USER ctiuser

CMD ["python", "-m", "src.main"]