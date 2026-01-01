# DEBUG Dockerfile — shows full errors
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure data directory exists and is writable
RUN mkdir -p /app/data && chmod 777 /app/data

EXPOSE 8000

# Run with Flask dev server (shows real errors)
CMD ["python", "run.py"]