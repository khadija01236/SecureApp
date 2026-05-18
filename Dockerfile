# ── Image de base ─────────────────────────────────────────────────────────
FROM python:3.12-slim

# Évite les fichiers .pyc et force les logs en temps réel
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Répertoire de travail ──────────────────────────────────────────────────
WORKDIR /app

# ── Dépendances système (psycopg2 a besoin de libpq) ──────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# ── Dépendances Python ────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==22.0.0

# ── Code source ───────────────────────────────────────────────────────────
COPY . .

# ── Répertoire de logs (monté en volume) ──────────────────────────────────
RUN mkdir -p /var/log/flask

# ── Entrypoint : applique les migrations puis lance la commande fournie ───
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# ── Port exposé (interne uniquement, Nginx fait le proxy) ─────────────────
EXPOSE 5000

ENTRYPOINT ["/entrypoint.sh"]

# ── Lancement par défaut : Gunicorn ───────────────────────────────────────
# En dev, override via docker-compose `command: flask --app app run ...`
CMD ["gunicorn", "--bind", "0.0.0.0:5000", \
     "--workers", "4", \
     "--timeout", "60", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "wsgi:app"]
