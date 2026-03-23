# ── Image de base ─────────────────────────────────────────────────────
FROM python:3.12-slim

# Évite les fichiers .pyc et force les logs en temps réel
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# ── Répertoire de travail ──────────────────────────────────────────────
WORKDIR /app

# ── Dépendances système (psycopg2 a besoin de libpq) ──────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# ── Dépendances Python ────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Code source ───────────────────────────────────────────────────────
COPY . .

# ── Port exposé ───────────────────────────────────────────────────────
EXPOSE 5000

# ── Lancement avec Gunicorn (prod) ou Flask dev server ────────────────
CMD ["flask", "--app", "app", "run", "--host=0.0.0.0", "--port=5000", "--debug"]
