#!/bin/sh
set -e

echo "[entrypoint] Checking migrations folder..."
if [ ! -d "migrations" ]; then
    echo "[entrypoint] Dossier migrations absent — initialisation..."
    flask db init
    flask db migrate -m "initial migration"
fi

echo "[entrypoint] Applying database migrations..."
flask db upgrade

echo "[entrypoint] Starting application..."
exec "$@"
