# CLAUDE.md

Ce fichier fournit des instructions à Claude Code (claude.ai/code) pour travailler dans ce dépôt.

## Présentation du projet

SecureApp est une application web Flask centrée sur la sécurité de l'authentification : MFA (TOTP + OTP par email), protection contre le brute-force, réinitialisation de mot de passe, et journalisation JSON structurée pour ingestion SIEM. La stack couple Flask/PostgreSQL à un SIEM Wazuh qui surveille les logs applicatifs et Nginx pour détecter les attaques et déclencher des réponses actives (ex. blocage d'IPs au niveau Nginx).

## Commandes de développement

### Initialisation
```bash
cp .env.example .env
# Remplir les valeurs dans .env
```

### Stack de développement (hot-reload Flask + MailHog + PostgreSQL)
```bash
docker compose up --build
```
- Application : http://localhost:8080 (via Nginx) ou http://localhost:5000 (direct)
- Interface MailHog : http://localhost:8025
- PostgreSQL : localhost:5432

### Stack de production
```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Migrations de base de données
```bash
# Dans le conteneur (s'exécute automatiquement au démarrage via entrypoint.sh)
flask db upgrade

# Générer une nouvelle migration après modification des modèles
docker compose exec web flask db migrate -m "description"
```

### Tests (SQLite en mémoire, Docker non requis)
```bash
pip install -r requirements-dev.txt
pytest

# Lancer un fichier de test
pytest tests/test_auth.py

# Lancer un test précis
pytest tests/test_auth.py::TestLogin::test_success_by_username -v
```

> **Attention** : `itsdangerous` est dans `requirements-dev.txt` mais utilisé en production pour les tokens de réinitialisation de mot de passe. Vérifier sa présence avant un déploiement prod hors Docker.

### Stack Wazuh SIEM (séparée)
```bash
# Générer les certificats TLS (une seule fois)
bash wazuh/setup.sh

# Lancer Wazuh (la stack applicative doit être démarrée en premier)
docker compose -f wazuh/docker-compose.wazuh.yml up -d
```
- Dashboard Wazuh : https://localhost:5601

## Architecture

### Application Flask (`app/`)

L'application utilise le **pattern application factory** (`create_app()` dans `app/__init__.py`). Les extensions (SQLAlchemy, Flask-Login, Flask-Mail, Flask-Limiter, Flask-Migrate) sont instanciées au niveau module comme singletons, puis rattachées à l'application dans `create_app()`.

Deux blueprints :
- `app/auth/` — toutes les routes d'authentification : inscription, connexion (en 2 étapes avec MFA), configuration/vérification MFA, déconnexion, réinitialisation de mot de passe
- `app/main/` — routes protégées : dashboard, profil, gestion des codes de secours, et endpoint `/health`

**Flux de connexion** : vérification du mot de passe → si MFA activé, stockage de `mfa_user_id` en session et redirection vers `/auth/mfa/verify` → `login_user()` complet uniquement après validation du MFA. La vérification TOTP utilise `valid_window=1` (±30 secondes de tolérance).

**Rate limits** (Flask-Limiter) : `/auth/login` et `/auth/mfa/verify` → 10 req/min ; `/auth/forgot-password` → 5 req/min. Le rate-limiting est désactivé dans les fixtures de test.

### Journalisation des événements de sécurité

Chaque événement d'authentification est enregistré en double :
1. Écrit dans la table `login_events` en base (`app/models.py:LoginEvent`)
2. Émis en JSON structuré dans `/var/log/flask/app.log` via le module `logging` Python avec un `JsonFormatter` custom

C'est ce format JSON que Wazuh analyse. Le helper `_log_event()` dans `app/auth/routes.py` gère les deux.

### Modèles de données (`app/models.py`)

- `User` — identifiants, état MFA (secret TOTP, OTP email), codes de secours (tableau JSON de hashes), compteurs brute-force (`failed_login_attempts`, `locked_until`). Le verrouillage se déclenche à 10 tentatives échouées pendant 15 minutes.
- `LoginEvent` — table de journal d'audit avec des constantes typées pour `event_type`.

Les codes de secours sont générés par lot de **8**, stockés en JSON dans une colonne texte (`backup_codes_json`) sous forme de tableau de hashes bcrypt. Utiliser un code l'invalide en mettant son emplacement à `null`.

### Infrastructure

**Docker Compose (dev)** — `docker-compose.yml` : Nginx → Flask (port 5000, interne uniquement) → PostgreSQL + MailHog. Flask tourne avec `--debug` et le code source est monté en volume pour le hot-reload.

**Docker Compose (prod)** — `docker-compose.prod.yml` : même topologie mais Flask tourne sous Gunicorn (4 workers), sans montage de source, port PostgreSQL non exposé à l'hôte.

**Nginx** — reverse proxy dans `nginx/`. Gère HTTP→HTTPS, transmet les headers `X-Real-IP`/`X-Forwarded-*` (Flask fait confiance via `ProxyFix`). Lit le volume `nginx_blocked_ips` pour les IPs bloquées dynamiquement par Wazuh.

**Wazuh** (`wazuh/docker-compose.wazuh.yml`) — stack compose séparée qui se rattache aux volumes externes nommés `flask_logs`, `nginx_logs` et `nginx_blocked_ips`, ainsi qu'au réseau externe `secureapp_network`. La stack applicative doit être démarrée en premier pour créer ces ressources.

Les règles Wazuh custom (`wazuh/rules/local_rules.xml`, IDs 100000–100016) détectent : échecs de connexion, brute-force, tentatives de bypass MFA, verrouillages de compte, SQLi, XSS, path traversal, dépassement de rate-limit et énumération web. Les règles de niveau ≥ 10 déclenchent une réponse active.

**Aucune CI/CD configurée** — `.github/workflows` est absent. Ne pas supposer qu'un pipeline existe.

### Architecture des tests

Les tests utilisent `pytest` avec les fixtures définies dans `tests/conftest.py`. La fixture `app` remplace la base par SQLite en mémoire, supprime l'envoi de mails et désactive le rate-limiting. Docker n'est pas nécessaire pour les tests.

## Variables d'environnement clés

| Variable | Rôle |
|---|---|
| `SECRET_KEY` | Signature des sessions Flask et des tokens itsdangerous (reset de mot de passe) |
| `DATABASE_URL` | Chaîne de connexion PostgreSQL |
| `MFA_ISSUER` | Libellé affiché dans les applications d'authentification TOTP |
| `MAIL_*` | Configuration SMTP (MailHog en développement) |
| `GUNICORN_WORKERS` | Nombre de workers Gunicorn en production |
