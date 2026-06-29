# SecureApp

Application web Flask centrée sur la sécurité de l'authentification, développée dans le cadre du projet annuel ESGI 2026.

![CI](https://github.com/khadija01236/SecureApp/actions/workflows/ci.yml/badge.svg)

## Sommaire

- [Fonctionnalités](#fonctionnalités)
- [Stack technique](#stack-technique)
- [Architecture](#architecture)
- [Structure du projet](#structure-du-projet)
- [Prérequis](#prérequis)
- [Installation](#installation)
- [Lancer en développement](#lancer-en-développement)
- [Lancer en production](#lancer-en-production)
- [Stack Wazuh SIEM](#stack-wazuh-siem)
- [Variables d'environnement](#variables-denvironnement)
- [Tests](#tests)
- [Migrations de base de données](#migrations-de-base-de-données)
- [Règles de détection Wazuh](#règles-de-détection-wazuh)
- [CI/CD](#cicd)

---

## Fonctionnalités

- **Inscription et connexion sécurisée** avec hachage bcrypt des mots de passe
- **Double authentification (MFA)** : TOTP via Google Authenticator / Authy + OTP par email
- **Codes de secours** : 8 codes à usage unique pour récupération de compte
- **Protection brute-force** : verrouillage du compte après 10 tentatives échouées (15 min)
- **Rate limiting** : 10 req/min sur login/MFA, 5 req/min sur forgot-password
- **Réinitialisation de mot de passe** par email (token signé, durée limitée)
- **Journalisation JSON structurée** de tous les événements de sécurité
- **Intégration SIEM Wazuh** : détection des attaques et réponse active (blocage d'IPs au niveau Nginx)
- **En-têtes de sécurité HTTP** : X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy

---

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Flask 3.1, Python 3.11 |
| Base de données | PostgreSQL 16 + Flask-SQLAlchemy |
| Authentification | Flask-Login |
| MFA | pyotp 2.9 (TOTP), Flask-Mail (OTP email) |
| QR code | qrcode[pil] |
| Rate limiting | Flask-Limiter 3.9 |
| Migrations | Flask-Migrate (Alembic) |
| Reverse proxy | Nginx |
| SIEM | Wazuh 4.x |
| Conteneurs | Docker + Docker Compose |
| Tests | pytest + SQLite en mémoire |
| CI | GitHub Actions |

---

## Architecture

```
Client
  │
  ▼
Nginx (port 8080/443)          ← reverse proxy, TLS, blocage IPs dynamique
  │
  ▼
Flask / Gunicorn (port 5000)   ← application web
  │                    │
  ▼                    ▼
PostgreSQL         /var/log/flask/app.log  (JSON structuré)
                           │
                           ▼
                     Wazuh SIEM
                           │
                           ▼
              Active Response → nginx_blocked_ips (volume partagé)
```

**Flux de connexion MFA :**
```
POST /auth/login
  → vérification mot de passe
  → si MFA activé : stockage mfa_user_id en session → redirect /auth/mfa/verify
  → validation TOTP (window ±30 s) ou OTP email → login_user()
```

---

## Structure du projet

```
SecureApp/
├── app/
│   ├── __init__.py          # Application factory, logging JSON, extensions
│   ├── models.py            # User, LoginEvent
│   ├── auth/
│   │   └── routes.py        # Inscription, login, MFA, reset password
│   ├── main/
│   │   └── routes.py        # Dashboard, profil, codes de secours, /health
│   └── templates/
│       ├── base.html
│       ├── auth/            # login, register, mfa_setup, mfa_verify, forgot/reset password
│       └── main/            # dashboard, profile, backup_codes
├── migrations/              # Alembic — migrations de base de données
├── nginx/
│   ├── Dockerfile
│   └── nginx.conf           # Reverse proxy, headers sécurité, blocage IPs
├── wazuh/
│   ├── docker-compose.wazuh.yml
│   ├── rules/local_rules.xml     # Règles de détection custom (IDs 100000–100018)
│   ├── config/ossec.conf          # Configuration agent/manager Wazuh
│   ├── active-response/nginx-block.sh
│   └── certs/               # Certificats TLS (générés via wazuh/setup.sh)
├── tests/
│   ├── conftest.py          # Fixtures pytest (SQLite mémoire, mail désactivé)
│   ├── test_auth.py
│   ├── test_mfa.py
│   ├── test_password_reset.py
│   ├── test_logs.py
│   └── test_main.py
├── .github/workflows/ci.yml
├── docker-compose.yml           # Stack de développement
├── docker-compose.prod.yml      # Stack de production
├── wazuh.yml                    # Alias / référence config Wazuh
├── Dockerfile
├── entrypoint.sh                # Migrations auto + lancement Flask/Gunicorn
├── wsgi.py
├── requirements.txt
├── requirements-dev.txt
└── .env.example
```

---

## Prérequis

- [Docker](https://docs.docker.com/get-docker/) et Docker Compose (v2+)
- Git
- Python 3.11+ *(uniquement pour lancer les tests sans Docker)*

---

## Installation

```bash
git clone https://github.com/khadija01236/SecureApp.git
cd SecureApp
cp .env.example .env
```

Ouvrir `.env` et ajuster les valeurs (voir [Variables d'environnement](#variables-denvironnement)).

---

## Lancer en développement

```bash
docker compose up --build
```

| Service | URL |
|---|---|
| Application | http://localhost:8080 |
| Flask direct (sans Nginx) | http://localhost:5000 |
| MailHog (capture des emails) | http://localhost:8025 |
| PostgreSQL | localhost:5432 |

Le code source est monté en volume : toute modification Python est rechargée à chaud sans redémarrage.

---

## Lancer en production

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

Différences avec le mode dev :
- Flask tourne sous **Gunicorn** (workers configurés via `GUNICORN_WORKERS`)
- Aucun montage de volume source
- Port PostgreSQL non exposé à l'hôte
- Logs centralisés dans le volume `flask_logs`

---

## Stack Wazuh SIEM

La stack Wazuh est indépendante. Elle se connecte aux volumes nommés créés par la stack applicative.

> La stack applicative (`docker compose up`) doit être démarrée **avant** Wazuh pour que les volumes et le réseau existent.

```bash
# 1. Générer les certificats TLS (une seule fois)
bash wazuh/setup.sh

# 2. Lancer Wazuh
docker compose -f wazuh/docker-compose.wazuh.yml up -d
```

| Service | URL |
|---|---|
| Dashboard Wazuh (OpenSearch) | https://localhost:5601 |

La stack Wazuh monte trois volumes partagés avec l'application :
- `flask_logs` — logs JSON applicatifs (lecture)
- `nginx_logs` — logs d'accès Nginx (lecture)
- `nginx_blocked_ips` — fichier d'IPs bloquées mis à jour par la réponse active (écriture)

---

## Variables d'environnement

Copier `.env.example` en `.env` et remplir les valeurs :

| Variable | Description | Exemple |
|---|---|---|
| `SECRET_KEY` | Clé secrète Flask (sessions + tokens) | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `FLASK_ENV` | Environnement (`development` / `production`) | `development` |
| `DATABASE_URL` | URL PostgreSQL | `postgresql://user:pass@db:5432/dbname` |
| `POSTGRES_USER` | Utilisateur PostgreSQL | `flask_user` |
| `POSTGRES_PASSWORD` | Mot de passe PostgreSQL | `flask_pass` |
| `POSTGRES_DB` | Nom de la base | `flask_mfa_db` |
| `MFA_ISSUER` | Nom affiché dans l'app TOTP | `SecureApp` |
| `MAIL_SERVER` | Serveur SMTP | `mailhog` (dev) / `smtp.example.com` (prod) |
| `MAIL_PORT` | Port SMTP | `1025` (dev) / `587` (prod) |
| `MAIL_USE_TLS` | TLS SMTP | `false` / `true` |
| `MAIL_USERNAME` | Identifiant SMTP | *(vide en dev)* |
| `MAIL_PASSWORD` | Mot de passe SMTP | *(vide en dev)* |
| `MAIL_DEFAULT_SENDER` | Adresse expéditeur | `noreply@secureapp.local` |
| `GUNICORN_WORKERS` | Nombre de workers Gunicorn (prod) | `4` |

Générer une `SECRET_KEY` sécurisée :
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Tests

Les tests utilisent SQLite en mémoire — **Docker non requis**.

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Lancer un fichier ou un test précis :
```bash
pytest tests/test_auth.py -v
pytest tests/test_mfa.py::TestTOTP::test_setup -v
```

**Couverture actuelle : 57 tests** couvrant :
- Authentification (inscription, login, logout)
- MFA TOTP (setup, vérification, window de tolérance)
- MFA OTP email
- Codes de secours (génération, utilisation, invalidation)
- Réinitialisation de mot de passe (token valide / expiré / invalide)
- Protection brute-force et verrouillage de compte
- Journalisation des événements de sécurité

---

## Migrations de base de données

Les migrations sont appliquées **automatiquement** au démarrage via `entrypoint.sh`. Pour les gérer manuellement :

```bash
# Appliquer toutes les migrations en attente
docker compose exec web flask db upgrade

# Créer une nouvelle migration après modification des modèles
docker compose exec web flask db migrate -m "description de la migration"

# Annuler la dernière migration
docker compose exec web flask db downgrade
```

---

## Règles de détection Wazuh

Les règles custom (`wazuh/rules/local_rules.xml`, IDs 100000–100018) détectent :

| ID | Événement | Niveau |
|---|---|---|
| 100000–100002 | Échecs de connexion (utilisateur / IP inconnu) | 5–6 |
| 100003–100004 | Brute-force (≥5 / ≥10 tentatives) | 10–12 |
| 100005 | Tentative de bypass MFA | 10 |
| 100006 | Verrouillage de compte | 8 |
| 100007–100008 | Injection SQL / XSS | 12 |
| 100009 | Path traversal | 10 |
| 100010–100011 | Rate-limit dépassé | 8–10 |
| 100012 | Énumération web (scan de routes) | 8 |
| 100013–100015 | Événements MFA (succès, échec OTP, backup code) | 3–8 |
| 100016–100018 | Connexion réussie / compte déverrouillé | 3–4 |

Les alertes de **niveau ≥ 10** déclenchent la réponse active `nginx-block` qui ajoute l'IP dans le volume partagé `nginx_blocked_ips`, bloquant immédiatement les requêtes au niveau Nginx.

---

## CI/CD

GitHub Actions (`.github/workflows/ci.yml`) s'exécute à chaque push/PR sur `master` / `main` :

1. Checkout du code
2. Setup Python 3.11
3. Installation des dépendances (`requirements-dev.txt`)
4. Création du répertoire de logs (`/var/log/flask`)
5. Exécution de la suite de tests avec `pytest`
