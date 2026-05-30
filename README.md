# SecureApp

Application web Flask centrée sur la sécurité de l'authentification, développée dans le cadre du projet annuel ESGI 2026.

![CI](https://github.com/khadija01236/SecureApp/actions/workflows/ci.yml/badge.svg)

## Fonctionnalités

- Inscription et connexion sécurisée
- Double authentification (MFA) : TOTP (Google Authenticator) + OTP par email
- Protection contre le brute-force : verrouillage du compte après 10 tentatives échouées (15 min)
- Réinitialisation de mot de passe par email
- Codes de secours (8 codes à usage unique)
- Journalisation JSON structurée des événements de sécurité
- Intégration SIEM Wazuh avec détection et réponse active (blocage d'IPs)

## Stack technique

| Composant | Technologie |
|---|---|
| Backend | Flask 3.1, Python 3.11 |
| Base de données | PostgreSQL + Flask-SQLAlchemy |
| MFA | pyotp (TOTP), Flask-Mail (OTP email) |
| Rate limiting | Flask-Limiter |
| Reverse proxy | Nginx |
| SIEM | Wazuh |
| Conteneurs | Docker + Docker Compose |

## Architecture

```
Client → Nginx (reverse proxy) → Flask (port 5000) → PostgreSQL
                                       ↓
                               /var/log/flask/app.log
                                       ↓
                                 Wazuh SIEM → Active Response (blocage IP)
```

## Lancer le projet

### Prérequis

- Docker et Docker Compose installés
- Git

### Installation

```bash
git clone https://github.com/khadija01236/SecureApp.git
cd SecureApp
cp .env.example .env
# Modifier les valeurs dans .env
```

### Développement

```bash
docker compose up --build
```

- Application : http://localhost:8080
- MailHog (emails) : http://localhost:8025

### Production

```bash
docker compose -f docker-compose.prod.yml up --build -d
```

### Stack Wazuh (optionnel)

```bash
# Générer les certificats TLS (une seule fois)
bash wazuh/setup.sh

# Lancer Wazuh (après la stack applicative)
docker compose -f wazuh/docker-compose.wazuh.yml up -d
```

- Dashboard Wazuh : https://localhost:5601

## Variables d'environnement

Copier `.env.example` en `.env` et remplir les valeurs :

| Variable | Description |
|---|---|
| `SECRET_KEY` | Clé secrète Flask (sessions + tokens) |
| `DATABASE_URL` | URL de connexion PostgreSQL |
| `MFA_ISSUER` | Nom affiché dans l'app TOTP |
| `MAIL_SERVER` | Serveur SMTP |
| `GUNICORN_WORKERS` | Nombre de workers en production |

Générer une `SECRET_KEY` sécurisée :
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

## Tests

Les tests utilisent SQLite en mémoire — Docker non requis.

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

57 tests couvrant : authentification, MFA (TOTP + OTP email + codes de secours), réinitialisation de mot de passe, protection brute-force.

## Migrations de base de données

```bash
# Appliquer les migrations (automatique au démarrage via entrypoint.sh)
docker compose exec web flask db upgrade

# Créer une nouvelle migration après modification des modèles
docker compose exec web flask db migrate -m "description"
```

## Règles de détection Wazuh

Les règles custom (IDs 100000–100016) détectent :

- Échecs de connexion et brute-force
- Tentatives de bypass MFA
- Verrouillages de compte
- Injections SQL, XSS, path traversal
- Dépassements de rate-limit
- Énumération web

Les alertes de niveau ≥ 10 déclenchent un blocage automatique de l'IP au niveau Nginx.
