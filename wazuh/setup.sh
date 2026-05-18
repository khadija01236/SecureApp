#!/bin/bash
# =============================================================================
# setup.sh — Initialisation du SIEM Wazuh
# À exécuter depuis la racine du projet : bash wazuh/setup.sh
# Compatible Windows (Git Bash + Docker Desktop) et Linux/Mac
# =============================================================================

set -euo pipefail

# Empêche Git Bash de convertir les flags openssl (-subj, etc.)
export MSYS_NO_PATHCONV=1

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="$SCRIPT_DIR/certs"
mkdir -p "$CERTS_DIR"

# Sur Windows avec Git Bash, openssl (MinGW) nécessite des chemins Windows
# pour ses flags -out/-in/-CA/-CAkey. On convertit avec cygpath si disponible.
to_os_path() {
    if command -v cygpath >/dev/null 2>&1; then
        cygpath -w "$1"
    else
        echo "$1"
    fi
}

C="$(to_os_path "$CERTS_DIR")"

echo "[*] Vérification des prérequis..."
command -v docker  >/dev/null 2>&1 || { echo "Docker est requis.";  exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "OpenSSL est requis."; exit 1; }

# =============================================================================
# Génération des certificats TLS avec openssl
# =============================================================================

sign_cert() {
    local name="$1"
    local san="$2"
    local cn="${3:-$name}"

    echo "  → $name"

    # Clé privée
    openssl genrsa 2048 > "${CERTS_DIR}/${name}-key.pem" 2>/dev/null

    # Fichier d'extensions SAN
    cat > "${CERTS_DIR}/${name}-ext.cnf" << EOF
[v3_req]
subjectAltName = DNS:${san},DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
EOF

    # CSR → certificat signé
    openssl req -new \
        -key    "$(to_os_path "${CERTS_DIR}/${name}-key.pem")" \
        -subj   "/C=FR/O=SecureApp ESGI/CN=${cn}" \
        2>/dev/null \
    | openssl x509 -req -sha256 \
        -CA     "$(to_os_path "${CERTS_DIR}/root-ca.pem")" \
        -CAkey  "$(to_os_path "${CERTS_DIR}/root-ca-key.pem")" \
        -CAcreateserial \
        -out    "$(to_os_path "${CERTS_DIR}/${name}.pem")" \
        -days   730 \
        -extfile "$(to_os_path "${CERTS_DIR}/${name}-ext.cnf")" \
        -extensions v3_req \
        2>/dev/null

    rm -f "${CERTS_DIR}/${name}-ext.cnf"
}

if [ -f "$CERTS_DIR/root-ca.pem" ]; then
    echo "[!] Certificats déjà présents. Supprime wazuh/certs/ pour les régénérer."
else
    echo "[*] Génération des certificats TLS..."

    # ── Root CA ───────────────────────────────────────────────────────────
    echo "  → Root CA"
    openssl genrsa 4096 > "${CERTS_DIR}/root-ca-key.pem" 2>/dev/null
    openssl req -new -x509 -sha256 \
        -key  "$(to_os_path "${CERTS_DIR}/root-ca-key.pem")" \
        -out  "$(to_os_path "${CERTS_DIR}/root-ca.pem")" \
        -days 730 \
        -subj "/C=FR/O=SecureApp ESGI/CN=SecureApp Root CA" \
        2>/dev/null

    # Copie pour le manager (Filebeat l'attend sous ce nom)
    cp "${CERTS_DIR}/root-ca.pem" "${CERTS_DIR}/root-ca-manager.pem"

    # ── Admin (OpenSearch Security bootstrap) ─────────────────────────────
    echo "  → admin"
    openssl genrsa 2048 > "${CERTS_DIR}/admin-key.pem" 2>/dev/null
    openssl req -new \
        -key  "$(to_os_path "${CERTS_DIR}/admin-key.pem")" \
        -subj "/C=FR/O=SecureApp ESGI/CN=admin" \
        2>/dev/null \
    | openssl x509 -req -sha256 \
        -CA    "$(to_os_path "${CERTS_DIR}/root-ca.pem")" \
        -CAkey "$(to_os_path "${CERTS_DIR}/root-ca-key.pem")" \
        -CAcreateserial \
        -out   "$(to_os_path "${CERTS_DIR}/admin.pem")" \
        -days  730 \
        2>/dev/null

    # ── Certificats des services ──────────────────────────────────────────
    sign_cert "wazuh-indexer"   "wazuh-indexer"
    sign_cert "wazuh-manager"   "wazuh-manager"
    sign_cert "wazuh-dashboard" "wazuh-dashboard"

    # 644 : lisible par tous (nécessaire pour OpenSearch/Java dans le conteneur)
    chmod 644 "${CERTS_DIR}"/*.pem 2>/dev/null || true
    echo "[+] Certificats générés dans wazuh/certs/"
fi

# =============================================================================
# Vérifier que le réseau et les volumes du stack principal existent
# =============================================================================
echo "[*] Vérification du réseau Docker secureapp_network..."
if ! docker network ls --format '{{.Name}}' | grep -q "^secureapp_network$"; then
    echo "[!] Lance d'abord le stack principal : docker-compose up -d"
    exit 1
fi

echo "[*] Vérification des volumes de logs..."
for vol in flask_logs nginx_logs; do
    if ! docker volume ls --format '{{.Name}}' | grep -q "^${vol}$"; then
        echo "[!] Volume $vol introuvable. Lance d'abord : docker-compose up -d"
        exit 1
    fi
done

# =============================================================================
# Démarrer le stack Wazuh
# =============================================================================
echo "[*] Démarrage du stack Wazuh..."
# Réactiver la conversion de chemins pour docker-compose (binaire Windows)
unset MSYS_NO_PATHCONV
docker-compose -f "$SCRIPT_DIR/docker-compose.wazuh.yml" up -d

echo ""
echo "[+] Wazuh démarré ! Attends 2-3 minutes que les services s'initialisent."
echo ""
echo "    Dashboard : https://localhost:5601"
echo "    Login     : admin / SecretPassword"
echo ""
echo "    Manager API : https://localhost:55000"
echo "    Login API   : wazuh-wui / MyS3cr37P450r.*-"
