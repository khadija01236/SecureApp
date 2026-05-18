#!/bin/sh
# =============================================================================
# nginx-block.sh — Active Response Wazuh
# Bloque / débloque une IP dans Nginx via un fichier partagé (volume Docker).
#
# Wazuh passe les arguments dans cet ordre :
#   $1 = action      : "add" (bloquer) | "delete" (débloquer)
#   $2 = user        : utilisateur concerné (peut être vide)
#   $3 = ip          : adresse IP source à bloquer
#   $4 = alert_id    : ID de l'alerte Wazuh
#   $5 = rule_id     : ID de la règle déclenchante
#   $6 = agent_name  : nom de l'agent (ici : wazuh-manager)
#   $7 = filename    : fichier log source (peut être vide)
#
# Le fichier de blocage est lu par Nginx via `include /etc/nginx/blocked_ips.conf`.
# Nginx doit être rechargé après modification — via le socket Docker.
#
# Prérequis dans docker-compose.wazuh.yml :
#   - volume  nginx_blocked_ips monté sur /etc/nginx/blocked_ips.conf (Wazuh + Nginx)
#   - volume  /var/run/docker.sock:/var/run/docker.sock monté dans Wazuh manager
# =============================================================================

ACTION="$1"
IP="$3"
RULE_ID="$5"

DENY_FILE="/etc/nginx/wazuh/blocked_ips.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"
NGINX_CONTAINER="nginx_proxy"

# Timestamp ISO 8601
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Valider l'IP (IPv4 ou IPv6 simple)
echo "$IP" | grep -Eq '^[0-9a-fA-F.:]+$' || {
    echo "$TS [nginx-block] IP invalide : '$IP'" >> "$LOG_FILE"
    exit 1
}

# S'assurer que le fichier existe
touch "$DENY_FILE" 2>/dev/null

reload_nginx() {
    if [ -S /var/run/docker.sock ]; then
        # Envoyer SIGHUP à Nginx via le socket Docker (reload gracieux)
        curl -sf --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/containers/${NGINX_CONTAINER}/kill?signal=HUP" \
            > /dev/null 2>&1
        echo "$TS [nginx-block] Nginx rechargé (HUP envoyé à ${NGINX_CONTAINER})" >> "$LOG_FILE"
    else
        echo "$TS [nginx-block] AVERTISSEMENT : socket Docker absent, Nginx non rechargé" >> "$LOG_FILE"
    fi
}

case "$ACTION" in
    add)
        # Éviter les doublons
        if grep -qF "deny ${IP};" "$DENY_FILE" 2>/dev/null; then
            echo "$TS [nginx-block] IP ${IP} déjà bloquée (règle ${RULE_ID})" >> "$LOG_FILE"
        else
            echo "deny ${IP}; # blocked_rule=${RULE_ID} ts=${TS}" >> "$DENY_FILE"
            echo "$TS [nginx-block] BLOCAGE ajouté : ${IP} (règle ${RULE_ID})" >> "$LOG_FILE"
            reload_nginx
        fi
        ;;

    delete)
        if grep -qF "deny ${IP};" "$DENY_FILE" 2>/dev/null; then
            # Supprimer la ligne contenant l'IP (compatible busybox sed)
            tmp=$(mktemp)
            grep -vF "deny ${IP};" "$DENY_FILE" > "$tmp" && mv "$tmp" "$DENY_FILE"
            echo "$TS [nginx-block] DÉBLOCAGE effectué : ${IP} (règle ${RULE_ID})" >> "$LOG_FILE"
            reload_nginx
        else
            echo "$TS [nginx-block] IP ${IP} non trouvée dans la liste de blocage" >> "$LOG_FILE"
        fi
        ;;

    *)
        echo "$TS [nginx-block] Action inconnue : '$ACTION'" >> "$LOG_FILE"
        exit 1
        ;;
esac

exit 0
