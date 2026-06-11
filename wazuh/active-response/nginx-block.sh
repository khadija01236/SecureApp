#!/bin/sh
# =============================================================================
# nginx-block.sh — Active Response Wazuh 4.x
# Bloque / débloque une IP dans Nginx via un fichier partagé (volume Docker).
#
# Wazuh 4.x envoie une ligne JSON sur stdin (pas de fermeture du pipe).
# On lit UNE ligne avec read -r et on agit immédiatement sans check_keys.
# L'IP est extraite depuis data.ip (Flask) ou data.srcip (standard Wazuh).
# =============================================================================

DENY_FILE="/etc/nginx/wazuh/blocked_ips.conf"
LOG_FILE="/var/ossec/logs/active-responses.log"
NGINX_CONTAINER="nginx_proxy"

TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
echo "$TS [nginx-block] STARTED args=[$*]" >> "$LOG_FILE"

# Lire UNE seule ligne JSON depuis stdin (read -r évite le blocage sur pipe ouvert)
read -r INPUT

if [ -z "$INPUT" ]; then
    echo "$TS [nginx-block] ERREUR : stdin vide" >> "$LOG_FILE"
    exit 1
fi

# Parser le JSON avec Python3
ACTION=$(echo "$INPUT" | python3 -c "import sys,json; print(json.loads(sys.stdin.read()).get('command',''))" 2>/dev/null)
RULE_ID=$(echo "$INPUT" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(d.get('parameters',{}).get('alert',{}).get('rule',{}).get('id',''))" 2>/dev/null)

IP=$(echo "$INPUT" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
data = d.get('parameters', {}).get('alert', {}).get('data', {})
ip = data.get('ip') or data.get('srcip') or data.get('remote_addr') or ''
print(ip)
" 2>/dev/null)

# Valider l'IP
echo "$IP" | grep -Eq '^[0-9a-fA-F.:]+$' || {
    echo "$TS [nginx-block] IP invalide : '$IP' (action=$ACTION rule=$RULE_ID)" >> "$LOG_FILE"
    exit 1
}

touch "$DENY_FILE" 2>/dev/null

reload_nginx() {
    if [ -S /var/run/docker.sock ]; then
        curl -sf -m 5 --unix-socket /var/run/docker.sock \
            -X POST "http://localhost/containers/${NGINX_CONTAINER}/kill?signal=HUP" \
            > /dev/null 2>&1
        echo "$TS [nginx-block] Nginx rechargé (HUP → ${NGINX_CONTAINER})" >> "$LOG_FILE"
    else
        echo "$TS [nginx-block] AVERTISSEMENT : socket Docker absent, Nginx non rechargé" >> "$LOG_FILE"
    fi
}

case "$ACTION" in
    add)
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
            tmp=$(mktemp)
            grep -vF "deny ${IP};" "$DENY_FILE" > "$tmp" && mv "$tmp" "$DENY_FILE"
            echo "$TS [nginx-block] DÉBLOCAGE effectué : ${IP} (règle ${RULE_ID})" >> "$LOG_FILE"
            reload_nginx
        else
            echo "$TS [nginx-block] IP ${IP} non trouvée" >> "$LOG_FILE"
        fi
        ;;
    *)
        echo "$TS [nginx-block] Action inconnue : '$ACTION' ip=$IP rule=$RULE_ID" >> "$LOG_FILE"
        exit 1
        ;;
esac

exit 0
