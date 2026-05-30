#!/bin/bash
# =============================================================================
# wazuh_rules_test.sh — Test des règles Wazuh via wazuh-logtest
#
# Prérequis : stack Wazuh lancée (docker compose -f wazuh/docker-compose.wazuh.yml up -d)
#
# Usage :
#   bash tests/wazuh_rules_test.sh
# =============================================================================

WAZUH_CONTAINER="wazuh-manager"
PASS=0
FAIL=0

run_test() {
    local description="$1"
    local log_line="$2"
    local expected_rule="$3"

    result=$(echo "$log_line" | docker exec -i "$WAZUH_CONTAINER" /var/ossec/bin/wazuh-logtest -U 2>/dev/null | grep -o "Rule Id: [0-9]*" | awk '{print $3}')

    if echo "$result" | grep -q "$expected_rule"; then
        echo "  [PASS] $description (règle $expected_rule)"
        PASS=$((PASS + 1))
    else
        echo "  [FAIL] $description — attendu règle $expected_rule, obtenu: '$result'"
        FAIL=$((FAIL + 1))
    fi
}

echo ""
echo "======================================"
echo " Tests des règles Wazuh — SecureApp"
echo "======================================"
echo ""

# --- Logs Flask (source: flask) ---
echo "[Flask] Événements d'authentification"

run_test "Echec de connexion (login_fail)" \
    '{"source":"flask","timestamp":"2026-01-01T10:00:00","level":"INFO","message":"auth_event","event_type":"login_fail","user":"alice","ip":"10.0.0.1","user_agent":"Mozilla/5.0","details":"identifier=alice"}' \
    "100001"

run_test "Connexion réussie (login_success)" \
    '{"source":"flask","timestamp":"2026-01-01T10:00:00","level":"INFO","message":"auth_event","event_type":"login_success","user":"alice","ip":"10.0.0.1","user_agent":"Mozilla/5.0","details":null}' \
    "100002"

run_test "Echec MFA (mfa_fail)" \
    '{"source":"flask","timestamp":"2026-01-01T10:00:00","level":"INFO","message":"auth_event","event_type":"mfa_fail","user":"alice","ip":"10.0.0.1","user_agent":"Mozilla/5.0","details":"method=totp"}' \
    "100004"

run_test "Compte verrouillé (account_locked)" \
    '{"source":"flask","timestamp":"2026-01-01T10:00:00","level":"INFO","message":"auth_event","event_type":"account_locked","user":"alice","ip":"10.0.0.1","user_agent":"Mozilla/5.0","details":null}' \
    "100006"

echo ""
echo "[Nginx] Attaques web"

run_test "Injection SQL dans l'URI" \
    '{"source":"nginx","remote_addr":"10.0.0.2","method":"GET","uri":"/auth/login?id=1 UNION SELECT username,password FROM users--","status":400}' \
    "100011"

run_test "XSS dans l'URI" \
    '{"source":"nginx","remote_addr":"10.0.0.2","method":"GET","uri":"/auth/login?next=<script>alert(document.cookie)</script>","status":400}' \
    "100012"

run_test "Path traversal dans l'URI" \
    '{"source":"nginx","remote_addr":"10.0.0.2","method":"GET","uri":"/static/../../../etc/passwd","status":403}' \
    "100013"

run_test "Rate limit atteint (erreur 429)" \
    '{"source":"nginx","remote_addr":"10.0.0.3","method":"POST","uri":"/auth/login","status":429}' \
    "100014"

echo ""
echo "======================================"
printf " Résultat : %d passés, %d échoués\n" "$PASS" "$FAIL"
echo "======================================"
echo ""

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
