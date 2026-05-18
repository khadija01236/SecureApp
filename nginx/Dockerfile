FROM nginx:1.27-alpine

# Outils pour générer le certificat self-signed
RUN apk add --no-cache openssl

# Générer le certificat TLS self-signed au moment du build
RUN mkdir -p /etc/nginx/certs && \
    openssl req -x509 -nodes -days 365 \
      -newkey rsa:2048 \
      -keyout /etc/nginx/certs/server.key \
      -out    /etc/nginx/certs/server.crt \
      -subj "/C=FR/ST=IleDeFrance/L=Paris/O=ESGI/OU=SecureApp/CN=localhost"

# Copier la configuration Nginx
COPY nginx.conf /etc/nginx/nginx.conf

# Répertoire + fichier de deny list Wazuh — créés vides pour éviter une erreur au démarrage
# Seront remplacés par le volume nginx_blocked_ips une fois Wazuh actif
RUN mkdir -p /etc/nginx/wazuh && touch /etc/nginx/wazuh/blocked_ips.conf

# Créer le répertoire de logs
RUN mkdir -p /var/log/nginx

EXPOSE 80 443
