#!/bin/bash
set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Panel Installer v1.0${NC}"
echo -e "${GREEN}========================================${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo).${NC}"
    exit 1
fi

echo -e "${YELLOW}Enter username for panel login:${NC}"
read -p "Username: " USERNAME
if [ -z "$USERNAME" ]; then
    echo -e "${RED}Username cannot be empty.${NC}"
    exit 1
fi

PASSWORD=$(openssl rand -base64 12 | tr -d "=+/" | cut -c1-16)
echo -e "${GREEN}Your generated password: ${PASSWORD}${NC}"

RANDOM_PATH=$(openssl rand -hex 4)
PANEL_DIR="/var/www/panel/${RANDOM_PATH}"
mkdir -p "$PANEL_DIR"
chown -R www-data:www-data "$PANEL_DIR"

HASH=$(php -r "echo password_hash('$PASSWORD', PASSWORD_DEFAULT);")
USER_BASE64=$(echo -n "$USERNAME" | base64)

TEMPLATE_URL="https://raw.githubusercontent.com/vesalalizadeh08/vestpanel/main/panel.template.php"
curl -sSL "$TEMPLATE_URL" -o /tmp/panel.template.php

sed -i "s/{{USERNAME_BASE64}}/$USER_BASE64/g" /tmp/panel.template.php
sed -i "s/{{PASS_HASH}}/$HASH/g" /tmp/panel.template.php

mv /tmp/panel.template.php "$PANEL_DIR/panel.php"
chown www-data:www-data "$PANEL_DIR/panel.php"
chmod 644 "$PANEL_DIR/panel.php"

NGINX_CONF="/etc/nginx/conf.d/panel.conf"
cat > "$NGINX_CONF" << EOF
location /$RANDOM_PATH/ {
    alias $PANEL_DIR/;
    index panel.php;
    location ~ \.php$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
    }
}
EOF

nginx -t && systemctl reload nginx

SERVER_IP=$(hostname -I | awk '{print $1}')

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✅ Panel installed successfully!${NC}"
echo -e "${GREEN}🔗 Access URL: http://$SERVER_IP/$RANDOM_PATH/panel.php${NC}"
echo -e "${GREEN}👤 Username: $USERNAME${NC}"
echo -e "${GREEN}🔑 Password: $PASSWORD${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}Please save these credentials.${NC}"
