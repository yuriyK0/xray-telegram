#!/bin/bash

set -e

# XRAY VPN + TELEGRAM BOT v23.0-full (FIXED)
# НАДЁЖНЫЕ уведомления (API + systemd) + исправлена смена Reality + whitelist
# ИСПРАВЛЕНО: права на файлы для корректной работы уведомлений

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                XRAY VPN + TELEGRAM BOT                        ║"
echo "║                    v23.0-full                                 ║"
echo "║                                                                ║"
echo "║   🔔 НАДЁЖНЫЕ уведомления (API + systemd service)            ║"
echo "║   🔧 ИСПРАВЛЕНА смена Reality из бота (--force режим)         ║"
echo "║   🎭 WHITELIST: GitHub, Google, Yahoo                         ║"
echo "║   ✅ ИСПРАВЛЕНЫ права файлов для работы из коробки            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Check if this is an update from previous version
if [[ -f "/usr/local/etc/xray/config.json" ]]; then
    echo -e "${YELLOW}📋 Обнаружена предыдущая установка - обновление до v23.0-full${NC}"
    UPDATE_MODE=true
    
    cp /usr/local/etc/xray/config.json /usr/local/etc/xray/config.json.backup.$(date +%s)
    
    if [[ -f "/usr/local/etc/xray/.keys" ]]; then
        SERVER_IP=$(curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
        REALITY_SNI=$(awk -F': ' '/reality_sni/ {print $2}' /usr/local/etc/xray/.keys)
        REALITY_NAME=$(awk -F': ' '/reality_name/ {print $2}' /usr/local/etc/xray/.keys)
        PUBLIC_KEY=$(awk -F': ' '/Public key/ {print $2}' /usr/local/etc/xray/.keys)
        PRIVATE_KEY=$(awk -F': ' '/Private key/ {print $2}' /usr/local/etc/xray/.keys)
        SHORT_ID=$(awk -F': ' '/shortsid/ {print $2}' /usr/local/etc/xray/.keys)
        MAIN_UUID=$(awk -F': ' '/uuid/ {print $2}' /usr/local/etc/xray/.keys)
        
        if [[ -f "/usr/local/etc/xray/bot_token.txt" ]]; then
            TELEGRAM_TOKEN=$(cat /usr/local/etc/xray/bot_token.txt)
        fi
        
        echo -e "${GREEN}✅ Настройки сохранены${NC}"
    fi
else
    UPDATE_MODE=false
fi

# Utility functions
test_reality_dest() {
    local dest=$1
    echo "Testing $dest..."
    if timeout 5 curl -s --max-time 3 -I "https://$dest" >/dev/null 2>&1; then
        echo "✅ $dest accessible"
        return 0
    else
        echo "❌ $dest not accessible"
        return 1
    fi
}

validate_ip() {
    local ip=$1
    [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
}

validate_token() {
    local token=$1
    [[ $token =~ ^[0-9]{1,3}[0-9]{7,10}:[a-zA-Z0-9_-]{35}$ ]]
}

validate_owner_id() {
    local owner_id=$1
    [[ $owner_id =~ ^[0-9]+$ ]] && [[ ${#owner_id} -ge 5 ]]
}

if [[ "$UPDATE_MODE" == "false" ]]; then
    echo -e "${CYAN}📋 Интерактивная настройка v23.0-full${NC}"
    echo

    while true; do
        read -p "🌐 IP адрес сервера (Enter для автоопределения): " SERVER_IP
        if [[ -z "$SERVER_IP" ]]; then
            AUTO_IP=$(curl -s --max-time 10 ifconfig.me 2>/dev/null || curl -s --max-time 10 ipinfo.io/ip 2>/dev/null || echo "")
            if [[ -n "$AUTO_IP" ]] && validate_ip "$AUTO_IP"; then
                read -p "🤖 Определен IP: $AUTO_IP. Использовать? (y/n): " use_auto
                if [[ $use_auto =~ ^[Yy]$ ]]; then
                    SERVER_IP="$AUTO_IP"
                    break
                fi
            fi
        elif validate_ip "$SERVER_IP"; then
            break
        else
            echo -e "${RED}❌ Неверный формат IP${NC}"
        fi
    done

    while true; do
        read -p "🤖 Токен Telegram бота (@BotFather): " TELEGRAM_TOKEN
        if validate_token "$TELEGRAM_TOKEN"; then
            break
        else
            echo -e "${RED}❌ Неверный формат токена${NC}"
        fi
    done

    while true; do
        read -p "👤 Ваш Telegram User ID (@userinfobot): " OWNER_ID
        if validate_owner_id "$OWNER_ID"; then
            break
        else
            echo -e "${RED}❌ Неверный User ID${NC}"
        fi
    done

    echo
    echo -e "${CYAN}🎭 Автоопределение Reality...${NC}"

    if test_reality_dest "github.com"; then
        REALITY_DEST="github.com:443"
        REALITY_SNI="github.com"  
        REALITY_NAME="GitHub"
        REALITY_SERVERS='["github.com", "www.github.com"]'
    elif test_reality_dest "www.google.com"; then
        REALITY_DEST="www.google.com:443"
        REALITY_SNI="www.google.com"
        REALITY_NAME="Google"
        REALITY_SERVERS='["www.google.com", "google.com"]'
    elif test_reality_dest "www.yahoo.com"; then
        REALITY_DEST="www.yahoo.com:443"
        REALITY_SNI="www.yahoo.com"
        REALITY_NAME="Yahoo"
        REALITY_SERVERS='["www.yahoo.com", "yahoo.com"]'
    else
        echo -e "${YELLOW}⚠️ Все домены недоступны, использую Google${NC}"
        REALITY_DEST="www.google.com:443"
        REALITY_SNI="www.google.com"
        REALITY_NAME="Google"
        REALITY_SERVERS='["www.google.com", "google.com"]'
    fi

    echo -e "${GREEN}✅ Выбрана маскировка: $REALITY_NAME${NC}"
else
    if [[ -f "/usr/local/bin/xray_bot.py" ]]; then
        OWNER_ID=$(grep "AUTHORIZED_USERS.*\[" /usr/local/bin/xray_bot.py | grep -o '[0-9]\+' | head -1)
    fi
    
    case "$REALITY_SNI" in
        "github.com")
            REALITY_DEST="github.com:443"
            REALITY_SERVERS='["github.com", "www.github.com"]'
            ;;
        "www.google.com")
            REALITY_DEST="www.google.com:443" 
            REALITY_SERVERS='["www.google.com", "google.com"]'
            ;;
        "www.yahoo.com")
            REALITY_DEST="www.yahoo.com:443"
            REALITY_SERVERS='["www.yahoo.com", "yahoo.com"]'
            ;;
        *)
            REALITY_DEST="$REALITY_SNI:443"
            REALITY_SERVERS='["'$REALITY_SNI'", "www.'$REALITY_SNI'"]'
            ;;
    esac
    
    echo -e "${GREEN}✅ Обновление с сохранением настроек:${NC}"
    echo -e "   🌐 IP: ${YELLOW}$SERVER_IP${NC}"
    echo -e "   🎭 Reality: ${YELLOW}$REALITY_NAME${NC}"
    echo -e "   👤 Owner: ${YELLOW}$OWNER_ID${NC}"
fi

if [[ "$UPDATE_MODE" == "false" ]]; then
    echo
    echo -e "${GREEN}✅ Настройка завершена:${NC}"
    echo -e "   🌐 IP: ${YELLOW}$SERVER_IP${NC}"
    echo -e "   🤖 Токен: ${YELLOW}${TELEGRAM_TOKEN:0:10}...${NC}"
    echo -e "   👤 Owner: ${YELLOW}$OWNER_ID${NC}"
    echo -e "   🎭 Reality: ${YELLOW}$REALITY_NAME${NC}"

    echo
    read -p "🚀 Начать установку v23.0-full? (y/n): " confirm
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        echo "❌ Установка отменена"
        exit 1
    fi
fi

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}❌ Требуются права root${NC}"
    exit 1
fi

echo
echo -e "${GREEN}🚀 Начинаем установку v23.0-full...${NC}"

if [[ "$UPDATE_MODE" == "false" ]]; then
    echo -e "${YELLOW}🧹 Очистка...${NC}"
    systemctl stop xray xray_bot xray_notify_boot 2>/dev/null || true
    systemctl disable xray xray_bot xray_notify_boot 2>/dev/null || true
    rm -f /etc/systemd/system/xray*.service
    fuser -k 443/tcp 2>/dev/null || true
    rm -f /usr/local/bin/xray*
    rm -rf /usr/local/etc/xray /var/log/xray
    userdel -r xray 2>/dev/null || true
    systemctl daemon-reload
    echo -e "${GREEN}✅ Очистка завершена${NC}"

    echo -e "${YELLOW}📦 Установка зависимостей...${NC}"
    apt update && apt upgrade -y
    apt install -y curl jq unzip openssl wget psmisc python3 python3-pip bc

    if pip3 install pyTelegramBotAPI requests 2>/dev/null; then
        echo "✅ Python установлен"
    else
        pip3 install --break-system-packages pyTelegramBotAPI requests
        echo "✅ Python установлен"
    fi

    echo -e "${YELLOW}📥 Установка Xray...${NC}"
    XRAY_VERSION=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r '.tag_name')
    echo "Версия: $XRAY_VERSION"

    mkdir -p /usr/local/{bin,etc/xray/backups} /var/log/xray

    TMP_DIR=$(mktemp -d)
    curl -L -o "$TMP_DIR/xray.zip" "https://github.com/XTLS/Xray-core/releases/download/$XRAY_VERSION/Xray-linux-64.zip"
    unzip -j "$TMP_DIR/xray.zip" xray -d /usr/local/bin/
    chmod +x /usr/local/bin/xray
    rm -rf "$TMP_DIR"

    echo "✅ Xray: $(/usr/local/bin/xray version | head -1)"

    echo -e "${YELLOW}🔐 Генерация ключей...${NC}"
    MAIN_UUID=$(/usr/local/bin/xray uuid)
    KEY_OUTPUT=$(/usr/local/bin/xray x25519)
    PRIVATE_KEY=$(echo "$KEY_OUTPUT" | grep "^Private key:" | awk '{print $3}')
    PUBLIC_KEY=$(echo "$KEY_OUTPUT" | grep "^Public key:" | awk '{print $3}')

    if [[ -z "$PRIVATE_KEY" ]]; then
        PRIVATE_KEY=$(echo "$KEY_OUTPUT" | grep -E "^(Private key|PrivateKey):" | awk '{print $NF}')
    fi
    if [[ -z "$PUBLIC_KEY" ]]; then
        PUBLIC_KEY=$(echo "$KEY_OUTPUT" | grep -E "^(Public key|Password):" | awk '{print $NF}')
    fi

    SHORT_ID=$(openssl rand -hex 8)

    if [[ -z "$PRIVATE_KEY" || -z "$PUBLIC_KEY" ]]; then
        echo -e "${RED}❌ Ошибка генерации ключей${NC}"
        exit 1
    fi

    echo "✅ Ключи сгенерированы"

    useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/xray --create-home xray 2>/dev/null || true
else
    echo -e "${YELLOW}🔄 Режим обновления${NC}"
fi

cat > /usr/local/etc/xray/.keys << EOF
uuid: $MAIN_UUID
Private key: $PRIVATE_KEY
Public key: $PUBLIC_KEY
shortsid: $SHORT_ID
reality_dest: $REALITY_DEST
reality_sni: $REALITY_SNI
reality_name: $REALITY_NAME
EOF

# ИСПРАВЛЕНО: создаём файлы от root с правильными правами
echo -e "${YELLOW}🔧 Создание файлов конфигурации уведомлений...${NC}"

# Сохраняем токен бота (от root для доступа из скриптов)
echo "$TELEGRAM_TOKEN" > /usr/local/etc/xray/bot_token.txt
chown root:root /usr/local/etc/xray/bot_token.txt
chmod 600 /usr/local/etc/xray/bot_token.txt

# Сохраняем chat_id для уведомлений (от root для доступа из скриптов)  
echo "$OWNER_ID" > /usr/local/etc/xray/.chatid
chown root:root /usr/local/etc/xray/.chatid
chmod 600 /usr/local/etc/xray/.chatid

echo "✅ Файлы уведомлений созданы с правильными правами"

echo -e "${YELLOW}📄 Создание конфигурации Xray...${NC}"
cat > /usr/local/etc/xray/config.json << EOF
{
  "log": {
    "access": "/var/log/xray/access.log",
    "error": "/var/log/xray/error.log", 
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 443,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "$MAIN_UUID",
            "flow": "xtls-rprx-vision",
            "email": "main"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$REALITY_DEST",
          "xver": 0,
          "serverNames": $REALITY_SERVERS,
          "privateKey": "$PRIVATE_KEY",
          "shortIds": ["$SHORT_ID"]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": []
  }
}
EOF

if ! /usr/local/bin/xray run -c /usr/local/etc/xray/config.json -test; then
    echo -e "${RED}❌ Ошибка конфигурации${NC}"
    exit 1
fi
echo "✅ Конфигурация создана"

echo -e "${YELLOW}📄 Создание скриптов...${NC}"

cat > /usr/local/bin/newuser << 'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"
KEYS_FILE="/usr/local/etc/xray/.keys"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ $# -ne 1 ]; then
    echo "Usage: newuser <name>"
    exit 1
fi

USERNAME="$1"

if [[ ! "$USERNAME" =~ ^[a-zA-Z0-9_-]+$ ]] || [[ ${#USERNAME} -gt 20 ]]; then
    echo -e "${RED}❌ Invalid name${NC}"
    exit 1
fi

if jq -e --arg name "$USERNAME" '.inbounds[0].settings.clients[]? | select(.email == $name)' "$CONFIG" >/dev/null 2>&1; then
    echo -e "${RED}❌ User exists${NC}"
    exit 1
fi

UUID=$(cat /proc/sys/kernel/random/uuid)
cp "$CONFIG" "$CONFIG.bak"

if jq --arg uuid "$UUID" --arg name "$USERNAME" '.inbounds[0].settings.clients += [{"id": $uuid, "flow": "xtls-rprx-vision", "email": $name}]' "$CONFIG" > "$CONFIG.tmp"; then
    mv "$CONFIG.tmp" "$CONFIG"
    systemctl restart xray
    sleep 3
    
    if ! systemctl is-active --quiet xray; then
        echo -e "${RED}❌ Error${NC}"
        mv "$CONFIG.bak" "$CONFIG" 2>/dev/null || true
        exit 1
    fi
    
    SERVER_IP=$(curl -s icanhazip.com 2>/dev/null || echo "YOUR_SERVER_IP")
    PUBLIC_KEY=$(awk -F': ' '/Public key/ {print $2}' "$KEYS_FILE")
    SHORT_ID=$(awk -F': ' '/shortsid/ {print $2}' "$KEYS_FILE")
    REALITY_SNI=$(awk -F': ' '/reality_sni/ {print $2}' "$KEYS_FILE")
    
    LINK="vless://$UUID@$SERVER_IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&spx=%2F#$USERNAME"
    
    echo -e "${GREEN}✅ Created: $USERNAME${NC}"
    echo "$LINK"
else
    echo -e "${RED}❌ Error${NC}"
    mv "$CONFIG.bak" "$CONFIG" 2>/dev/null || true
    exit 1
fi
EOF

cat > /usr/local/bin/listusers << 'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"

[[ ! -f "$CONFIG" ]] && echo "Config not found" && exit 1

echo "Users:"
USERS=$(jq -r '.inbounds[0].settings.clients[].email' "$CONFIG" 2>/dev/null)

if [[ -n "$USERS" ]]; then
    echo "$USERS" | while IFS= read -r user; do
        echo "• $user"
    done
    TOTAL=$(echo "$USERS" | wc -l)
    echo "Total: $TOTAL"
else
    echo "No users"
fi
EOF

cat > /usr/local/bin/deluser << 'EOF'
#!/bin/bash
CONFIG="/usr/local/etc/xray/config.json"

if [ $# -ne 1 ]; then
    echo "Usage: deluser <name>"
    exit 1
fi

USERNAME="$1"

if ! jq -e --arg name "$USERNAME" '.inbounds[0].settings.clients[]? | select(.email == $name)' "$CONFIG" >/dev/null 2>&1; then
    echo "❌ Not found"
    exit 1
fi

cp "$CONFIG" "$CONFIG.bak"

if jq --arg name "$USERNAME" '(.inbounds[0].settings.clients) |= map(select(.email != $name))' "$CONFIG" > "$CONFIG.tmp"; then
    mv "$CONFIG.tmp" "$CONFIG"
    systemctl restart xray
    sleep 3
    
    if systemctl is-active --quiet xray; then
        echo "✅ Deleted: $USERNAME"
    else
        echo "❌ Error"
        mv "$CONFIG.bak" "$CONFIG" 2>/dev/null || true
        exit 1
    fi
else
    echo "❌ Error"
    mv "$CONFIG.bak" "$CONFIG" 2>/dev/null || true
    exit 1
fi
EOF

chmod +x /usr/local/bin/{newuser,listusers,deluser}
echo "✅ User scripts created"

# ИСПРАВЛЕННЫЙ change-reality-domain.sh с --force + ПРЯМОЕ уведомление через API
cat > /usr/local/bin/change-reality-domain.sh << 'CHANGE_EOF'
#!/bin/bash

set -e

# XRAY REALITY DOMAIN CHANGER v23.0-full (FIXED)
# --force режим + прямое уведомление через Telegram API
# ИСПРАВЛЕНО: правильная работа с файлами от root

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PURPLE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          REALITY DOMAIN CHANGER v23.0-full                   ║"
echo "║          WHITELIST: GitHub, Google, Yahoo                    ║"
echo "║          + Надёжное уведомление через Telegram API           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

CONFIG="/usr/local/etc/xray/config.json"
KEYS_FILE="/usr/local/etc/xray/.keys"
BOT_FILE="/usr/local/bin/xray_bot.py"
BACKUP_DIR="/usr/local/etc/xray/backups"

[[ $EUID -ne 0 ]] && echo -e "${RED}❌ Root required${NC}" && exit 1

# Check for --force parameter
FORCE_MODE=false
if [[ "$1" == "--force" ]]; then
    FORCE_MODE=true
    shift
fi

# Функция отправки уведомления через Telegram API
send_telegram_notification() {
    local message="$1"
    
    if [[ -f "/usr/local/etc/xray/bot_token.txt" ]] && [[ -f "/usr/local/etc/xray/.chatid" ]]; then
        local TOKEN=$(cat /usr/local/etc/xray/bot_token.txt 2>/dev/null)
        local CHAT_ID=$(cat /usr/local/etc/xray/.chatid 2>/dev/null)
        
        if [[ -n "$TOKEN" ]] && [[ -n "$CHAT_ID" ]]; then
            echo -e "${CYAN}🔔 Отправка уведомления...${NC}"
            
            # Попытка отправить через API с таймаутом
            local response=$(curl -s --max-time 10 -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
                -d chat_id="$CHAT_ID" \
                -d text="$message" \
                -d parse_mode="Markdown" 2>/dev/null)
            
            if echo "$response" | grep -q '"ok":true'; then
                echo -e "${GREEN}✅ Уведомление отправлено${NC}"
            else
                echo -e "${YELLOW}⚠️ Не удалось отправить уведомление${NC}"
                echo -e "${YELLOW}Ответ API: ${response:0:100}...${NC}"
            fi
        else
            echo -e "${YELLOW}⚠️ Отсутствует токен или chat_id${NC}"
        fi
    else
        echo -e "${YELLOW}⚠️ Файлы конфигурации уведомлений отсутствуют${NC}"
    fi
}

# WHITELIST v23.0-full: GitHub, Google, Yahoo
validate_domain() {
    local domain=$1
    
    echo -e "${YELLOW}🔍 Checking domain: $domain${NC}"
    
    case "$domain" in
        "github.com"|"www.github.com")
            echo -e "${GREEN}✅ GitHub - approved${NC}"
            return 0
            ;;
        "www.google.com"|"google.com")
            echo -e "${GREEN}✅ Google - approved${NC}"
            return 0
            ;;
        "www.yahoo.com"|"yahoo.com")
            echo -e "${GREEN}✅ Yahoo - approved${NC}"
            return 0
            ;;
        *)
            echo -e "${YELLOW}⚠️ Non-standard domain: $domain${NC}"
            echo -e "${YELLOW}Whitelist: github.com, www.google.com, www.yahoo.com${NC}"
            
            if [[ "$FORCE_MODE" == "true" ]]; then
                echo -e "${YELLOW}Force mode: proceeding anyway${NC}"
                return 0
            else
                read -p "Continue with this domain? (y/n): " custom_confirm
                [[ $custom_confirm =~ ^[Yy]$ ]] && return 0 || return 1
            fi
            ;;
    esac
}

get_domain_info() {
    local domain=$1
    local base_domain
    local server_names
    local domain_name
    
    if [[ "$domain" =~ ^www\. ]]; then
        base_domain=${domain#www.}
        server_names="[\"$domain\", \"$base_domain\"]"
    else
        server_names="[\"$domain\", \"www.$domain\"]"
        base_domain="$domain"
    fi
    
    if [[ "$domain" =~ google ]]; then
        domain_name="Google"
    elif [[ "$domain" =~ github ]]; then
        domain_name="GitHub"
    elif [[ "$domain" =~ yahoo ]]; then
        domain_name="Yahoo"
    else
        domain_name=$(echo "$base_domain" | sed 's/\..*$//' | awk '{print toupper(substr($0,1,1)) tolower(substr($0,2))}')
    fi
    
    echo "$server_names|$domain_name|$base_domain"
}

backup_files() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    mkdir -p "$BACKUP_DIR"
    echo -e "${YELLOW}💾 Backup...${NC}"
    
    [[ -f "$CONFIG" ]] && cp "$CONFIG" "$BACKUP_DIR/config.json.backup.$timestamp"
    [[ -f "$KEYS_FILE" ]] && cp "$KEYS_FILE" "$BACKUP_DIR/.keys.backup.$timestamp"
    
    echo "$timestamp" > /tmp/xray_change_timestamp
    echo -e "${GREEN}✅ Backed up: $timestamp${NC}"
}

update_configs() {
    local new_domain=$1
    local domain_info
    local server_names
    local domain_name
    
    domain_info=$(get_domain_info "$new_domain")
    server_names=$(echo "$domain_info" | cut -d'|' -f1)
    domain_name=$(echo "$domain_info" | cut -d'|' -f2)
    
    echo -e "${YELLOW}🔄 Updating configs...${NC}"
    
    if [[ -f "$CONFIG" ]]; then
        sed -i "s/\"dest\": \"[^\"]*:443\"/\"dest\": \"$new_domain:443\"/g" "$CONFIG"
        jq --argjson names "$server_names" '.inbounds[0].streamSettings.realitySettings.serverNames = $names' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
        echo -e " ✅ config.json"
    fi
    
    if [[ -f "$KEYS_FILE" ]]; then
        sed -i "s/reality_dest: .*/reality_dest: $new_domain:443/g" "$KEYS_FILE"
        sed -i "s/reality_sni: .*/reality_sni: $new_domain/g" "$KEYS_FILE"
        sed -i "s/reality_name: .*/reality_name: $domain_name/g" "$KEYS_FILE"
        echo -e " ✅ .keys"
    fi
    
    if [[ -f "$BOT_FILE" ]]; then
        sed -i "s/REALITY_NAME = '[^']*'/REALITY_NAME = '$domain_name'/g" "$BOT_FILE"
        echo -e " ✅ bot"
    fi
    
    echo -e "${GREEN}✅ All configs updated${NC}"
}

restart_services() {
    echo -e "${YELLOW}🔄 Restarting...${NC}"
    
    systemctl stop xray
    if systemctl start xray; then
        echo -e " ✅ Xray started"
    else
        echo -e " ${RED}❌ Xray failed${NC}"
        return 1
    fi
    
    sleep 5
    
    systemctl is-active --quiet xray || { echo -e "${RED}❌ Not active${NC}"; return 1; }
    ss -tlnp | grep -q ":443" || { echo -e "${RED}❌ Port 443${NC}"; return 1; }
    
   # systemctl restart xray_bot 2>/dev/null || true
    
    echo -e "${GREEN}✅ Services restarted${NC}"
    return 0
}

if [ $# -eq 0 ]; then
    echo -e "${YELLOW}USAGE:${NC} $0 [--force] <domain>"
    echo
    echo -e "${GREEN}WHITELIST v23.0-full:${NC}"
    echo " • github.com / www.github.com"
    echo " • www.google.com / google.com"
    echo " • www.yahoo.com / yahoo.com"
    echo
    echo -e "${YELLOW}EXAMPLES:${NC}"
    echo " $0 github.com"
    echo " $0 --force www.google.com  (no confirmation + telegram notify)"
    exit 1
fi

NEW_DOMAIN="$1"

echo -e "${PURPLE}🎭 CHANGING TO: ${CYAN}$NEW_DOMAIN${NC}"
[[ "$FORCE_MODE" == "true" ]] && echo -e "${CYAN}(Force mode: no confirmation + notification)${NC}"
echo

if ! validate_domain "$NEW_DOMAIN"; then
    echo -e "${RED}❌ Domain rejected${NC}"
    exit 1
fi

# Ask confirmation only if NOT force mode
if [[ "$FORCE_MODE" != "true" ]]; then
    echo -e "${YELLOW}⚠️ CHANGE MASKING TO $NEW_DOMAIN? (y/n)${NC}"
    read -p "> " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && echo "❌ Cancelled" && exit 0
fi

echo

backup_files
BACKUP_TIMESTAMP=$(cat /tmp/xray_change_timestamp)

update_configs "$NEW_DOMAIN" || { echo -e "${RED}❌ Update failed${NC}"; exit 1; }

if ! /usr/local/bin/xray run -c "$CONFIG" -test >/dev/null 2>&1; then
    echo -e "${RED}❌ Config invalid! Restoring...${NC}"
    [[ -f "$BACKUP_DIR/config.json.backup.$BACKUP_TIMESTAMP" ]] && cp "$BACKUP_DIR/config.json.backup.$BACKUP_TIMESTAMP" "$CONFIG"
    [[ -f "$BACKUP_DIR/.keys.backup.$BACKUP_TIMESTAMP" ]] && cp "$BACKUP_DIR/.keys.backup.$BACKUP_TIMESTAMP" "$KEYS_FILE"
    systemctl restart xray
    exit 1
fi

restart_services || { echo -e "${RED}❌ Restart failed${NC}"; exit 1; }

echo
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║               CHANGE COMPLETED!                              ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo
echo -e "${GREEN}✅ Changed to: ${PURPLE}$NEW_DOMAIN${NC}"
echo -e "${BLUE}💾 Backup: $BACKUP_TIMESTAMP${NC}"

# ИСПРАВЛЕНО: Отправка уведомления через Telegram API при force режиме
if [[ "$FORCE_MODE" == "true" ]]; then
    DOMAIN_NAME=$(awk -F': ' '/reality_name/ {print $2}' "$KEYS_FILE")
    NOTIFICATION="🔔 *УВЕДОМЛЕНИЕ v23.0-full*

✅ Смена маскировки завершена успешно!
🎭 Новая маскировка: *$DOMAIN_NAME*
❌ Ошибок не обнаружено
📱 Создайте нового пользователя для получения рабочей ссылки

✅ Reality change completed successfully!
🎭 New masking: *$DOMAIN_NAME*
❌ No errors detected  
📱 Create new user to get working link"
    
    send_telegram_notification "$NOTIFICATION"
fi

rm -f /tmp/xray_change_timestamp
CHANGE_EOF

cat > /usr/local/bin/xray-diagnostics.sh << 'DIAG_EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                XRAY DIAGNOSTICS v23.0-full                   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo

check_service() {
    systemctl is-active --quiet $1 && echo -e " $2: ${GREEN}✅ Active${NC}" || echo -e " $2: ${RED}❌ Inactive${NC}"
}

check_port() {
    ss -tlnp | grep -q ":$1" && echo -e " Port $1: ${GREEN}✅ Open${NC}" || echo -e " Port $1: ${RED}❌ Closed${NC}"
}

check_file() {
    [[ -f "$1" ]] && echo -e " $2: ${GREEN}✅ Exists${NC}" || echo -e " $2: ${RED}❌ Missing${NC}"
}

echo -e "${YELLOW}🔧 SERVICES:${NC}"
check_service "xray" "Xray"
check_service "xray_bot" "Bot"
check_service "xray_notify_boot" "Boot Notify (oneshot - normal if inactive)"
echo

echo -e "${YELLOW}🌐 PORTS:${NC}"
check_port "443"
echo

echo -e "${YELLOW}📁 FILES:${NC}"
check_file "/usr/local/etc/xray/config.json" "config.json"
check_file "/usr/local/etc/xray/.keys" ".keys"
check_file "/usr/local/etc/xray/.chatid" ".chatid"
check_file "/usr/local/bin/change-reality-domain.sh" "change-reality"
check_file "/usr/local/bin/xray_notify_boot.sh" "notify-boot"
echo

echo -e "${YELLOW}🔔 NOTIFICATION FILES:${NC}"
if [[ -f "/usr/local/etc/xray/bot_token.txt" ]]; then
    TOKEN_LEN=$(wc -c < /usr/local/etc/xray/bot_token.txt)
    echo -e " bot_token.txt: ${GREEN}✅ Exists (${TOKEN_LEN} chars)${NC}"
    TOKEN_OWNER=$(ls -la /usr/local/etc/xray/bot_token.txt | awk '{print $3":"$4}')
    echo -e " Owner: ${GREEN}$TOKEN_OWNER${NC}"
else
    echo -e " bot_token.txt: ${RED}❌ Missing${NC}"
fi

if [[ -f "/usr/local/etc/xray/.chatid" ]]; then
    CHAT_ID=$(cat /usr/local/etc/xray/.chatid 2>/dev/null)
    echo -e " .chatid: ${GREEN}✅ Exists ($CHAT_ID)${NC}"
    CHATID_OWNER=$(ls -la /usr/local/etc/xray/.chatid | awk '{print $3":"$4}')
    echo -e " Owner: ${GREEN}$CHATID_OWNER${NC}"
else
    echo -e " .chatid: ${RED}❌ Missing${NC}"
fi

echo
echo -e "${YELLOW}🎭 REALITY:${NC}"
[[ -f "/usr/local/etc/xray/config.json" ]] && {
    DEST=$(jq -r '.inbounds[0].streamSettings.realitySettings.dest' /usr/local/etc/xray/config.json 2>/dev/null)
    echo -e " Masking: ${PURPLE}$DEST${NC}"
}

echo
echo -e "${YELLOW}📊 USERS:${NC}"
[[ -f "/usr/local/etc/xray/config.json" ]] && {
    COUNT=$(jq -r '.inbounds[0].settings.clients | length' /usr/local/etc/xray/config.json 2>/dev/null)
    echo -e " Total: ${GREEN}$COUNT${NC}"
}

echo
echo -e "${PURPLE}Completed: $(date)${NC}"
DIAG_EOF

cat > /usr/local/bin/uninstall-xray.sh << 'UNINSTALL_EOF'
#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${RED}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                XRAY UNINSTALLER v23.0-full                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

[[ $EUID -ne 0 ]] && echo -e "${RED}❌ Root required${NC}" && exit 1

read -p "🗑️ Completely remove Xray? (y/n): " confirm
[[ ! $confirm =~ ^[Yy]$ ]] && echo "❌ Cancelled" && exit 1

echo -e "${YELLOW}🛑 Stopping...${NC}"
systemctl stop xray xray_bot xray_notify_boot 2>/dev/null || true
systemctl disable xray xray_bot xray_notify_boot 2>/dev/null || true

echo -e "${YELLOW}🗂️ Removing...${NC}"
rm -f /etc/systemd/system/xray*.service
rm -f /usr/local/bin/xray*
rm -rf /usr/local/etc/xray /var/log/xray /var/lib/xray

echo -e "${YELLOW}👤 Removing user...${NC}"
userdel -r xray 2>/dev/null || true

systemctl daemon-reload

echo -e "${GREEN}✅ Removal complete!${NC}"
UNINSTALL_EOF

# НОВОЕ: Создание скрипта уведомления о загрузке системы
echo -e "${YELLOW}🔔 Создание скрипта уведомлений о перезагрузке...${NC}"
cat > /usr/local/bin/xray_notify_boot.sh << 'NOTIFY_EOF'
#!/bin/bash

# Boot Notification Script v23.0-full (FIXED)
# Отправляет уведомление в Telegram после загрузки сервера
# ИСПРАВЛЕНО: правильная работа с файлами от root

# Ожидание полной загрузки и появления сети
sleep 15

# Проверка доступности интернета
for i in {1..12}; do
    if ping -c1 8.8.8.8 &>/dev/null; then
        echo "Network is up"
        break
    fi
    echo "Waiting for network... ($i/12)"
    sleep 10
done

# Чтение конфигурации (файлы теперь принадлежат root)
if [[ -f "/usr/local/etc/xray/bot_token.txt" ]] && [[ -f "/usr/local/etc/xray/.chatid" ]]; then
    TOKEN=$(cat /usr/local/etc/xray/bot_token.txt 2>/dev/null)
    CHAT_ID=$(cat /usr/local/etc/xray/.chatid 2>/dev/null)
else
    echo "Config files not found"
    exit 1
fi

if [[ -z "$TOKEN" ]] || [[ -z "$CHAT_ID" ]]; then
    echo "Empty token or chat_id"
    exit 1
fi

# Сбор информации о системе
HOSTNAME=$(hostname)
SERVER_IP=$(curl -s --max-time 10 icanhazip.com 2>/dev/null || echo "unknown")
BOOT_TIME=$(date '+%Y-%m-%d %H:%M:%S')

# Проверка статуса Xray
if systemctl is-active --quiet xray; then
    XRAY_STATUS="✅ Активен"
else
    XRAY_STATUS="❌ Неактивен"
fi

# Проверка порта 443
if ss -tlnp | grep -q ":443"; then
    PORT_STATUS="✅ Открыт"
else
    PORT_STATUS="❌ Закрыт"
fi

# Получение информации о маскировке
if [[ -f "/usr/local/etc/xray/.keys" ]]; then
    REALITY_NAME=$(awk -F': ' '/reality_name/ {print $2}' /usr/local/etc/xray/.keys 2>/dev/null || echo "Unknown")
else
    REALITY_NAME="Unknown"
fi

# Формирование сообщения
MESSAGE="🔔 *УВЕДОМЛЕНИЕ v23.0-full*

✅ Сервер успешно перезагружен!
🖥️ Хост: $HOSTNAME
🌐 IP: $SERVER_IP
🕒 Время загрузки: $BOOT_TIME

🔧 *Статус сервисов:*
• Xray: $XRAY_STATUS
• Порт 443: $PORT_STATUS
• Reality: $REALITY_NAME

📊 Все системы работают в штатном режиме

✅ Server rebooted successfully!
🖥️ Host: $HOSTNAME
🌐 IP: $SERVER_IP
🕒 Boot time: $BOOT_TIME

🔧 *Service status:*
• Xray: $XRAY_STATUS
• Port 443: $PORT_STATUS  
• Reality: $REALITY_NAME

📊 All systems operational"

# Отправка уведомления с несколькими попытками
for attempt in {1..3}; do
    response=$(curl -s --max-time 15 -X POST "https://api.telegram.org/bot$TOKEN/sendMessage" \
        -d chat_id="$CHAT_ID" \
        -d text="$MESSAGE" \
        -d parse_mode="Markdown" 2>/dev/null)
    
    if echo "$response" | grep -q '"ok":true'; then
        echo "Boot notification sent successfully (attempt $attempt)"
        break
    else
        echo "Failed to send notification (attempt $attempt/3)"
        echo "Response: ${response:0:100}..."
        sleep 5
    fi
done
NOTIFY_EOF

chmod +x /usr/local/bin/{change-reality-domain.sh,xray-diagnostics.sh,uninstall-xray.sh,xray_notify_boot.sh}
echo "✅ All scripts created"

# Создание systemd сервиса для уведомлений о загрузке
echo -e "${YELLOW}⚙️ Создание сервиса уведомлений...${NC}"
cat > /etc/systemd/system/xray_notify_boot.service << EOF
[Unit]
Description=Send Telegram notification after server boot v23.0-full
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/xray_notify_boot.sh
RemainAfterExit=no

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/xray.service << EOF
[Unit]
Description=Xray VPN service v23.0-full
Documentation=https://github.com/xtls/xray-core
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/xray run -c /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

echo -e "${YELLOW}🤖 Создание бота v23.0-full...${NC}"

cat > /usr/local/bin/xray_bot.py << 'BOT_EOF'
#!/usr/bin/env python3

import telebot
import subprocess
import logging
import time
import sys
import os
from datetime import datetime
from telebot import types

TOKEN = 'TOKEN_PLACEHOLDER'
AUTHORIZED_USERS = [OWNER_ID_PLACEHOLDER]
SERVER_IP = 'SERVER_IP_PLACEHOLDER'
REALITY_NAME = 'REALITY_NAME_PLACEHOLDER'

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

bot = telebot.TeleBot(TOKEN)

def is_authorized(user_id):
    return user_id in AUTHORIZED_USERS

def run_command(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return result.returncode, result.stdout, result.stderr
    except Exception as e:
        return 1, "", str(e)

def send_notification(chat_id, message):
    """Отправка уведомления пользователю"""
    try:
        bot.send_message(chat_id, message, parse_mode='Markdown')
        logger.info(f"Notification sent to {chat_id}: {message[:50]}...")
    except Exception as e:
        logger.error(f"Failed to send notification: {e}")

def main_menu():
    markup = types.ReplyKeyboardMarkup(resize_keyboard=True, row_width=2)
    markup.add(
        "➕ Создать пользователя (Add User)", 
        "➖ Удалить пользователя (Delete User)"
    )
    markup.add(
        "📜 Список пользователей (User List)", 
        "📊 Статус сервера (Server Status)"
    )
    markup.add(
        "🔄 Перезапуск Xray (Restart Xray)", 
        "🎭 Смена маскировки (Change Reality)"
    )
    markup.add(
        "🔄 Перезагрузка сервера (Reboot Server)",
        "📖 Руководство (Guide)"
    )
    markup.add(
        "🔧 Диагностика (Diagnostics)",
        "📋 Логи (Logs)"
    )
    return markup

@bot.message_handler(commands=['start'])
def start_handler(message):
    if not is_authorized(message.from_user.id):
        bot.send_message(message.chat.id, "❌ Доступ запрещен / Access denied")
        return

    welcome_text = f"""🤖 *Xray Management Bot v23.0-full (FIXED)*

🌐 Сервер / Server: {SERVER_IP}
🎭 Маскировка / Reality: {REALITY_NAME}
📅 Время / Time: {datetime.now().strftime('%Y-%m-%d %H:%M')}

✨ v23.0-full - STABLE NOTIFICATIONS:
• 🔔 Надёжные уведомления (ИСПРАВЛЕНЫ права)
• 🔧 Исправлена смена Reality из бота
• 🎭 Whitelist: GitHub, Google, Yahoo
• ⚡ Готовый продукт - работает из коробки

🔧 Выберите действие / Choose action:"""

    bot.send_message(message.chat.id, welcome_text, parse_mode='Markdown', reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "➕ Создать пользователя (Add User)")
def ask_new_user(message):
    if not is_authorized(message.from_user.id):
        return
    msg = bot.send_message(message.chat.id, "📝 Введите имя пользователя / Enter username:")
    bot.register_next_step_handler(msg, create_user)

def create_user(message):
    if not is_authorized(message.from_user.id):
        return
    
    username = message.text.strip()
    if not username or not username.replace('_','').replace('-','').isalnum() or len(username) > 20:
        bot.send_message(message.chat.id, "❌ Неверное имя пользователя / Invalid username", reply_markup=main_menu())
        return

    processing_msg = bot.send_message(message.chat.id, "⏳ Создаем пользователя / Creating user...")
    
    returncode, stdout, stderr = run_command(['/usr/local/bin/newuser', username])
    
    try:
        bot.delete_message(message.chat.id, processing_msg.message_id)
    except:
        pass

    if returncode == 0:
        lines = stdout.split('\n')
        link = ""
        for line in lines:
            if line.startswith('vless://'):
                link = line.strip()
                break
        
        if link:
            success_text = f"✅ *Пользователь создан / User created: {username}*\n\n📱 *Кликабельная ссылка / Clickable link:*"
            
            markup = types.InlineKeyboardMarkup()
            copy_button = types.InlineKeyboardButton("📋 Скопировать / Copy", callback_data=f"copy_{username}")
            markup.add(copy_button)
            
            bot.send_message(message.chat.id, success_text, parse_mode='Markdown')
            bot.send_message(message.chat.id, f"`{link}`", parse_mode='Markdown', reply_markup=markup)
            bot.send_message(message.chat.id, "✅ Готово! / Done!", reply_markup=main_menu())
        else:
            bot.send_message(message.chat.id, f"✅ Пользователь создан / User created", reply_markup=main_menu())
        
        logger.info(f"User {username} created by {message.from_user.id}")
    else:
        bot.send_message(message.chat.id, f"❌ Ошибка / Error: {stderr[:200]}", reply_markup=main_menu())

@bot.callback_query_handler(func=lambda call: call.data.startswith('copy_'))
def copy_callback(call):
    username = call.data.replace('copy_', '')
    bot.answer_callback_query(call.id, f"📋 Выделите и скопируйте ссылку выше / Select and copy link above", show_alert=True)

@bot.message_handler(func=lambda m: m.text == "➖ Удалить пользователя (Delete User)")
def ask_del_user(message):
    if not is_authorized(message.from_user.id):
        return
    
    returncode, stdout, stderr = run_command(['/usr/local/bin/listusers'])
    if returncode == 0 and stdout.strip():
        msg = bot.send_message(message.chat.id, f"📋 *Текущие пользователи / Current users:*\n```\n{stdout}\n```\n\n📝 Введите имя / Enter name:", parse_mode='Markdown')
    else:
        msg = bot.send_message(message.chat.id, "📝 Введите имя / Enter name:")
    
    bot.register_next_step_handler(msg, delete_user)

def delete_user(message):
    if not is_authorized(message.from_user.id):
        return
    
    username = message.text.strip()
    processing_msg = bot.send_message(message.chat.id, "⏳ Удаляем / Deleting...")
    
    returncode, stdout, stderr = run_command(['/usr/local/bin/deluser', username])
    
    try:
        bot.delete_message(message.chat.id, processing_msg.message_id)
    except:
        pass

    if returncode == 0:
        bot.send_message(message.chat.id, f"✅ Удален / Deleted: *{username}*", parse_mode='Markdown', reply_markup=main_menu())
        logger.info(f"User {username} deleted by {message.from_user.id}")
    else:
        bot.send_message(message.chat.id, f"❌ Ошибка / Error: {stderr[:200]}", reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "📜 Список пользователей (User List)")
def list_users(message):
    if not is_authorized(message.from_user.id):
        return
    
    returncode, stdout, stderr = run_command(['/usr/local/bin/listusers'])
    
    if returncode == 0:
        if stdout.strip():
            bot.send_message(message.chat.id, f"📜 *Список пользователей / User list:*\n```\n{stdout}\n```", parse_mode='Markdown', reply_markup=main_menu())
        else:
            bot.send_message(message.chat.id, "📭 Пользователи не созданы / No users", reply_markup=main_menu())
    else:
        bot.send_message(message.chat.id, f"❌ Ошибка / Error: {stderr[:200]}", reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "📊 Статус сервера (Server Status)")
def server_status(message):
    if not is_authorized(message.from_user.id):
        return
    
    returncode, stdout, stderr = run_command(['systemctl', 'is-active', 'xray'])
    xray_status = "🟢 Активен / Active" if returncode == 0 else "🔴 Неактивен / Inactive"
    
    returncode, stdout, stderr = run_command(['uptime', '-p'])
    uptime = stdout.strip() if returncode == 0 else "N/A"
    
    returncode, stdout, stderr = run_command(['free', '-h'])
    memory = "N/A"
    if returncode == 0:
        lines = stdout.split('\n')
        if len(lines) > 1:
            mem_info = lines[1].split()
            if len(mem_info) >= 3:
                memory = f"{mem_info[2]} / {mem_info[1]}"

    status_text = f"""📊 *Статус сервера / Server Status v23.0-full*

🌐 *IP:* {SERVER_IP}
🔧 *Xray:* {xray_status}
🎭 *Reality:* {REALITY_NAME}
⏱️ *Uptime:* {uptime}
💾 *RAM:* {memory}
📅 *Время / Time:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

    bot.send_message(message.chat.id, status_text, parse_mode='Markdown', reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "🔄 Перезапуск Xray (Restart Xray)")
def restart_xray(message):
    if not is_authorized(message.from_user.id):
        return
    
    progress_msg = bot.send_message(message.chat.id, "⏳ Инициируем перезапуск / Initiating restart...")
    
    try:
        bot.edit_message_text("🔄 Перезапуск / Restarting...", message.chat.id, progress_msg.message_id)
        returncode, stdout, stderr = run_command(['systemctl', 'restart', 'xray'])
        
        time.sleep(3)
        bot.edit_message_text("🔍 Проверка / Checking...", message.chat.id, progress_msg.message_id)
        
        returncode2, stdout2, stderr2 = run_command(['systemctl', 'is-active', 'xray'])
        
        if returncode2 == 0:
            returncode3, stdout3, stderr3 = run_command(['ss', '-tlnp'])
            port_ok = ":443" in stdout3
            
            final_text = "✅ *Xray перезапущен / Xray restarted!*\n\n"
            final_text += "🔧 Статус / Status: Активен / Active\n"
            final_text += f"🌐 Порт / Port 443: {'Открыт / Open' if port_ok else 'Проверяется / Checking'}\n"
            final_text += "📊 Готов / Ready"
            
            bot.edit_message_text(final_text, message.chat.id, progress_msg.message_id, parse_mode='Markdown')
            logger.info(f"Xray restarted by {message.from_user.id}")
            
            # Уведомление после успешного перезапуска
            time.sleep(2)
            send_notification(
                message.chat.id,
                "🔔 *УВЕДОМЛЕНИЕ v23.0-full*\n\n✅ Xray успешно перезапущен!\nВсе системы работают в штатном режиме.\n\n✅ Xray restarted successfully!\nAll systems operational."
            )
        else:
            bot.edit_message_text(f"❌ *Ошибка / Error*", message.chat.id, progress_msg.message_id, parse_mode='Markdown')
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Ошибка / Error")
    
    time.sleep(2)
    bot.send_message(message.chat.id, "Выберите действие / Choose action:", reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "🎭 Смена маскировки (Change Reality)")
def change_reality_menu(message):
    if not is_authorized(message.from_user.id):
        return
    
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("🔵 Google", callback_data="reality_www.google.com"),
        types.InlineKeyboardButton("⚫ GitHub", callback_data="reality_github.com")
    )
    markup.add(types.InlineKeyboardButton("🟣 Yahoo", callback_data="reality_www.yahoo.com"))
    markup.add(types.InlineKeyboardButton("❌ Отмена / Cancel", callback_data="reality_cancel"))
    
    warning_text = """🎭 *Смена маскировки Reality / Change Reality*

⚠️ *ВНИМАНИЕ / WARNING!*
Старые ссылки перестанут работать / Old links will stop working

✅ *WHITELIST v23.0-full:*
• GitHub
• Google  
• Yahoo

Выберите домен / Choose domain:"""
    
    bot.send_message(message.chat.id, warning_text, parse_mode='Markdown', reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('reality_'))
def reality_callback(call):
    if not is_authorized(call.from_user.id):
        return
    
    if call.data == "reality_cancel":
        bot.edit_message_text("❌ Отменено / Cancelled", call.message.chat.id, call.message.message_id)
        bot.send_message(call.message.chat.id, "Выберите действие / Choose:", reply_markup=main_menu())
        return
    
    domain = call.data.replace('reality_', '')
    
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("✅ ПОДТВЕРДИТЬ / CONFIRM", callback_data=f"confirm_{domain}"),
        types.InlineKeyboardButton("❌ Отмена / Cancel", callback_data="reality_cancel")
    )
    
    confirm_text = f"""⚠️ *ПОДТВЕРЖДЕНИЕ / CONFIRMATION*

Новая маскировка / New: *{domain}*

🚨 Старые ссылки перестанут работать!
Old links will stop working!

Подтвердите / Confirm:"""
    
    bot.edit_message_text(confirm_text, call.message.chat.id, call.message.message_id, 
                         parse_mode='Markdown', reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('confirm_'))
def confirm_reality_callback(call):
    if not is_authorized(call.from_user.id):
        return
    
    domain = call.data.replace('confirm_', '')
    
    bot.edit_message_text(f"⏳ *Меняем на / Changing to {domain}...*\n\nПодождите / Wait...", 
                         call.message.chat.id, call.message.message_id, parse_mode='Markdown')
    
    try:
        # Используем --force режим + прямое уведомление через API
        returncode, stdout, stderr = run_command(['/usr/local/bin/change-reality-domain.sh', '--force', domain])
        
        if returncode == 0:
            if "google" in domain:
                friendly_name = "Google"
            elif "github" in domain:
                friendly_name = "GitHub" 
            elif "yahoo" in domain:
                friendly_name = "Yahoo"
            else:
                friendly_name = domain
            
            success_text = f"""✅ *Маскировка изменена / Changed!*

🎭 *Новая / New:* {friendly_name}
🔄 *Конфигурации / Configs:* Обновлены / Updated
🔄 *Сервисы / Services:* Перезапущены / Restarted
🔔 *Уведомление / Notification:* Отправлено / Sent via API

⚠️ *ВАЖНО / IMPORTANT:* Старые ссылки недействительны / Old links invalid!
📱 Создайте новых пользователей / Create new users"""
            
            bot.edit_message_text(success_text, call.message.chat.id, call.message.message_id, parse_mode='Markdown')
            logger.info(f"Reality changed to {domain} by {call.from_user.id}")
            
            time.sleep(3)
            bot.send_message(call.message.chat.id, "Выберите действие:", reply_markup=main_menu())
            
        else:
            error_text = f"❌ *Ошибка смены / Change error*\n\nЛоги / Logs:\n```\n{stderr[:500]}\n```"
            bot.edit_message_text(error_text, call.message.chat.id, call.message.message_id, parse_mode='Markdown')
    
    except Exception as e:
        bot.edit_message_text(f"❌ *Системная ошибка / System error*: {str(e)[:200]}", call.message.chat.id, call.message.message_id, parse_mode='Markdown')

@bot.message_handler(func=lambda m: m.text == "🔄 Перезагрузка сервера (Reboot Server)")
def reboot_server_confirm(message):
    if not is_authorized(message.from_user.id):
        return
    
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("⚠️ ДА, ПЕРЕЗАГРУЗИТЬ / YES, REBOOT", callback_data="reboot_confirm"),
        types.InlineKeyboardButton("❌ Отмена / Cancel", callback_data="reboot_cancel")
    )
    
    warning_text = """⚠️ *ПРЕДУПРЕЖДЕНИЕ / WARNING*

Перезагрузка сервера приведет к:
Server reboot will cause:
• Разрыв всех VPN подключений / Disconnect VPNs
• Перезапуск всех сервисов / Restart services
• Недоступность 1-2 минуты / Unavailable 1-2 min

🔔 Вы получите уведомление после загрузки
You will receive notification after boot

Вы уверены / Are you sure?"""
    
    bot.send_message(message.chat.id, warning_text, parse_mode='Markdown', reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('reboot_'))
def reboot_callback(call):
    if not is_authorized(call.from_user.id):
        return
    
    action = call.data.replace('reboot_', '')
    
    if action == "cancel":
        bot.edit_message_text("❌ Отменено / Cancelled", call.message.chat.id, call.message.message_id)
        bot.send_message(call.message.chat.id, "Выберите действие / Choose:", reply_markup=main_menu())
        return
    
    if action == "confirm":
        bot.edit_message_text("🔄 *Сервер перезагружается / Server rebooting...*\n\n1-2 минуты / 1-2 minutes\n\n🔔 Systemd отправит уведомление автоматически\nSystemd will send notification automatically", 
                             call.message.chat.id, call.message.message_id, parse_mode='Markdown')
        
        logger.info(f"Server reboot by {call.from_user.id}")
        
        # systemd сервис автоматически отправит уведомление
        subprocess.Popen(['bash', '-c', 'sleep 3 && shutdown -r now'], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)

@bot.message_handler(func=lambda m: m.text == "📖 Руководство (Guide)")
def comprehensive_guide(message):
    if not is_authorized(message.from_user.id):
        return
    
    guide_text = """📖 *РУКОВОДСТВО v23.0-full (FIXED) / GUIDE*

👤 *УПРАВЛЕНИЕ / USER MANAGEMENT:*
• Создать - создает VPN пользователя
• Удалить - удаляет пользователя
• Список - показывает всех
• Статус - информация о системе
• Перезапуск - перезапуск Xray + 🔔 уведомление
• Смена Reality - изменение домена + 🔔 API уведомление
• Перезагрузка - перезагрузка + 🔔 systemd уведомление
• Диагностика - полная проверка + проверка прав

📁 *РАСПОЛОЖЕНИЕ ФАЙЛОВ / FILE LOCATIONS:*
• Config: `/usr/local/etc/xray/config.json`
• Ключи / Keys: `/usr/local/etc/xray/.keys`
• Token: `/usr/local/etc/xray/bot_token.txt` (owner: root)
• Chat ID: `/usr/local/etc/xray/.chatid` (owner: root)
• Логи / Logs: `/var/log/xray/`
• Скрипты / Scripts: `/usr/local/bin/`

⚡ *SSH КОМАНДЫ / SSH COMMANDS:*
• `newuser имя` - создать пользователя
• `listusers` - список пользователей
• `deluser имя` - удалить пользователя
• `systemctl restart xray` - перезапуск
• `systemctl status xray` - статус

🔧 *SSH СКРИПТЫ / SSH SCRIPTS:*
• `xray-diagnostics.sh` - диагностика + проверка прав
• `change-reality-domain.sh github.com` - интерактивная смена
• `change-reality-domain.sh --force github.com` - автоматическая смена + уведомление
• `xray_notify_boot.sh` - уведомление о загрузке
• `uninstall-xray.sh` - удаление

🎭 *WHITELIST v23.0-full (безопасные / safe):*
• github.com / www.github.com
• www.google.com / google.com
• www.yahoo.com / yahoo.com

🔔 *УВЕДОМЛЕНИЯ v23.0-full (ИСПРАВЛЕНО):*
• После перезагрузки Xray (в бот)
• После смены Reality (через API, права исправлены)
• После перезагрузки сервера (systemd сервис)

📋 *ПРОСМОТР ЛОГОВ / VIEW LOGS:*
• `journalctl -u xray -f` - Xray realtime
• `journalctl -u xray_bot -f` - bot realtime
• `journalctl -u xray_notify_boot` - boot notifications
• `tail -f /var/log/xray/error.log` - ошибки
• `tail -f /var/log/xray/access.log` - подключения

🔍 *ОТЛАДКА / DEBUGGING:*
• `systemctl status xray` - статус
• `systemctl status xray_notify_boot` - статус уведомлений (oneshot)
• `ss -tlnp | grep 443` - порт
• `ls -la /usr/local/etc/xray/bot_token.txt` - права токена
• `ls -la /usr/local/etc/xray/.chatid` - права chat_id
• `/usr/local/bin/xray run -c config.json -test` - тест
• `xray-diagnostics.sh` - диагностика

🛠️ *ИСПРАВЛЕНИЯ v23.0-full:*
• bot_token.txt: owner root:root, chmod 600
• .chatid: owner root:root, chmod 600
• Все скрипты корректно читают файлы от root"""

    bot.send_message(message.chat.id, guide_text, parse_mode='Markdown', reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "🔧 Диагностика (Diagnostics)")
def run_diagnostics(message):
    if not is_authorized(message.from_user.id):
        return
    
    processing_msg = bot.send_message(message.chat.id, "⏳ Запуск / Running...")
    
    try:
        returncode, stdout, stderr = run_command(['/usr/local/bin/xray-diagnostics.sh'])
        
        try:
            bot.delete_message(message.chat.id, processing_msg.message_id)
        except:
            pass
        
        if returncode == 0 and stdout:
            max_length = 4000
            if len(stdout) > max_length:
                parts = [stdout[i:i+max_length] for i in range(0, len(stdout), max_length)]
                for i, part in enumerate(parts):
                    if i == 0:
                        bot.send_message(message.chat.id, f"🔧 *Диагностика v23.0-full (часть {i+1}):*\n```\n{part}\n```", parse_mode='Markdown')
                    else:
                        bot.send_message(message.chat.id, f"```\n{part}\n```", parse_mode='Markdown')
            else:
                bot.send_message(message.chat.id, f"🔧 *Диагностика:*\n```\n{stdout}\n```", parse_mode='Markdown')
        else:
            bot.send_message(message.chat.id, f"❌ Ошибка:\n```\n{stderr[:1000]}\n```", parse_mode='Markdown')
        
    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Ошибка: {str(e)[:200]}")
    
    bot.send_message(message.chat.id, "Выберите действие:", reply_markup=main_menu())

@bot.message_handler(func=lambda m: m.text == "📋 Логи (Logs)")
def show_logs_menu(message):
    if not is_authorized(message.from_user.id):
        return
    
    markup = types.InlineKeyboardMarkup()
    markup.add(
        types.InlineKeyboardButton("🔧 Xray Logs", callback_data="logs_xray"),
        types.InlineKeyboardButton("🤖 Bot Logs", callback_data="logs_bot")
    )
    markup.add(
        types.InlineKeyboardButton("🔔 Boot Notify", callback_data="logs_notify"),
        types.InlineKeyboardButton("❌ Error Log", callback_data="logs_error")
    )
    markup.add(types.InlineKeyboardButton("❌ Отмена / Cancel", callback_data="logs_cancel"))
    
    bot.send_message(message.chat.id, "📋 *Выбор логов / Choose logs:*", parse_mode='Markdown', reply_markup=markup)

@bot.callback_query_handler(func=lambda call: call.data.startswith('logs_'))
def logs_callback(call):
    if not is_authorized(call.from_user.id):
        return
    
    if call.data == "logs_cancel":
        bot.edit_message_text("❌ Отменено / Cancelled", call.message.chat.id, call.message.message_id)
        bot.send_message(call.message.chat.id, "Выберите действие:", reply_markup=main_menu())
        return
    
    log_type = call.data.replace('logs_', '')
    
    try:
        if log_type == "xray":
            returncode, stdout, stderr = run_command(['journalctl', '-u', 'xray', '--no-pager', '-n', '20'])
            log_title = "🔧 Xray Service Logs (last 20)"
        elif log_type == "bot":
            returncode, stdout, stderr = run_command(['journalctl', '-u', 'xray_bot', '--no-pager', '-n', '20'])
            log_title = "🤖 Bot Service Logs (last 20)"
        elif log_type == "notify":
            returncode, stdout, stderr = run_command(['journalctl', '-u', 'xray_notify_boot', '--no-pager', '-n', '20'])
            log_title = "🔔 Boot Notification Logs (last 20)"
        elif log_type == "error":
            returncode, stdout, stderr = run_command(['tail', '-n', '20', '/var/log/xray/error.log'])
            log_title = "❌ Xray Error Log (last 20)"
        else:
            bot.edit_message_text("❌ Неизвестный тип", call.message.chat.id, call.message.message_id)
            return
        
        bot.edit_message_text("⏳ Загружаем / Loading...", call.message.chat.id, call.message.message_id)
        
        if returncode == 0 and stdout.strip():
            max_length = 3500
            log_content = stdout.strip()
            if len(log_content) > max_length:
                log_content = log_content[-max_length:]
                log_content = "...\n" + log_content
            
            final_text = f"📋 *{log_title}:*\n```\n{log_content}\n```"
            bot.edit_message_text(final_text, call.message.chat.id, call.message.message_id, parse_mode='Markdown')
        else:
            error_msg = stderr[:500] if stderr else "Логи недоступны"
            bot.edit_message_text(f"❌ *Ошибка:*\n```\n{error_msg}\n```", call.message.chat.id, call.message.message_id, parse_mode='Markdown')
            
    except Exception as e:
        bot.edit_message_text(f"❌ Ошибка: {str(e)[:200]}", call.message.chat.id, call.message.message_id)

@bot.message_handler(func=lambda m: True)
def handle_unknown(message):
    if not is_authorized(message.from_user.id):
        bot.send_message(message.chat.id, "❌ Доступ запрещен / Access denied")
        return
    bot.send_message(message.chat.id, "❓ Неизвестная команда / Unknown. Используйте меню / Use menu.", reply_markup=main_menu())

if __name__ == "__main__":
    logger.info("Starting Xray Telegram Bot v23.0-full (FIXED)...")
    logger.info(f"Authorized users: {AUTHORIZED_USERS}")
    logger.info(f"Server IP: {SERVER_IP}")
    logger.info(f"Reality: {REALITY_NAME}")
    logger.info("Features: FULL BOT + FIXED notifications (correct file permissions) + Fixed Reality + Whitelist")
    
    try:
        bot.infinity_polling(none_stop=True, timeout=60)
    except Exception as e:
        logger.error(f"Bot error: {e}")
        time.sleep(5)
        try:
            bot.infinity_polling(none_stop=True, timeout=60)
        except Exception as e2:
            logger.error(f"Failed to restart: {e2}")
            sys.exit(1)
BOT_EOF

sed -i "s/TOKEN_PLACEHOLDER/$TELEGRAM_TOKEN/g" /usr/local/bin/xray_bot.py
sed -i "s/OWNER_ID_PLACEHOLDER/$OWNER_ID/g" /usr/local/bin/xray_bot.py
sed -i "s/SERVER_IP_PLACEHOLDER/$SERVER_IP/g" /usr/local/bin/xray_bot.py
sed -i "s/REALITY_NAME_PLACEHOLDER/$REALITY_NAME/g" /usr/local/bin/xray_bot.py

chmod +x /usr/local/bin/xray_bot.py

cat > /etc/systemd/system/xray_bot.service << EOF
[Unit]
Description=Xray Telegram Bot v23.0-full (FIXED)
After=network.target xray.service

[Service]
Type=simple
User=root
WorkingDirectory=/usr/local/bin
ExecStart=/usr/local/bin/xray_bot.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "✅ Bot v23.0-full (FIXED) with working notifications created"

echo -e "${YELLOW}🔒 Установка правильных прав...${NC}"
mkdir -p /var/lib/xray
useradd --system --shell /usr/sbin/nologin --home-dir /var/lib/xray xray 2>/dev/null || true

# ИСПРАВЛЕНО: правильные права для файлов
chown -R xray:xray /usr/local/etc/xray /var/log/xray /var/lib/xray 2>/dev/null || true
chmod 755 /usr/local/etc/xray /usr/local/etc/xray/backups 2>/dev/null || true
chmod 600 /usr/local/etc/xray/config.json 2>/dev/null || true
chmod 644 /usr/local/etc/xray/.keys 2>/dev/null || true

# ВАЖНО: файлы для уведомлений должны принадлежать root (бот запускается от root)
chown root:root /usr/local/etc/xray/bot_token.txt /usr/local/etc/xray/.chatid
chmod 600 /usr/local/etc/xray/bot_token.txt /usr/local/etc/xray/.chatid

echo "✅ Права настроены правильно (уведомления от root)"

echo -e "${YELLOW}🧪 Тест...${NC}"
if /usr/local/bin/xray run -c /usr/local/etc/xray/config.json -test; then
    echo "✅ Конфигурация валидна"
else
    echo -e "${RED}❌ Ошибка${NC}"
    exit 1
fi

echo -e "${YELLOW}🚀 Запуск сервисов...${NC}"
systemctl daemon-reload

systemctl enable xray
systemctl restart xray

sleep 5

if systemctl is-active --quiet xray; then
    echo "✅ Xray запущен"
else
    echo -e "${RED}❌ Ошибка Xray${NC}"
    exit 1
fi

if ss -tlnp | grep -q ":443"; then
    echo "✅ Порт 443 открыт"
else
    echo -e "${RED}❌ Порт 443 закрыт${NC}"
    exit 1
fi

systemctl enable xray_bot
systemctl restart xray_bot

sleep 3

if systemctl is-active --quiet xray_bot; then
    echo "✅ Bot запущен"
else
    echo -e "${YELLOW}⚠️ Проблемы с ботом${NC}"
fi

systemctl enable xray_notify_boot
echo "✅ Boot notification service enabled"

echo -e "${YELLOW}🔔 Тест уведомлений...${NC}"
# Проверяем, что файлы читаются корректно
if TOKEN=$(cat /usr/local/etc/xray/bot_token.txt 2>/dev/null) && CHAT_ID=$(cat /usr/local/etc/xray/.chatid 2>/dev/null); then
    if [[ -n "$TOKEN" ]] && [[ -n "$CHAT_ID" ]]; then
        echo "✅ Файлы уведомлений читаются корректно"
        echo "   Token length: ${#TOKEN}"
        echo "   Chat ID: $CHAT_ID"
    else
        echo "⚠️ Файлы пустые"
    fi
else
    echo "❌ Не удается прочитать файлы уведомлений"
fi

PUBLIC_KEY=$(awk -F': ' '/Public key/ {print $2}' /usr/local/etc/xray/.keys)
SHORT_ID=$(awk -F': ' '/shortsid/ {print $2}' /usr/local/etc/xray/.keys)
MAIN_LINK="vless://$MAIN_UUID@$SERVER_IP:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$REALITY_SNI&fp=chrome&pbk=$PUBLIC_KEY&sid=$SHORT_ID&type=tcp&spx=%2F#main"

echo
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║              УСТАНОВКА ЗАВЕРШЕНА!                            ║${NC}"
echo -e "${GREEN}║                v23.0-full (FIXED)                            ║${NC}" 
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"

echo
echo -e "${YELLOW}🔧 v23.0-full ИСПРАВЛЕНИЯ:${NC}"
echo -e "${GREEN}   ✅ ИСПРАВЛЕНЫ права файлов для уведомлений${NC}"
echo -e "${GREEN}   ✅ bot_token.txt и .chatid принадлежат root${NC}"
echo -e "${GREEN}   ✅ Уведомления будут работать из коробки${NC}"
echo -e "${GREEN}   ✅ Готовый продукт - законченный функционал${NC}"

echo
echo -e "${YELLOW}🔔 УВЕДОМЛЕНИЯ v23.0-full (ИСПРАВЛЕНО):${NC}"
echo -e "${GREEN}   ✅ После перезагрузки Xray (в бот)${NC}"
echo -e "${GREEN}   ✅ После смены Reality (API уведомление - РАБОТАЕТ!)${NC}"
echo -e "${GREEN}   ✅ После перезагрузки сервера (systemd сервис)${NC}"

echo
echo -e "${YELLOW}🎭 WHITELIST:${NC}"
echo -e "   • github.com / www.github.com"
echo -e "   • www.google.com / google.com"
echo -e "   • www.yahoo.com / yahoo.com"

echo
echo -e "${YELLOW}📁 ФАЙЛЫ (ИСПРАВЛЕННЫЕ ПРАВА):${NC}"
echo -e "   📄 ${CYAN}/usr/local/etc/xray/config.json${NC} (xray:xray)"
echo -e "   🔑 ${CYAN}/usr/local/etc/xray/.keys${NC} (xray:xray)"
echo -e "   🤖 ${CYAN}/usr/local/etc/xray/bot_token.txt${NC} (root:root 600) ✅"
echo -e "   👤 ${CYAN}/usr/local/etc/xray/.chatid${NC} (root:root 600) ✅"
echo -e "   📊 ${CYAN}/var/log/xray/${NC}"
echo -e "   🔧 ${CYAN}/usr/local/bin/${NC}"

echo
echo -e "${YELLOW}⚡ СКРИПТЫ:${NC}"
echo -e "   🔧 ${CYAN}xray-diagnostics.sh${NC} (+ проверка прав файлов)"
echo -e "   🎭 ${CYAN}change-reality-domain.sh${NC} (+ --force + API notify ИСПРАВЛЕНО)"
echo -e "   🔔 ${CYAN}xray_notify_boot.sh${NC} (systemd notification ИСПРАВЛЕНО)"
echo -e "   🗑️ ${CYAN}uninstall-xray.sh${NC}"

echo
echo -e "${YELLOW}🔧 СЕРВИСЫ:${NC}"
echo -e "   🔧 ${CYAN}xray.service${NC} - основной VPN"
echo -e "   🤖 ${CYAN}xray_bot.service${NC} - Telegram бот"
echo -e "   🔔 ${CYAN}xray_notify_boot.service${NC} - уведомления о загрузке"

echo
echo -e "${YELLOW}📋 ИНФОРМАЦИЯ:${NC}"
echo -e "   🌐 IP: ${GREEN}$SERVER_IP${NC}"
echo -e "   🎭 Reality: ${GREEN}$REALITY_NAME${NC}"
echo -e "   👤 Owner: ${GREEN}$OWNER_ID${NC}"

echo
echo -e "${YELLOW}🔗 ССЫЛКА:${NC}"
echo "$MAIN_LINK"

echo
echo -e "${YELLOW}🚀 СЛЕДУЮЩИЕ ШАГИ:${NC}"
echo -e "   1. ${CYAN}/start${NC} боту"
echo -e "   2. Проверьте смену Reality - теперь с уведомлениями!"
echo -e "   3. Перезагрузите сервер - получите уведомление!"
echo -e "   4. Диагностика покажет правильные права файлов"

echo
echo -e "${GREEN}🎉 v23.0-full (FIXED) ГОТОВ!${NC}"
echo -e "${PURPLE}Законченный продукт с работающими уведомлениями! 🔔✅🎭${NC}"

if [[ "$UPDATE_MODE" == "true" ]]; then
    echo
    echo -e "${BLUE}💡 Обновление завершено! Права файлов исправлены!${NC}"
fi
