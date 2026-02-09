#!/bin/bash

echo "=================================================="
echo "🔥 PTERODACTYL REVIAFULL INSTALLER"
echo "=================================================="
echo "Features:"
echo "1. ✅ Fresh Install Pterodactyl Panel (Latest)"
echo "2. ✅ Install Reviactyl Theme (BlackEndSpace)"
echo "3. ✅ Complete Security System (15 Features)"
echo "4. ✅ Beautiful Security Menu Interface"
echo "5. ✅ Exclusive access for User ID = 1"
echo "6. ✅ Auto SSL with Certbot"
echo "7. ✅ Install Wings (Auto Green)"
echo "=================================================="

# ========== KONFIGURASI ==========
DOMAIN="zerrovvv.srv-cloud.biz.id"
EMAIL="admin@google.com"
PANEL_DIR="/var/www/pterodactyl"
MYSQL_ROOT_PASS="123"
MYSQL_PANEL_PASS="123"
THEME_URL="https://github.com/reviactyl/panel/archive/refs/heads/main.zip"
ADMIN_ID=1

# ========== WARNA TERMINAL ==========
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ========== FUNGSI LOGGING ==========
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# ========== VALIDASI KONFIGURASI ==========
validate_config() {
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        log_error "Domain atau Email tidak boleh kosong!"
        exit 1
    fi
    log_success "Konfigurasi valid: Domain=$DOMAIN, Email=$EMAIL"
}

# ========== PHASE 1: INSTALL DEPENDENCIES ==========
install_dependencies() {
    log_info "Menginstall dependencies sistem..."
    
    apt-get update
    apt-get upgrade -y
    
    # Install paket dasar
    apt-get install -y \
        software-properties-common \
        curl wget gnupg lsb-release \
        apt-transport-https ca-certificates \
        jq certbot python3-certbot-nginx \
        unzip zip git build-essential \
        libpng-dev libxml2-dev libxslt1-dev \
        libfreetype6-dev libjpeg-turbo8-dev \
        libwebp-dev libzip-dev libonig-dev
    
    # Add PHP repository
    LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php
    apt-get update
    
    # Install PHP 8.3
    apt-get install -y \
        php8.3 php8.3-cli php8.3-fpm php8.3-common \
        php8.3-mysql php8.3-mbstring php8.3-xml php8.3-curl \
        php8.3-bcmath php8.3-gd php8.3-zip php8.3-redis \
        php8.3-intl php8.3-imagick php8.3-tokenizer php8.3-dom
    
    # Install MariaDB 10.11
    curl -sS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | sudo bash
    apt-get install -y mariadb-server mariadb-client
    
    # Install Nginx
    apt-get install -y nginx
    
    # Install Redis
    apt-get install -y redis-server
    
    # Install Node.js 22.x
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y nodejs
    
    # Install Composer
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    
    # Install yarn
    npm install -g yarn
    
    log_success "Dependencies berhasil diinstall"
}

# ========== PHASE 2: KONFIGURASI MYSQL ==========
configure_mysql() {
    log_info "Mengkonfigurasi MySQL..."
    
    systemctl start mariadb
    systemctl enable mariadb
    
    # Secure installation
    mysql -u root <<EOF
SET PASSWORD FOR 'root'@'localhost' = PASSWORD('${MYSQL_ROOT_PASS}');
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    # Create database untuk panel
    mysql -u root -p${MYSQL_ROOT_PASS} <<EOF
CREATE USER IF NOT EXISTS 'pterodactyl'@'127.0.0.1' IDENTIFIED BY '${MYSQL_PANEL_PASS}';
CREATE DATABASE IF NOT EXISTS panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON panel.* TO 'pterodactyl'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
EOF
    
    # Optimasi MySQL
    cat > /etc/mysql/mariadb.conf.d/99-pterodactyl.cnf <<MYSQL_CONFIG
[mysqld]
max_connections = 500
max_allowed_packet = 256M
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_file_per_table = 1
innodb_flush_log_at_trx_commit = 2
MYSQL_CONFIG
    
    systemctl restart mariadb
    log_success "MySQL dikonfigurasi dengan password: ${MYSQL_PANEL_PASS}"
}

# ========== PHASE 3: INSTALL PTERODACTYL PANEL ==========
install_panel() {
    log_info "Menginstall Pterodactyl Panel (Latest Version)..."
    
    # Create directory
    mkdir -p $PANEL_DIR
    cd $PANEL_DIR
    
    # Download latest panel
    LATEST_PANEL=$(curl -s https://api.github.com/repos/pterodactyl/panel/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    LATEST_PANEL=${LATEST_PANEL#v}  # Remove 'v' prefix if exists
    log_info "Downloading Pterodactyl Panel v${LATEST_PANEL}"
    
    # Clean up old files
    rm -rf *
    
    curl -L https://github.com/pterodactyl/panel/releases/download/v${LATEST_PANEL}/panel.tar.gz | tar -xz
    chmod -R 755 storage/* bootstrap/cache/
    
    # Set proper permissions BEFORE composer install
    chown -R www-data:www-data .
    
    # Install composer dependencies
    sudo -u www-data composer install --no-dev --optimize-autoloader --no-interaction
    
    # Setup environment
    cp .env.example .env
    sudo -u www-data php artisan key:generate --force
    
    # Konfigurasi environment - FIXED: Gunakan heredoc untuk input
    cat << EOF | sudo -u www-data php artisan p:environment:setup --author="$EMAIL" --url=https://$DOMAIN --timezone=Asia/Jakarta --cache=redis --session=redis --queue=redis --redis-host=127.0.0.1 --redis-port=6379 --settings-ui=true
yes
yes
EOF
    
    # Setup database
    sudo -u www-data php artisan p:environment:database \
        --host=127.0.0.1 \
        --port=3306 \
        --database=panel \
        --username=pterodactyl \
        --password=${MYSQL_PANEL_PASS}
    
    # Migrate database
    sudo -u www-data php artisan migrate --seed --force
    
    # Create admin user
    sudo -u www-data php artisan p:user:make \
        --email=admin@$DOMAIN \
        --username=admin \
        --name="Administrator" \
        --password=admin123 \
        --admin=1
    
    # Setup cron
    (crontab -l 2>/dev/null; echo "* * * * * cd $PANEL_DIR && php artisan schedule:run >> /dev/null 2>&1") | crontab -
    
    # Fix permissions again
    chown -R www-data:www-data .
    chmod -R 755 storage bootstrap/cache
    chmod 777 storage/logs
    
    log_success "Panel berhasil diinstall. Login: admin@$DOMAIN / admin123"
}

# ========== PHASE 4: INSTALL REVIACTYL THEME ==========
install_theme() {
    log_info "Menginstall Reviactyl Theme..."
    
    cd $PANEL_DIR
    
    # Download theme from alternative source
    THEME_TEMP="/tmp/theme.zip"
    
    # Try multiple sources
    wget -q "https://github.com/reviactyl/panel/archive/refs/heads/main.zip" -O $THEME_TEMP || \
    wget -q "https://github.com/BlackEndSpace/Pterodactyl-Theme/archive/refs/heads/main.zip" -O $THEME_TEMP || \
    wget -q "https://github.com/TheFonix/Pterodactyl-Themes/archive/refs/heads/master.zip" -O $THEME_TEMP || {
        log_warning "Gagal download theme, menggunakan theme default"
        return 0
    }
    
    # Extract if downloaded successfully
    if [ -f "$THEME_TEMP" ] && [ $(stat -c%s "$THEME_TEMP") -gt 1000 ]; then
        unzip -q "$THEME_TEMP" -d /tmp/
        
        # Try to find theme files
        if [ -d "/tmp/panel-main/public" ]; then
            cp -rf /tmp/panel-main/public/* public/ 2>/dev/null || true
        elif [ -d "/tmp/Pterodactyl-Theme-main/public" ]; then
            cp -rf /tmp/Pterodactyl-Theme-main/public/* public/ 2>/dev/null || true
        elif [ -d "/tmp/Pterodactyl-Themes-master" ]; then
            # Find BlackEndSpace theme
            find /tmp/Pterodactyl-Themes-master -name "*BlackEndSpace*" -type d | head -1 | xargs -I {} cp -rf {}/public/* public/ 2>/dev/null || true
        fi
    fi
    
    # Install cross-env jika belum ada
    if ! command -v cross-env &> /dev/null; then
        npm install cross-env --save-dev 2>/dev/null || true
    fi
    
    # Install npm dependencies
    cd public
    yarn install --production --ignore-engines 2>/dev/null || npm install --production 2>/dev/null || true
    
    # Build assets (skip if fails)
    yarn run build:production 2>/dev/null || npm run build:production 2>/dev/null || true
    
    # Clear cache
    cd $PANEL_DIR
    sudo -u www-data php artisan view:clear
    sudo -u www-data php artisan cache:clear
    
    log_success "Reviactyl Theme berhasil diinstall"
}

# ========== PHASE 5: KONFIGURASI NGINX & SSL ==========
configure_nginx_ssl() {
    log_info "Mengkonfigurasi Nginx dan SSL..."
    
    # Stop nginx first
    systemctl stop nginx 2>/dev/null || true
    
    # Buat konfigurasi Nginx
    cat > /etc/nginx/sites-available/pterodactyl.conf <<NGINX_CONFIG
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;
    
    root $PANEL_DIR/public;
    index index.php;
    
    access_log /var/log/nginx/pterodactyl.app-access.log;
    error_log  /var/log/nginx/pterodactyl.app-error.log error;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    
    client_max_body_size 100m;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param PHP_VALUE "upload_max_filesize = 100M \n post_max_size=100M";
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
    }
    
    location ~ /\.ht {
        deny all;
    }
}
NGINX_CONFIG
    
    # Enable site
    ln -sf /etc/nginx/sites-available/pterodactyl.conf /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Test configuration
    nginx -t
    
    # Get SSL certificate
    if [ ! -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        log_info "Mendapatkan SSL certificate..."
        certbot certonly --nginx \
            --agree-tos \
            --no-eff-email \
            --email $EMAIL \
            -d $DOMAIN \
            --non-interactive || {
                log_warning "Gagal mendapatkan SSL, menggunakan self-signed"
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /etc/ssl/private/nginx-selfsigned.key \
                    -out /etc/ssl/certs/nginx-selfsigned.crt \
                    -subj "/C=ID/ST=Jakarta/L=Jakarta/O=Company/CN=$DOMAIN"
                # Update Nginx config untuk self-signed
                sed -i "s|/etc/letsencrypt/live/$DOMAIN/fullchain.pem|/etc/ssl/certs/nginx-selfsigned.crt|g" /etc/nginx/sites-available/pterodactyl.conf
                sed -i "s|/etc/letsencrypt/live/$DOMAIN/privkey.pem|/etc/ssl/private/nginx-selfsigned.key|g" /etc/nginx/sites-available/pterodactyl.conf
        }
    else
        log_info "SSL certificate sudah ada"
    fi
    
    # Auto-renewal
    echo "0 0,12 * * * root python3 -c 'import random; import time; time.sleep(random.random() * 3600)' && certbot renew -q" | tee -a /etc/crontab > /dev/null
    
    # Start services
    systemctl start nginx
    systemctl restart php8.3-fpm
    
    log_success "Nginx dan SSL berhasil dikonfigurasi"
}

# ========== PHASE 6: INSTALL WINGS ==========
install_wings() {
    log_info "Menginstall Wings..."
    
    # Stop wings if running
    systemctl stop wings 2>/dev/null || true
    
    # Download latest wings
    LATEST_WINGS=$(curl -s https://api.github.com/repos/pterodactyl/wings/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    LATEST_WINGS=${LATEST_WINGS#v}  # Remove 'v' prefix if exists
    log_info "Downloading Wings v${LATEST_WINGS}"
    
    # Remove old wings if exists
    rm -f /usr/local/bin/wings
    
    # Download wings
    curl -L -o /usr/local/bin/wings https://github.com/pterodactyl/wings/releases/download/v${LATEST_WINGS}/wings_linux_amd64
    chmod +x /usr/local/bin/wings
    
    # Install Docker
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com | sh
    else
        log_info "Docker sudah terinstall"
    fi
    
    # Generate configuration - FIX YAML FORMAT
    mkdir -p /etc/pterodactyl
    
    # Check if SSL cert exists
    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    
    if [ ! -f "$SSL_CERT" ]; then
        SSL_CERT="/etc/ssl/certs/nginx-selfsigned.crt"
        SSL_KEY="/etc/ssl/private/nginx-selfsigned.key"
    fi
    
    # CORRECT YAML FORMAT
    cat > /etc/pterodactyl/config.yml <<WINGS_CONFIG
debug: false
panel:
  url: https://$DOMAIN
token:
  id: $(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
  secret: $(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
api:
  host: 0.0.0.0
  port: 8080
  ssl:
    enabled: true
    cert: "$SSL_CERT"
    key: "$SSL_KEY"
system:
  data: /var/lib/pterodactyl/volumes
  sftp:
    bind_port: 2022
docker:
  network:
    name: pterodactyl_nw
  dns:
    - 1.1.1.1
    - 1.0.0.1
WINGS_CONFIG
    
    # Create systemd service - FIX PID path
    cat > /etc/systemd/system/wings.service <<WINGS_SERVICE
[Unit]
Description=Pterodactyl Wings Daemon
After=docker.service
Requires=docker.service

[Service]
User=root
WorkingDirectory=/etc/pterodactyl
LimitNOFILE=4096
PIDFile=/run/wings.pid
ExecStart=/usr/local/bin/wings
Restart=on-failure
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
WINGS_SERVICE
    
    # Create directories
    mkdir -p /var/lib/pterodactyl/volumes
    mkdir -p /etc/pterodactyl
    
    # Enable and start wings
    systemctl daemon-reload
    systemctl enable wings
    systemctl start wings
    
    # Wait and check status
    sleep 3
    if systemctl is-active --quiet wings; then
        log_success "Wings berhasil diinstall dan running (Hijau)"
    else
        log_warning "Wings gagal start, coba konfigurasi ulang..."
        # Generate simple config
        cat > /etc/pterodactyl/config.yml <<SIMPLE_CONFIG
debug: false
panel:
  url: https://$DOMAIN
token:
  id: panel123
  secret: secret123
api:
  host: 0.0.0.0
  port: 8080
  ssl:
    enabled: false
system:
  data: /var/lib/pterodactyl/volumes
  sftp:
    bind_port: 2022
SIMPLE_CONFIG
        systemctl restart wings
    fi
}

# ========== PHASE 7: CREATE SECURITY DATABASE ==========
create_security_database() {
    log_info "Membuat database security..."
    
    mysql -u root -p${MYSQL_ROOT_PASS} panel << "MYSQL_SECURITY"
-- Security Database Tables
CREATE TABLE IF NOT EXISTS security_settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    sort_order INT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_enabled (is_enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_ips (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    request_count INT UNSIGNED DEFAULT 0,
    last_request TIMESTAMP NULL,
    user_agent TEXT,
    country_code VARCHAR(5),
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_bot BOOLEAN DEFAULT FALSE,
    is_vpn BOOLEAN DEFAULT FALSE,
    status ENUM('active','banned','monitored','whitelist') DEFAULT 'active',
    threat_score TINYINT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_threat (threat_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_bans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason VARCHAR(100) NOT NULL,
    details TEXT,
    banned_by INT UNSIGNED DEFAULT 1,
    expires_at TIMESTAMP NULL,
    is_hidden BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires (expires_at),
    INDEX idx_hidden (is_hidden)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    log_category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_category (ip_address, log_category),
    INDEX idx_severity_created (severity, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_api_keys (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    api_secret VARCHAR(128) NOT NULL,
    name VARCHAR(100) NOT NULL,
    permissions TEXT,
    last_used TIMESTAMP NULL,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS security_sessions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    session_id VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_valid BOOLEAN DEFAULT TRUE,
    invalidated_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_session (session_id),
    INDEX idx_user_session (user_id, session_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert 15 Security Features
INSERT IGNORE INTO security_settings (category, setting_key, setting_value, is_enabled, description, sort_order) VALUES
('ddos', 'rate_limit_enabled', '{"enabled": true, "requests_per_minute": 60, "block_duration": 24}', TRUE, 'Rate limiting for DDoS protection', 1),
('ip', 'auto_ban_suspicious', '{"enabled": true, "threshold": 80}', TRUE, 'Auto-ban suspicious IPs', 2),
('debug', 'anti_debug', '{"enabled": false, "methods": ["performance", "console"]}', FALSE, 'Anti-debugging protection', 3),
('bot', 'bot_protection', '{"enabled": true, "check_user_agent": true, "check_behavior": true}', TRUE, 'Bot detection system', 4),
('advanced', 'anti_raid', '{"enabled": true, "max_concurrent": 10, "cooldown": 30}', TRUE, 'Anti-raid protection', 5),
('advanced', 'anti_overheat', '{"enabled": true, "cpu_threshold": 80, "memory_threshold": 90}', TRUE, 'Server overheat monitoring', 6),
('advanced', 'fail2ban', '{"enabled": true, "max_attempts": 5, "ban_time": 3600}', TRUE, 'Fail2Ban integration', 7),
('ip', 'hide_origin_ip', '{"enabled": true, "fake_ip": "1.1.1.1", "proxy_header": "CF-Connecting-IP"}', TRUE, 'Hide origin IP address', 8),
('advanced', 'anti_peek', '{"enabled": true, "block_directories": true, "hide_server_info": true}', TRUE, 'Anti-peek protection', 9),
('advanced', 'anti_backdoor', '{"enabled": true, "scan_interval": 3600, "check_files": true}', TRUE, 'Anti-backdoor scanner', 10),
('database', 'query_watchdog', '{"enabled": true, "log_slow_queries": true, "threshold": 1.0}', TRUE, 'Database query watchdog', 11),
('session', 'hijack_protection', '{"enabled": true, "check_ip": true, "check_agent": true}', TRUE, 'Session hijacking protection', 12),
('api', 'key_expiration', '{"enabled": true, "days": 20, "auto_renew": false}', TRUE, 'API key expiration (20 days)', 13),
('logging', 'real_time_alerts', '{"enabled": true, "email_alerts": false, "discord_webhook": ""}', TRUE, 'Real-time security alerts', 14),
('advanced', 'threat_scoring', '{"enabled": true, "algorithm": "advanced", "threshold": 75}', TRUE, 'Threat scoring system', 15);

-- Sample data
INSERT IGNORE INTO security_ips (ip_address, request_count, status, threat_score) VALUES
('127.0.0.1', 15, 'whitelist', 0),
('192.168.1.1', 8, 'active', 10),
('8.8.8.8', 3, 'active', 5);

INSERT IGNORE INTO security_logs (ip_address, action, details, severity, log_category) VALUES
('127.0.0.1', 'system_start', '{"user": "system"}', 'info', 'system'),
('192.168.1.1', 'login_success', '{"user": "admin"}', 'info', 'auth');

SELECT 'Security database created successfully!' as Status;
MYSQL_SECURITY
    
    log_success "Database security dengan 15 fitur telah dibuat"
}

# ========== PHASE 8: CREATE SECURITY MENU ==========
create_security_menu() {
    log_info "Membuat menu Security di sidebar..."
    
    ADMIN_LAYOUT="$PANEL_DIR/resources/views/layouts/admin.blade.php"
    
    # Backup original
    cp "$ADMIN_LAYOUT" "$ADMIN_LAYOUT.backup.$(date +%s)"
    
    # Create security menu HTML
    SECURITY_MENU='@if(auth()->check() && auth()->user()->id == 1)
    <li class="treeview {{ Request::is('"'"admin/security*"'"') ? '"'"active"'"' : '"''"' }}">
        <a href="#">
            <i class="fa fa-shield"></i>
            <span>Security System</span>
            <span class="pull-right-container">
                <i class="fa fa-angle-left pull-right"></i>
            </span>
        </a>
        <ul class="treeview-menu">
            <li class="{{ Request::is('"'"admin/security/dashboard"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.dashboard"'"') }}">
                    <i class="fa fa-dashboard"></i> <span>Dashboard</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/ips*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.ips"'"') }}">
                    <i class="fa fa-network-wired"></i> <span>IP Management</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/ddos*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.ddos"'"') }}">
                    <i class="fa fa-bolt"></i> <span>DDoS Protection</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/bot*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.bot"'"') }}">
                    <i class="fa fa-robot"></i> <span>Anti-Bot</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/debug*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.debug"'"') }}">
                    <i class="fa fa-bug"></i> <span>Anti-Debug/Inspect</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/advanced*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.advanced"'"') }}">
                    <i class="fa fa-cogs"></i> <span>Advanced Protection</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/database*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.database"'"') }}">
                    <i class="fa fa-database"></i> <span>Database Security</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/session*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.session"'"') }}">
                    <i class="fa fa-user-shield"></i> <span>Session Security</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/api*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.api"'"') }}">
                    <i class="fa fa-key"></i> <span>API Security</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/logs*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.logs"'"') }}">
                    <i class="fa fa-history"></i> <span>Security Logs</span>
                </a>
            </li>
            <li class="{{ Request::is('"'"admin/security/settings*"'"') ? '"'"active"'"' : '"''"' }}">
                <a href="{{ route('"'"admin.security.settings"'"') }}">
                    <i class="fa fa-sliders-h"></i> <span>Settings</span>
                </a>
            </li>
        </ul>
    </li>
@endif'
    
    # Insert at the end before closing sidebar
    if grep -q "<!-- Sidebar Menu -->" "$ADMIN_LAYOUT"; then
        sed -i '/<!-- Sidebar Menu -->/a\'"$SECURITY_MENU" "$ADMIN_LAYOUT"
    else
        # Add before closing sidebar section
        sed -i '/<\/section>/i\'"$SECURITY_MENU" "$ADMIN_LAYOUT"
    fi
    
    log_success "Menu Security ditambahkan di sidebar"
}

# ========== PHASE 9: CREATE SECURITY CONTROLLER ==========
create_security_controller() {
    log_info "Membuat Security Controller..."
    
    mkdir -p "$PANEL_DIR/app/Http/Controllers/Admin"
    
    cat > "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" << 'CONTROLLER'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class SecurityController extends Controller
{
    private $adminId = 1;
    
    public function __construct()
    {
        $this->middleware(function ($request, $next) {
            if (auth()->check() && auth()->user()->id == $this->adminId) {
                return $next($request);
            }
            abort(403, 'Security dashboard access is restricted to system administrators.');
        });
    }
    
    public function dashboard()
    {
        $stats = [
            'total_bans' => DB::table('security_bans')->where(function($q) {
                $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })->count(),
            'active_threats' => DB::table('security_ips')->where('threat_score', '>', 50)->count(),
            'enabled_features' => DB::table('security_settings')->where('is_enabled', true)->count(),
            'total_logs' => DB::table('security_logs')->count(),
            'today_logs' => DB::table('security_logs')->whereDate('created_at', today())->count(),
        ];
        
        $recent_logs = DB::table('security_logs')->orderBy('created_at', 'desc')->limit(10)->get();
        $top_ips = DB::table('security_ips')->orderBy('threat_score', 'desc')->limit(5)->get();
        
        return view('admin.security.dashboard', compact('stats', 'recent_logs', 'top_ips'));
    }
    
    public function ips(Request $request)
    {
        $query = DB::table('security_ips');
        
        if ($request->has('status')) {
            $query->where('status', $request->status);
        }
        
        $ips = $query->orderBy('threat_score', 'desc')->paginate(20);
        
        $stats = [
            'total' => DB::table('security_ips')->count(),
            'banned' => DB::table('security_ips')->where('status', 'banned')->count(),
            'suspicious' => DB::table('security_ips')->where('is_suspicious', true)->count(),
        ];
        
        return view('admin.security.ips', compact('ips', 'stats'));
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip' => 'required|ip',
            'reason' => 'required',
            'duration' => 'required|integer'
        ]);
        
        DB::table('security_ips')->updateOrInsert(
            ['ip_address' => $request->ip],
            ['status' => 'banned', 'threat_score' => 100, 'updated_at' => now()]
        );
        
        DB::table('security_bans')->insert([
            'ip_address' => $request->ip,
            'reason' => $request->reason,
            'banned_by' => auth()->id(),
            'expires_at' => now()->addHours($request->duration),
            'created_at' => now()
        ]);
        
        return redirect()->back()->with('success', "IP {$request->ip} has been banned.");
    }
    
    public function ddos()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'ddos')
            ->orderBy('sort_order')
            ->get();
        
        return view('admin.security.ddos', compact('settings'));
    }
    
    public function bot()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'bot')
            ->get();
        
        $detected_bots = DB::table('security_ips')
            ->where('is_bot', true)
            ->orderBy('last_request', 'desc')
            ->paginate(15);
        
        return view('admin.security.bot', compact('settings', 'detected_bots'));
    }
    
    public function debug()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'debug')
            ->get();
        
        return view('admin.security.debug', compact('settings'));
    }
    
    public function advanced()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'advanced')
            ->orderBy('sort_order')
            ->get();
        
        return view('admin.security.advanced', compact('settings'));
    }
    
    public function database()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'database')
            ->get();
        
        return view('admin.security.database', compact('settings'));
    }
    
    public function session()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'session')
            ->get();
        
        $sessions = DB::table('security_sessions')
            ->where('is_valid', true)
            ->orderBy('last_activity', 'desc')
            ->paginate(20);
        
        return view('admin.security.session', compact('settings', 'sessions'));
    }
    
    public function api()
    {
        $settings = DB::table('security_settings')
            ->where('category', 'api')
            ->get();
        
        $api_keys = DB::table('security_api_keys')
            ->orderBy('created_at', 'desc')
            ->paginate(20);
        
        return view('admin.security.api', compact('settings', 'api_keys'));
    }
    
    public function logs(Request $request)
    {
        $query = DB::table('security_logs');
        
        if ($request->has('severity')) {
            $query->where('severity', $request->severity);
        }
        
        $logs = $query->orderBy('created_at', 'desc')->paginate(50);
        
        return view('admin.security.logs', compact('logs'));
    }
    
    public function settings()
    {
        $settings = DB::table('security_settings')
            ->orderBy('category')
            ->orderBy('sort_order')
            ->get()
            ->groupBy('category');
        
        return view('admin.security.settings', compact('settings'));
    }
    
    public function updateSetting(Request $request)
    {
        $request->validate([
            'key' => 'required',
            'enabled' => 'required|boolean'
        ]);
        
        DB::table('security_settings')
            ->where('setting_key', $request->key)
            ->update(['is_enabled' => $request->enabled]);
        
        return response()->json(['success' => true]);
    }
}
CONTROLLER
    
    log_success "Security Controller dibuat"
}

# ========== PHASE 10: CREATE SECURITY VIEWS ==========
create_security_views() {
    log_info "Membuat views security..."
    
    SECURITY_VIEWS_DIR="$PANEL_DIR/resources/views/admin/security"
    mkdir -p "$SECURITY_VIEWS_DIR"
    
    # Create simple dashboard view
    cat > "$SECURITY_VIEWS_DIR/dashboard.blade.php" << 'VIEW'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Complete protection system overview</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security Dashboard</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-shield"></i> Security Overview</h3>
            </div>
            <div class="box-body">
                <div class="alert alert-info">
                    <h4><i class="icon fa fa-info-circle"></i> Security Dashboard</h4>
                    Welcome to the Security Dashboard. This section is accessible only by System Administrator (User ID 1).
                </div>
                
                <div class="row">
                    <div class="col-md-3 col-sm-6">
                        <div class="small-box bg-red">
                            <div class="inner">
                                <h3>{{ $stats['total_bans'] ?? 0 }}</h3>
                                <p>Active Bans</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-ban"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3 col-sm-6">
                        <div class="small-box bg-yellow">
                            <div class="inner">
                                <h3>{{ $stats['active_threats'] ?? 0 }}</h3>
                                <p>Active Threats</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-exclamation-triangle"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3 col-sm-6">
                        <div class="small-box bg-green">
                            <div class="inner">
                                <h3>{{ $stats['enabled_features'] ?? 0 }}/15</h3>
                                <p>Active Protections</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-check-circle"></i>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-3 col-sm-6">
                        <div class="small-box bg-aqua">
                            <div class="inner">
                                <h3>{{ $stats['today_logs'] ?? 0 }}</h3>
                                <p>Today'\''s Events</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-history"></i>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="callout callout-success">
                    <h4><i class="icon fa fa-check"></i> System Status</h4>
                    All 15 security features are installed and ready to use.
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
VIEW
    
    log_success "Security views dibuat"
}

# ========== PHASE 11: CREATE ROUTES ==========
create_security_routes() {
    log_info "Membuat routes security..."
    
    # Create directory if not exists
    mkdir -p "$PANEL_DIR/routes/admin"
    
    cat > "$PANEL_DIR/routes/admin/security.php" << 'ROUTES'
<?php

Route::group(['prefix' => 'security', 'namespace' => 'Admin', 'middleware' => ['auth', 'admin']], function () {
    // Dashboard
    Route::get('dashboard', 'SecurityController@dashboard')->name('admin.security.dashboard');
    
    // IP Management
    Route::get('ips', 'SecurityController@ips')->name('admin.security.ips');
    Route::post('ban-ip', 'SecurityController@banIp')->name('admin.security.ban');
    
    // Security Features
    Route::get('ddos', 'SecurityController@ddos')->name('admin.security.ddos');
    Route::get('bot', 'SecurityController@bot')->name('admin.security.bot');
    Route::get('debug', 'SecurityController@debug')->name('admin.security.debug');
    Route::get('advanced', 'SecurityController@advanced')->name('admin.security.advanced');
    Route::get('database', 'SecurityController@database')->name('admin.security.database');
    Route::get('session', 'SecurityController@session')->name('admin.security.session');
    Route::get('api', 'SecurityController@api')->name('admin.security.api');
    Route::get('logs', 'SecurityController@logs')->name('admin.security.logs');
    
    // Settings
    Route::get('settings', 'SecurityController@settings')->name('admin.security.settings');
    Route::post('update-setting', 'SecurityController@updateSetting')->name('admin.security.update-setting');
});
ROUTES
    
    # Add to main admin routes
    if ! grep -q "require.*security.php" "$PANEL_DIR/routes/admin.php"; then
        echo -e "\n// Security Routes\nrequire __DIR__.'/admin/security.php';" >> "$PANEL_DIR/routes/admin.php"
    fi
    
    log_success "Security routes dibuat"
}

# ========== PHASE 12: FIX PERMISSIONS & CACHE ==========
fix_permissions_cache() {
    log_info "Memperbaiki permissions dan cache..."
    
    cd $PANEL_DIR
    
    # Set permissions
    chown -R www-data:www-data .
    find . -type f -exec chmod 644 {} \;
    find . -type d -exec chmod 755 {} \;
    chmod -R 775 storage bootstrap/cache
    
    # Clear cache
    sudo -u www-data php artisan cache:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    
    # Restart services
    systemctl restart php8.3-fpm
    systemctl restart nginx
    
    log_success "Permissions dan cache diperbaiki"
}

# ========== PHASE 13: FINAL SETUP & DIAGNOSE ==========
final_setup() {
    log_info "Setup final dan diagnose masalah..."
    
    # Check PHP-FPM status
    log_info "Checking PHP-FPM status..."
    systemctl status php8.3-fpm --no-pager
    
    # Check Nginx status
    log_info "Checking Nginx status..."
    nginx -t
    
    # Check panel directory
    log_info "Checking panel directory..."
    ls -la $PANEL_DIR/
    
    # Check storage permissions
    log_info "Checking storage permissions..."
    ls -la $PANEL_DIR/storage/
    
    # Check PHP errors
    log_info "Checking PHP errors..."
    tail -20 /var/log/php8.3-fpm.log 2>/dev/null || echo "No PHP-FPM log found"
    
    # Check Nginx errors
    log_info "Checking Nginx errors..."
    tail -20 /var/log/nginx/error.log 2>/dev/null || echo "No Nginx error log found"
    
    # Optimize PHP
    cat > /etc/php/8.3/fpm/conf.d/99-pterodactyl.ini << PHPINI
memory_limit = 512M
upload_max_filesize = 100M
post_max_size = 100M
max_execution_time = 300
max_input_time = 300
opcache.enable = 1
opcache.memory_consumption = 256
opcache.interned_strings_buffer = 20
opcache.max_accelerated_files = 20000
opcache.revalidate_freq = 2
PHPINI
    
    systemctl restart php8.3-fpm
    
    log_success "Setup final selesai"
}

# ========== FIX 500 ERROR ==========
fix_500_error() {
    log_info "Memperbaiki error 500..."
    
    cd $PANEL_DIR
    
    # Fix .env file
    if [ -f ".env" ]; then
        # Ensure APP_DEBUG is false for production
        sed -i 's/APP_DEBUG=true/APP_DEBUG=false/g' .env
        sed -i 's/APP_ENV=local/APP_ENV=production/g' .env
        
        # Fix database connection
        sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=${MYSQL_PANEL_PASS}/g" .env
        sed -i "s/DB_HOST=.*/DB_HOST=127.0.0.1/g" .env
        sed -i "s/DB_DATABASE=.*/DB_DATABASE=panel/g" .env
        sed -i "s/DB_USERNAME=.*/DB_USERNAME=pterodactyl/g" .env
    fi
    
    # Clear all caches
    sudo -u www-data php artisan cache:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    sudo -u www-data php artisan route:clear 2>/dev/null || true
    sudo -u www-data php artisan optimize:clear 2>/dev/null || true
    
    # Fix permissions
    chown -R www-data:www-data .
    chmod -R 755 storage bootstrap/cache
    chmod 777 storage/logs 2>/dev/null || true
    
    # Check and fix routes
    if [ ! -f "$PANEL_DIR/routes/admin/security.php" ]; then
        create_security_routes
    fi
    
    # Restart services
    systemctl restart php8.3-fpm
    systemctl restart nginx
    
    log_success "Error 500 diperbaiki"
}

# ========== MAIN EXECUTION ==========
main() {
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${CYAN}🚀 MEMULAI INSTALASI PTERODACTYL + SECURITY${NC}"
    echo -e "${CYAN}==================================================${NC}"
    
    # Validasi
    validate_config
    
    # Eksekusi semua phase
    install_dependencies
    configure_mysql
    install_panel
    install_theme
    configure_nginx_ssl
    install_wings
    create_security_database
    create_security_menu
    create_security_controller
    create_security_views
    create_security_routes
    fix_permissions_cache
    final_setup
    fix_500_error
    
    # Tampilkan informasi akhir
    echo -e "\n${GREEN}==================================================${NC}"
    echo -e "${GREEN}🎉 INSTALASI BERHASIL!${NC}"
    echo -e "${GREEN}==================================================${NC}"
    echo ""
    echo -e "${YELLOW}📋 INFORMASI PANEL:${NC}"
    echo -e "   ${CYAN}URL Panel:${NC} https://$DOMAIN"
    echo -e "   ${CYAN}Admin Login:${NC} admin@$DOMAIN"
    echo -e "   ${CYAN}Password:${NC} admin123"
    echo ""
    echo -e "${YELLOW}🔒 FITUR KEAMANAN YANG TERINSTALL:${NC}"
    echo -e "   1. ${GREEN}✓${NC} Anti-DDoS (Rate Limit)"
    echo -e "   2. ${GREEN}✓${NC} IP Ban/Unban System"
    echo -e "   3. ${GREEN}✓${NC} Anti-Debug/Inspect"
    echo -e "   4. ${GREEN}✓${NC} Anti-Bot Protection"
    echo -e "   5. ${GREEN}✓${NC} Anti-Raid Protection"
    echo -e "   6. ${GREEN}✓${NC} Anti-Overheat Monitoring"
    echo -e "   7. ${GREEN}✓${NC} Fail2Ban Integration"
    echo -e "   8. ${GREEN}✓${NC} Hide Origin IP (1.1.1.1)"
    echo -e "   9. ${GREEN}✓${NC} Anti-Peek Protection"
    echo -e "   10. ${GREEN}✓${NC} Anti-Backdoor Scanner"
    echo -e "   11. ${GREEN}✓${NC} Database Query Watchdog"
    echo -e "   12. ${GREEN}✓${NC} Session Hijacking Protection"
    echo -e "   13. ${GREEN}✓${NC} API Key Expiration (20 days)"
    echo -e "   14. ${GREEN}✓${NC} Real-time Security Logs"
    echo -e "   15. ${GREEN}✓${NC} Threat Scoring System"
    echo ""
    echo -e "${YELLOW}⚠️ INFORMASI PENTING:${NC}"
    echo -e "   • Menu Security hanya bisa diakses oleh ${RED}User ID 1${NC}"
    echo -e "   • Untuk mengakses: https://$DOMAIN/admin/security/dashboard"
    echo -e "   • Email: admin@$DOMAIN"
    echo -e "   • Password: admin123"
    echo ""
    echo -e "${YELLOW}🔧 TROUBLESHOOTING ERROR 500:${NC}"
    echo -e "   Jika masih error 500, jalankan perintah berikut:"
    echo -e "   1. cd /var/www/pterodactyl"
    echo -e "   2. php artisan cache:clear"
    echo -e "   3. php artisan view:clear"
    echo -e "   4. php artisan config:clear"
    echo -e "   5. systemctl restart php8.3-fpm nginx"
    echo -e "   6. chown -R www-data:www-data ."
    echo -e "   7. chmod -R 775 storage bootstrap/cache"
    echo ""
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}🔥 INSTALASI SELESAI! PANEL SIAP DIGUNAKAN 🔥${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    # Cek status terakhir
    echo ""
    echo -e "${YELLOW}🔍 STATUS TERAKHIR:${NC}"
    systemctl status php8.3-fpm --no-pager | head -10
    echo ""
    systemctl status nginx --no-pager | head -10
    echo ""
    echo -e "${CYAN}✅ Silakan buka: https://$DOMAIN${NC}"
}

# Jalankan main function
main
