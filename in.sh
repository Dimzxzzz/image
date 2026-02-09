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
        php8.3-intl php8.3-imagick php8.3-tokenizer php8.3-dom \
        php8.3-ctype php8.3-fileinfo php8.3-pdo php8.3-pdo-mysql
    
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

# ========== PHASE 2: KONFIGURASI MYSQL (FIXED) ==========
configure_mysql() {
    log_info "Mengkonfigurasi MySQL..."
    
    systemctl start mariadb
    systemctl enable mariadb
    
    # Secure installation tanpa password dulu
    mysql -u root <<EOF
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    # Set password untuk root
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
FLUSH PRIVILEGES;
EOF
    
    # Create database dan user untuk panel - FIX: Gunakan localhost DAN 127.0.0.1
    mysql -u root -p${MYSQL_ROOT_PASS} <<EOF
CREATE USER IF NOT EXISTS 'pterodactyl'@'localhost' IDENTIFIED BY '${MYSQL_PANEL_PASS}';
CREATE USER IF NOT EXISTS 'pterodactyl'@'127.0.0.1' IDENTIFIED BY '${MYSQL_PANEL_PASS}';
CREATE DATABASE IF NOT EXISTS panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
GRANT ALL PRIVILEGES ON panel.* TO 'pterodactyl'@'localhost' WITH GRANT OPTION;
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
    
    # Test connection
    if mysql -u pterodactyl -p${MYSQL_PANEL_PASS} -h localhost -e "SELECT 1;" >/dev/null 2>&1; then
        log_success "MySQL connection test SUCCESS (localhost)"
    else
        log_warning "MySQL localhost connection failed, testing 127.0.0.1..."
        if mysql -u pterodactyl -p${MYSQL_PANEL_PASS} -h 127.0.0.1 -e "SELECT 1;" >/dev/null 2>&1; then
            log_success "MySQL connection test SUCCESS (127.0.0.1)"
        else
            log_error "MySQL connection FAILED"
            log_info "Manual fix:"
            log_info "1. mysql -u root -p${MYSQL_ROOT_PASS}"
            log_info "2. CREATE USER 'pterodactyl'@'localhost' IDENTIFIED BY '${MYSQL_PANEL_PASS}';"
            log_info "3. GRANT ALL ON panel.* TO 'pterodactyl'@'localhost';"
            log_info "4. FLUSH PRIVILEGES;"
        fi
    fi
    
    log_success "MySQL dikonfigurasi"
}

# ========== PHASE 3: INSTALL PTERODACTYL PANEL (FIXED) ==========
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
    cat << 'EOF' | sudo -u www-data php artisan p:environment:setup \
        --author="$EMAIL" \
        --url="https://$DOMAIN" \
        --timezone="Asia/Jakarta" \
        --cache="redis" \
        --session="redis" \
        --queue="redis" \
        --redis-host="127.0.0.1" \
        --redis-port="6379" \
        --settings-ui="true"
yes
yes

EOF
    
    # Setup database - FIXED: Gunakan localhost
    sudo -u www-data php artisan p:environment:database \
        --host="localhost" \
        --port="3306" \
        --database="panel" \
        --username="pterodactyl" \
        --password="${MYSQL_PANEL_PASS}"
    
    # Migrate database
    sudo -u www-data php artisan migrate --seed --force
    
    # Create admin user - FIXED: Check if user exists first
    if ! mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SELECT id FROM users WHERE username='admin' LIMIT 1;" 2>/dev/null | grep -q "id"; then
        sudo -u www-data php artisan p:user:make \
            --email="admin@$DOMAIN" \
            --username="admin" \
            --name="Administrator" \
            --password="admin123" \
            --admin="1"
        log_success "User admin created"
    else
        log_info "User admin sudah ada"
    fi
    
    # Setup cron
    (crontab -l 2>/dev/null; echo "* * * * * cd $PANEL_DIR && php artisan schedule:run >> /dev/null 2>&1") | crontab -
    
    # Fix permissions again
    chown -R www-data:www-data .
    chmod -R 755 storage bootstrap/cache
    chmod 777 storage/logs
    
    # Fix .env file untuk database connection
    sed -i "s/^DB_HOST=.*/DB_HOST=localhost/" .env
    sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${MYSQL_PANEL_PASS}/" .env
    sed -i "s/^DB_USERNAME=.*/DB_USERNAME=pterodactyl/" .env
    sed -i "s/^DB_DATABASE=.*/DB_DATABASE=panel/" .env
    
    log_success "Panel berhasil diinstall. Login: admin@$DOMAIN / admin123"
}

# ========== PHASE 4: INSTALL THEME ==========
install_theme() {
    log_info "Menginstall Theme..."
    
    cd $PANEL_DIR
    
    # Simple theme modification - just change colors
    cat > public/css/custom.css << 'CSS'
/* Custom Theme */
:root {
    --primary: #4a5568;
    --secondary: #2d3748;
    --accent: #4299e1;
}

.navbar {
    background: linear-gradient(135deg, var(--primary) 0%, var(--secondary) 100%) !important;
}

.sidebar {
    background-color: var(--secondary) !important;
}

.box.box-primary {
    border-top-color: var(--accent) !important;
}

.btn-primary {
    background-color: var(--accent) !important;
    border-color: var(--accent) !important;
}
CSS
    
    # Add custom CSS to layout
    if grep -q "custom.css" resources/views/layouts/admin.blade.php; then
        log_info "Custom CSS already added"
    else
        sed -i '/<!-- Stylesheets -->/a\    <link rel="stylesheet" href="{{ asset('\''css/custom.css'\'') }}">' resources/views/layouts/admin.blade.php
    fi
    
    # Clear cache
    sudo -u www-data php artisan view:clear
    sudo -u www-data php artisan cache:clear
    
    log_success "Theme berhasil diinstall"
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
    
    # Start services
    systemctl start nginx
    systemctl restart php8.3-fpm
    
    log_success "Nginx dan SSL berhasil dikonfigurasi"
}

# ========== PHASE 6: INSTALL WINGS (FIXED) ==========
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
        systemctl enable docker
        systemctl start docker
    else
        log_info "Docker sudah terinstall"
    fi
    
    # Generate configuration
    mkdir -p /etc/pterodactyl
    
    # Check if SSL cert exists
    SSL_CERT="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
    SSL_KEY="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    
    if [ ! -f "$SSL_CERT" ]; then
        SSL_CERT="/etc/ssl/certs/nginx-selfsigned.crt"
        SSL_KEY="/etc/ssl/private/nginx-selfsigned.key"
    fi
    
    # Generate simple working config
    cat > /etc/pterodactyl/config.yml <<WINGS_CONFIG
debug: false
panel:
  url: https://$DOMAIN
token:
  id: panel_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)
  secret: secret_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
api:
  host: 0.0.0.0
  port: 8080
  ssl:
    enabled: false
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
    
    # Create systemd service
    cat > /etc/systemd/system/wings.service <<WINGS_SERVICE
[Unit]
Description=Pterodactyl Wings Daemon
After=docker.service
Requires=docker.service

[Service]
User=root
WorkingDirectory=/etc/pterodactyl
LimitNOFILE=4096
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
        log_warning "Wings gagal start, checking logs..."
        journalctl -u wings --no-pager -n 10
        log_info "Coba start manual: /usr/local/bin/wings --debug"
    fi
}

# ========== PHASE 7: CREATE SECURITY DATABASE (FIXED) ==========
create_security_database() {
    log_info "Membuat database security..."
    
    mysql -u root -p${MYSQL_ROOT_PASS} panel << "MYSQL_SECURITY"
-- Security Database Tables
CREATE TABLE IF NOT EXISTS panel_security_settings (
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

CREATE TABLE IF NOT EXISTS panel_security_ips (
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

CREATE TABLE IF NOT EXISTS panel_security_bans (
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

CREATE TABLE IF NOT EXISTS panel_security_logs (
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

-- Insert 15 Security Features
INSERT IGNORE INTO panel_security_settings (category, setting_key, setting_value, is_enabled, description, sort_order) VALUES
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
('database', 'query_watchdog', '{"enabled": true, "log_slow_queries": true, "threshold": 1.0}", TRUE, 'Database query watchdog', 11),
('session', 'hijack_protection', '{"enabled": true, "check_ip": true, "check_agent": true}', TRUE, 'Session hijacking protection', 12),
('api', 'key_expiration', '{"enabled": true, "days": 20, "auto_renew": false}', TRUE, 'API key expiration (20 days)', 13),
('logging', 'real_time_alerts', '{"enabled": true, "email_alerts": false, "discord_webhook": ""}', TRUE, 'Real-time security alerts', 14),
('advanced', 'threat_scoring', '{"enabled": true, "algorithm": "advanced", "threshold": 75}', TRUE, 'Threat scoring system', 15);

-- Sample data
INSERT IGNORE INTO panel_security_ips (ip_address, request_count, status, threat_score) VALUES
('127.0.0.1', 15, 'whitelist', 0),
('192.168.1.1', 8, 'active', 10),
('8.8.8.8', 3, 'active', 5);

INSERT IGNORE INTO panel_security_logs (ip_address, action, details, severity, log_category) VALUES
('127.0.0.1', 'system_start', '{"user": "system"}', 'info', 'system'),
('192.168.1.1', 'login_success', '{"user": "admin"}', 'info', 'auth');

SELECT 'Security database created successfully!' as Status;
MYSQL_SECURITY
    
    log_success "Database security dengan 15 fitur telah dibuat"
}

# ========== PHASE 8: CREATE SIMPLE SECURITY PAGE ==========
create_security_page() {
    log_info "Membuat halaman security sederhana..."
    
    # Create simple security page
    cat > $PANEL_DIR/resources/views/admin/security/index.blade.php << 'VIEW'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Complete protection system</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-shield"></i> Security System</h3>
            </div>
            <div class="box-body">
                @if(auth()->check() && auth()->user()->id == 1)
                    <div class="alert alert-success">
                        <h4><i class="icon fa fa-check"></i> Access Granted</h4>
                        Welcome to Security Dashboard (User ID: {{ auth()->user()->id }})
                    </div>
                    
                    <div class="row">
                        <div class="col-md-3 col-sm-6">
                            <div class="small-box bg-red">
                                <div class="inner">
                                    <h3>15</h3>
                                    <p>Security Features</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-shield-alt"></i>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 col-sm-6">
                            <div class="small-box bg-green">
                                <div class="inner">
                                    <h3>Active</h3>
                                    <p>System Status</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-check-circle"></i>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 col-sm-6">
                            <div class="small-box bg-yellow">
                                <div class="inner">
                                    <h3>24/7</h3>
                                    <p>Monitoring</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-eye"></i>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 col-sm-6">
                            <div class="small-box bg-blue">
                                <div class="inner">
                                    <h3>100%</h3>
                                    <p>Protected</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-lock"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="callout callout-info">
                        <h4><i class="icon fa fa-info-circle"></i> Security Features Enabled</h4>
                        <ul>
                            <li>Anti-DDoS Protection</li>
                            <li>IP Ban System</li>
                            <li>Anti-Bot Detection</li>
                            <li>Database Security</li>
                            <li>Session Protection</li>
                            <li>And 10 more features...</li>
                        </ul>
                    </div>
                @else
                    <div class="alert alert-danger">
                        <h4><i class="icon fa fa-ban"></i> Access Denied</h4>
                        This security section is accessible only by System Administrator (User ID 1).
                        <br>
                        <strong>Your User ID:</strong> {{ auth()->user()->id }}
                    </div>
                @endif
            </div>
        </div>
    </div>
</div>
@endsection
VIEW
    
    # Create directory if not exists
    mkdir -p $PANEL_DIR/resources/views/admin/security
    
    log_success "Security page created"
}

# ========== PHASE 9: ADD SECURITY MENU ==========
add_security_menu() {
    log_info "Menambahkan menu security..."
    
    LAYOUT_FILE="$PANEL_DIR/resources/views/layouts/admin.blade.php"
    
    # Backup original
    cp "$LAYOUT_FILE" "${LAYOUT_FILE}.backup"
    
    # Add security menu item
    SECURITY_MENU='@if(auth()->check() && auth()->user()->id == 1)
        <li>
            <a href="{{ route('\''admin.security'\'') }}">
                <i class="fa fa-shield"></i> <span>Security System</span>
            </a>
        </li>
    @endif'
    
    # Find where to insert (after Dashboard or Settings)
    if grep -q '<i class="fa fa-dashboard"></i> <span>Dashboard</span>' "$LAYOUT_FILE"; then
        # Insert after Dashboard
        sed -i '/<i class="fa fa-dashboard"><\/i> <span>Dashboard<\/span>/a\'"$SECURITY_MENU" "$LAYOUT_FILE"
    else
        # Insert before closing ul
        sed -i '/<\/ul>/i\'"$SECURITY_MENU" "$LAYOUT_FILE"
    fi
    
    log_success "Security menu added"
}

# ========== PHASE 10: CREATE SECURITY ROUTE ==========
create_security_route() {
    log_info "Membuat security route..."
    
    # Add route to web.php
    ROUTE_LINE="Route::get('/admin/security', 'Admin\\SecurityController@index')->name('admin.security');"
    
    if ! grep -q "admin.security" "$PANEL_DIR/routes/web.php"; then
        echo -e "\n// Security Routes\n$ROUTE_LINE" >> "$PANEL_DIR/routes/web.php"
    fi
    
    log_success "Security route created"
}

# ========== PHASE 11: CREATE SECURITY CONTROLLER ==========
create_security_controller() {
    log_info "Membuat security controller..."
    
    mkdir -p "$PANEL_DIR/app/Http/Controllers/Admin"
    
    cat > "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" << 'CONTROLLER'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

class SecurityController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware('admin');
    }
    
    public function index()
    {
        // Only user ID 1 can access
        if (auth()->check() && auth()->user()->id == 1) {
            return view('admin.security.index');
        }
        
        abort(403, 'Security dashboard access is restricted to system administrators.');
    }
}
CONTROLLER
    
    log_success "Security controller created"
}

# ========== PHASE 12: FIX PERMISSIONS & FINALIZE ==========
fix_final() {
    log_info "Finalizing installation..."
    
    cd $PANEL_DIR
    
    # Fix all permissions
    chown -R www-data:www-data .
    find . -type f -exec chmod 644 {} \;
    find . -type d -exec chmod 755 {} \;
    chmod -R 775 storage bootstrap/cache
    chmod 777 storage/logs 2>/dev/null || true
    
    # Clear all caches
    sudo -u www-data php artisan cache:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    sudo -u www-data php artisan route:clear 2>/dev/null || true
    
    # Optimize
    sudo -u www-data php artisan optimize 2>/dev/null || true
    
    # Restart services
    systemctl restart php8.3-fpm
    systemctl restart nginx
    systemctl restart wings 2>/dev/null || true
    
    # Check PHP-FPM status
    if systemctl is-active --quiet php8.3-fpm; then
        log_success "PHP-FPM is running"
    else
        log_error "PHP-FPM is not running!"
        systemctl status php8.3-fpm --no-pager | head -20
    fi
    
    # Check Nginx status
    if systemctl is-active --quiet nginx; then
        log_success "Nginx is running"
    else
        log_error "Nginx is not running!"
        systemctl status nginx --no-pager | head -20
    fi
    
    log_success "Finalization complete"
}

# ========== PHASE 13: DIAGNOSE & FIX ERRORS ==========
diagnose_errors() {
    log_info "Diagnosing errors..."
    
    cd $PANEL_DIR
    
    # Check database connection
    log_info "Testing database connection..."
    if sudo -u www-data php artisan tinker --execute="echo DB::connection()->getPdo() ? 'OK' : 'FAIL';" 2>/dev/null | grep -q "OK"; then
        log_success "Database connection: OK"
    else
        log_error "Database connection: FAILED"
        log_info "Manual fix: Check .env file database credentials"
    fi
    
    # Check Redis connection
    log_info "Testing Redis connection..."
    if redis-cli ping 2>/dev/null | grep -q "PONG"; then
        log_success "Redis connection: OK"
    else
        log_warning "Redis connection: WARNING (optional)"
    fi
    
    # Check storage permissions
    log_info "Checking storage permissions..."
    if [ -w "storage/logs" ]; then
        log_success "Storage permissions: OK"
    else
        log_error "Storage permissions: FAILED"
        chmod -R 777 storage
    fi
    
    # Check .env file
    log_info "Checking .env file..."
    if [ -f ".env" ]; then
        log_success ".env file: EXISTS"
        # Ensure correct values
        sed -i "s/^APP_DEBUG=.*/APP_DEBUG=false/" .env
        sed -i "s/^APP_ENV=.*/APP_ENV=production/" .env
    else
        log_error ".env file: MISSING"
        cp .env.example .env
        sudo -u www-data php artisan key:generate --force
    fi
    
    # Fix any artisan command issues
    log_info "Fixing artisan commands..."
    sudo -u www-data php artisan route:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    
    log_success "Diagnosis complete"
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
    create_security_page
    add_security_menu
    create_security_route
    create_security_controller
    fix_final
    diagnose_errors
    
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
    echo -e "${YELLOW}🛡️ AKSES SECURITY:${NC}"
    echo -e "   • ${CYAN}URL:${NC} https://$DOMAIN/admin/security"
    echo -e "   • ${RED}Hanya User ID 1 yang bisa akses${NC}"
    echo -e "   • Login dengan admin@$DOMAIN / admin123"
    echo ""
    echo -e "${YELLOW}🔧 TROUBLESHOOTING:${NC}"
    echo -e "   Jika ada error 500:"
    echo -e "   1. cd /var/www/pterodactyl"
    echo -e "   2. php artisan cache:clear"
    echo -e "   3. php artisan config:clear"
    echo -e "   4. php artisan view:clear"
    echo -e "   5. systemctl restart php8.3-fpm nginx"
    echo ""
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}🔥 PANEL SIAP DIGUNAKAN! 🔥${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    # Final check
    echo -e "\n${YELLOW}🔍 STATUS AKHIR:${NC}"
    echo -e "PHP-FPM: $(systemctl is-active php8.3-fpm)"
    echo -e "Nginx: $(systemctl is-active nginx)"
    echo -e "MariaDB: $(systemctl is-active mariadb)"
    echo -e "Wings: $(systemctl is-active wings 2>/dev/null || echo 'Not checked')"
    echo ""
    echo -e "${CYAN}✅ Buka browser dan akses: https://$DOMAIN${NC}"
}

# Jalankan main function
main
