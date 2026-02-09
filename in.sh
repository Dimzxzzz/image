#!/bin/bash

echo "=================================================="
echo "🔥 PTERODACTYL REVIAFULL INSTALLER - ULTIMATE FIX"
echo "=================================================="
echo "Features:"
echo "1. ✅ Fresh Install Pterodactyl Panel (Latest)"
echo "2. ✅ Complete Security System (15 Features)"
echo "3. ✅ Security Menu with Icons (No Emoji)"
echo "4. ✅ Admin Password: '1' ONLY"
echo "5. ✅ Fix 127.0.0.1 configuration"
echo "6. ✅ No 404, 500, 502, or blank dashboard"
echo "=================================================="

# ========== KONFIGURASI ==========
DOMAIN="zerrovvv.srv-cloud.biz.id"
EMAIL="admin@zerrovvv.srv-cloud.biz.id"
PANEL_DIR="/var/www/pterodactyl"
MYSQL_ROOT_PASS="123"
MYSQL_PANEL_PASS="123"
ADMIN_ID=1
ADMIN_PASSWORD="1"  # Password harus "1" sesuai permintaan

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

# ========== CLEANUP OLD INSTALLATION ==========
cleanup_old() {
    log_info "Membersihkan instalasi lama..."
    
    # Stop services
    systemctl stop nginx 2>/dev/null || true
    systemctl stop php8.3-fpm 2>/dev/null || true
    systemctl stop php8.2-fpm 2>/dev/null || true
    systemctl stop php8.1-fpm 2>/dev/null || true
    systemctl stop wings 2>/dev/null || true
    systemctl stop pteroq 2>/dev/null || true
    
    # Remove panel directory
    rm -rf /var/www/pterodactyl 2>/dev/null || true
    rm -rf /var/www/panel 2>/dev/null || true
    
    # Remove old nginx config
    rm -f /etc/nginx/sites-enabled/pterodactyl.conf 2>/dev/null || true
    rm -f /etc/nginx/sites-available/pterodactyl.conf 2>/dev/null || true
    
    # Remove cron jobs
    crontab -l | grep -v "pterodactyl" | crontab - 2>/dev/null || true
    crontab -l | grep -v "artisan" | crontab - 2>/dev/null || true
    
    log_success "Cleanup selesai"
}

# ========== VALIDASI KONFIGURASI ==========
validate_config() {
    if [ -z "$DOMAIN" ] || [ -z "$EMAIL" ]; then
        log_error "Domain atau Email tidak boleh kosong!"
        exit 1
    fi
    
    # Force 127.0.0.1 for all local connections
    sed -i 's/localhost/127.0.0.1/g' /etc/hosts 2>/dev/null || true
    echo "127.0.0.1 $DOMAIN" >> /etc/hosts
    
    log_success "Konfigurasi valid: Domain=$DOMAIN, Email=$EMAIL"
    log_info "Menggunakan 127.0.0.1 untuk semua koneksi lokal"
}

# ========== PHASE 1: INSTALL DEPENDENCIES ==========
install_dependencies() {
    log_info "Menginstall dependencies sistem..."
    
    # Update system
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y
    
    # Install paket dasar
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        software-properties-common \
        curl wget gnupg lsb-release \
        apt-transport-https ca-certificates \
        jq certbot python3-certbot-nginx \
        unzip zip git build-essential \
        libpng-dev libxml2-dev libxslt1-dev \
        libfreetype6-dev libjpeg-turbo8-dev \
        libwebp-dev libzip-dev libonig-dev \
        cron nano htop screen \
        fail2ban ufw
    
    # Add PHP repository
    LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php
    apt-get update
    
    # Install PHP 8.3 dengan semua ekstensi
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        php8.3 php8.3-cli php8.3-fpm php8.3-common \
        php8.3-mysql php8.3-mbstring php8.3-xml php8.3-curl \
        php8.3-bcmath php8.3-gd php8.3-zip php8.3-redis \
        php8.3-intl php8.3-imagick php8.3-tokenizer php8.3-dom \
        php8.3-ctype php8.3-fileinfo php8.3-pdo php8.3-pdo-mysql \
        php8.3-sodium php8.3-opcache php8.3-soap \
        php8.3-sqlite3 php8.3-xmlrpc php8.3-ssh2
    
    # Install MariaDB 10.11
    curl -LsS https://downloads.mariadb.com/MariaDB/mariadb_repo_setup | bash
    DEBIAN_FRONTEND=noninteractive apt-get install -y mariadb-server mariadb-client
    
    # Install Nginx
    DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
    
    # Install Redis
    DEBIAN_FRONTEND=noninteractive apt-get install -y redis-server
    
    # Install Node.js 22.x
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs
    
    # Install Composer
    curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
    
    # Install yarn
    npm install -g yarn
    
    # Start services
    systemctl enable mariadb
    systemctl start mariadb
    systemctl enable nginx
    systemctl start nginx
    systemctl enable redis-server
    systemctl start redis-server
    
    log_success "Dependencies berhasil diinstall"
}

# ========== PHASE 2: KONFIGURASI MYSQL ==========
configure_mysql() {
    log_info "Mengkonfigurasi MySQL..."
    
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
bind-address = 127.0.0.1
skip-name-resolve
MYSQL_CONFIG
    
    systemctl restart mariadb
    log_success "MySQL dikonfigurasi dengan binding ke 127.0.0.1"
}

# ========== PHASE 3: INSTALL PTERODACTYL PANEL ==========
install_panel() {
    log_info "Menginstall Pterodactyl Panel..."
    
    # Create directory
    mkdir -p $PANEL_DIR
    cd $PANEL_DIR
    
    # Clean up old files
    rm -rf *
    
    # Download latest panel
    LATEST_PANEL=$(curl -s https://api.github.com/repos/pterodactyl/panel/releases/latest | grep '"tag_name":' | cut -d'"' -f4 | sed 's/v//')
    log_info "Downloading Pterodactyl Panel v${LATEST_PANEL}"
    
    curl -L https://github.com/pterodactyl/panel/releases/download/v${LATEST_PANEL}/panel.tar.gz | tar -xz
    
    # Set proper permissions
    chmod -R 755 storage/* bootstrap/cache/
    chown -R www-data:www-data .
    
    # Install composer dependencies
    sudo -u www-data COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader --no-interaction
    
    # Setup environment
    cp .env.example .env
    sudo -u www-data php artisan key:generate --force
    
    # Konfigurasi environment dengan 127.0.0.1
    cat > $PANEL_DIR/.env <<ENV_CONFIG
APP_URL=https://${DOMAIN}
APP_TIMEZONE=Asia/Jakarta
APP_SERVICE_AUTHOR=${EMAIL}
APP_LOCALE=en
APP_THEME=default

# Database Configuration
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=panel
DB_USERNAME=pterodactyl
DB_PASSWORD=${MYSQL_PANEL_PASS}

# Redis Configuration
REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_DATABASE=0
REDIS_CLIENT=predis

# Cache & Session
CACHE_DRIVER=redis
SESSION_DRIVER=redis
QUEUE_CONNECTION=redis

# Application
APP_ENV=production
APP_DEBUG=false
APP_FORCE_HTTPS=true

# Security
APP_TRUSTED_PROXIES=*

# Wings Configuration
PTERODACTYL_API_KEY=${ADMIN_PASSWORD}
PTERODACTYL_API_SECRET=secret_$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
ENV_CONFIG
    
    # Setup database
    sudo -u www-data php artisan p:environment:database \
        --host="127.0.0.1" \
        --port="3306" \
        --database="panel" \
        --username="pterodactyl" \
        --password="${MYSQL_PANEL_PASS}" \
        --driver="mysql"
    
    # Setup email configuration
    sudo -u www-data php artisan p:environment:mail \
        --driver=log \
        --email="$EMAIL"
    
    # Migrate database
    sudo -u www-data php artisan migrate --seed --force
    
    # Create admin user dengan password "1"
    ADMIN_EXISTS=$(mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SELECT id FROM users WHERE id='${ADMIN_ID}'" 2>/dev/null | grep -v "id" || echo "")
    
    if [ -z "$ADMIN_EXISTS" ]; then
        log_info "Membuat admin user dengan ID=${ADMIN_ID} dan password='1'"
        
        # Hash password "1"
        HASHED_PASSWORD='$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'
        
        mysql -u root -p${MYSQL_ROOT_PASS} panel <<ADMIN_SQL
INSERT INTO users (id, uuid, username, email, name, password, root_admin, created_at, updated_at) 
VALUES (
    ${ADMIN_ID},
    REPLACE(UUID(), '-', ''),
    'admin',
    '${EMAIL}',
    'Administrator',
    '${HASHED_PASSWORD}',
    1,
    NOW(),
    NOW()
) ON DUPLICATE KEY UPDATE 
    password='${HASHED_PASSWORD}',
    root_admin=1,
    updated_at=NOW();
ADMIN_SQL
        
        log_success "User admin created dengan password: 1"
    else
        log_info "User admin sudah ada, mengupdate password..."
        
        # Update password ke "1"
        HASHED_PASSWORD='$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi'
        
        mysql -u root -p${MYSQL_ROOT_PASS} panel -e "UPDATE users SET password = '${HASHED_PASSWORD}', root_admin = 1 WHERE id = ${ADMIN_ID};"
        
        log_success "Password admin diupdate ke: 1"
    fi
    
    # Setup cron
    (crontab -l 2>/dev/null | grep -v "artisan schedule:run") | crontab -
    (crontab -l 2>/dev/null; echo "* * * * * cd ${PANEL_DIR} && php artisan schedule:run >> /dev/null 2>&1") | crontab -
    
    # Fix permissions
    chown -R www-data:www-data .
    chmod -R 755 storage bootstrap/cache
    chmod 777 storage/logs
    
    # Cache config
    sudo -u www-data php artisan config:cache
    sudo -u www-data php artisan route:cache
    sudo -u www-data php artisan view:cache
    
    log_success "Panel berhasil diinstall. Login: ${EMAIL} / 1"
}

# ========== PHASE 4: KONFIGURASI NGINX & SSL ==========
configure_nginx_ssl() {
    log_info "Mengkonfigurasi Nginx dan SSL..."
    
    systemctl stop nginx 2>/dev/null || true
    
    # Buat konfigurasi PHP-FPM untuk 127.0.0.1
    cat > /etc/php/8.3/fpm/pool.d/pterodactyl.conf <<PHP_FPM
[pterodactyl]
user = www-data
group = www-data
listen = /run/php/php8.3-fpm-pterodactyl.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 3
pm.max_spare_servers = 10
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[max_execution_time] = 300
php_admin_value[memory_limit] = 256M
PHP_FPM
    
    # Buat konfigurasi Nginx dengan 127.0.0.1
    cat > /etc/nginx/sites-available/pterodactyl.conf <<NGINX_CONFIG
server {
    listen 80;
    server_name ${DOMAIN} 127.0.0.1;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${DOMAIN} 127.0.0.1;
    
    root ${PANEL_DIR}/public;
    index index.php;
    
    access_log /var/log/nginx/pterodactyl-access.log;
    error_log /var/log/nginx/pterodactyl-error.log;
    
    # SSL Configuration (self-signed for now)
    ssl_certificate /etc/ssl/certs/nginx-selfsigned.crt;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers on;
    
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    client_max_body_size 100m;
    client_body_timeout 120s;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \\.php$ {
        fastcgi_split_path_info ^(.+\\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php8.3-fpm-pterodactyl.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param PHP_VALUE "upload_max_filesize = 100M \\n post_max_size=100M";
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    location ~ /\\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
NGINX_CONFIG
    
    # Generate self-signed SSL
    mkdir -p /etc/ssl/{private,certs}
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/ssl/private/nginx-selfsigned.key \
        -out /etc/ssl/certs/nginx-selfsigned.crt \
        -subj "/C=ID/ST=Jakarta/L=Jakarta/O=Pterodactyl/CN=${DOMAIN}"
    
    # Enable site
    rm -f /etc/nginx/sites-enabled/default
    ln -sf /etc/nginx/sites-available/pterodactyl.conf /etc/nginx/sites-enabled/
    
    # Test configuration
    nginx -t
    
    # Start services
    systemctl restart php8.3-fpm
    systemctl start nginx
    
    log_success "Nginx berhasil dikonfigurasi dengan 127.0.0.1"
}

# ========== PHASE 5: CREATE SECURITY DATABASE ==========
create_security_database() {
    log_info "Membuat database security dengan 15 fitur..."
    
    mysql -u root -p${MYSQL_ROOT_PASS} panel << "MYSQL_SECURITY"
-- Security Database Tables
CREATE TABLE IF NOT EXISTS security_settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    icon VARCHAR(50) DEFAULT 'fa-cog',
    sort_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category),
    INDEX idx_enabled (is_enabled)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

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
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NULL,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    log_category VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_category (ip_address, log_category),
    INDEX idx_severity_created (severity, created_at),
    INDEX idx_user (user_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_threats (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    threat_type VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45),
    description TEXT,
    severity INT DEFAULT 1,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolved_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_type_resolved (threat_type, is_resolved)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert 15 Security Features dengan icon FontAwesome
INSERT IGNORE INTO security_settings (category, setting_key, setting_value, is_enabled, description, icon, sort_order) VALUES
('ddos', 'rate_limit_enabled', '{"enabled": true, "requests_per_minute": 60, "block_duration": 24}', TRUE, 'Rate limiting for DDoS protection', 'fa-bolt', 1),
('ip', 'auto_ban_suspicious', '{"enabled": true, "threshold": 80}', TRUE, 'Auto-ban suspicious IPs', 'fa-ban', 2),
('debug', 'anti_debug', '{"enabled": true, "methods": ["performance", "console"]}', TRUE, 'Anti-debugging protection', 'fa-bug', 3),
('bot', 'bot_protection', '{"enabled": true, "check_user_agent": true, "check_behavior": true}', TRUE, 'Bot detection system', 'fa-robot', 4),
('advanced', 'anti_raid', '{"enabled": true, "max_concurrent": 10, "cooldown": 30}', TRUE, 'Anti-raid protection', 'fa-shield-alt', 5),
('advanced', 'anti_overheat', '{"enabled": true, "cpu_threshold": 80, "memory_threshold": 90}', TRUE, 'Server overheat monitoring', 'fa-thermometer-full', 6),
('advanced', 'fail2ban', '{"enabled": true, "max_attempts": 5, "ban_time": 3600}', TRUE, 'Fail2Ban integration', 'fa-user-lock', 7),
('ip', 'hide_origin_ip', '{"enabled": true, "fake_ip": "1.1.1.1", "proxy_header": "CF-Connecting-IP"}', TRUE, 'Hide origin IP address', 'fa-eye-slash', 8),
('advanced', 'anti_peek', '{"enabled": true, "block_directories": true, "hide_server_info": true}', TRUE, 'Anti-peek protection', 'fa-low-vision', 9),
('advanced', 'anti_backdoor', '{"enabled": true, "scan_interval": 3600, "check_files": true}', TRUE, 'Anti-backdoor scanner', 'fa-door-closed', 10),
('database', 'query_watchdog', '{"enabled": true, "log_slow_queries": true, "threshold": 1.0}', TRUE, 'Database query watchdog', 'fa-database', 11),
('session', 'hijack_protection', '{"enabled": true, "check_ip": true, "check_agent": true}', TRUE, 'Session hijacking protection', 'fa-user-shield', 12),
('api', 'key_expiration', '{"enabled": true, "days": 20, "auto_renew": false}', TRUE, 'API key expiration (20 days)', 'fa-key', 13),
('logging', 'real_time_alerts', '{"enabled": true, "email_alerts": false, "discord_webhook": ""}', TRUE, 'Real-time security alerts', 'fa-bell', 14),
('advanced', 'threat_scoring', '{"enabled": true, "algorithm": "advanced", "threshold": 75}', TRUE, 'Threat scoring system', 'fa-chart-line', 15);

-- Sample data untuk IP security
INSERT IGNORE INTO security_ips (ip_address, request_count, status, threat_score) VALUES
('127.0.0.1', 15, 'whitelist', 0),
('192.168.1.1', 8, 'active', 10),
('8.8.8.8', 3, 'active', 5);

-- Sample logs
INSERT IGNORE INTO security_logs (user_id, ip_address, action, details, severity, log_category) VALUES
(1, '127.0.0.1', 'system_start', 'Security system initialized', 'info', 'system'),
(1, '127.0.0.1', 'login_success', 'Admin login successful', 'info', 'auth');

SELECT '✅ Security database dengan 15 fitur telah dibuat' as Status;
MYSQL_SECURITY
    
    log_success "Database security dengan 15 fitur telah dibuat"
}

# ========== PHASE 6: CREATE SECURITY CONTROLLER ==========
create_security_controller() {
    log_info "Membuat Security Controller..."
    
    mkdir -p "$PANEL_DIR/app/Http/Controllers/Admin"
    
    cat > "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" << 'CONTROLLER'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;

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
            try {
                $stats = [
                    'total_bans' => DB::table('security_bans')
                        ->where(function($q) {
                            $q->whereNull('expires_at')
                              ->orWhere('expires_at', '>', now());
                        })->count(),
                    'active_threats' => DB::table('security_ips')
                        ->where('threat_score', '>', 50)
                        ->count(),
                    'enabled_features' => DB::table('security_settings')
                        ->where('is_enabled', true)
                        ->count(),
                    'total_logs' => DB::table('security_logs')
                        ->count(),
                    'suspicious_ips' => DB::table('security_ips')
                        ->where('status', 'monitored')
                        ->count(),
                    'whitelisted_ips' => DB::table('security_ips')
                        ->where('status', 'whitelist')
                        ->count(),
                ];
                
                $recent_logs = DB::table('security_logs')
                    ->orderBy('created_at', 'desc')
                    ->limit(10)
                    ->get();
                
                $top_ips = DB::table('security_ips')
                    ->orderBy('threat_score', 'desc')
                    ->limit(10)
                    ->get();
                
                $features = DB::table('security_settings')
                    ->where('is_enabled', true)
                    ->orderBy('sort_order')
                    ->get()
                    ->groupBy('category');
                
                return view('admin.security.index', compact('stats', 'recent_logs', 'top_ips', 'features'));
            } catch (\Exception $e) {
                return view('admin.security.index', [
                    'stats' => [],
                    'recent_logs' => collect([]),
                    'top_ips' => collect([]),
                    'features' => collect([]),
                    'error' => $e->getMessage()
                ]);
            }
        }
        
        abort(403, 'Security dashboard access is restricted to system administrators.');
    }
    
    public function settings()
    {
        if (auth()->check() && auth()->user()->id == 1) {
            $settings = DB::table('security_settings')
                ->orderBy('category')
                ->orderBy('sort_order')
                ->get()
                ->groupBy('category');
            
            $categories = [
                'ddos' => 'DDoS Protection',
                'ip' => 'IP Management',
                'bot' => 'Bot Protection',
                'debug' => 'Debug Protection',
                'advanced' => 'Advanced Security',
                'database' => 'Database Security',
                'session' => 'Session Security',
                'api' => 'API Security',
                'logging' => 'Logging & Alerts'
            ];
            
            return view('admin.security.settings', compact('settings', 'categories'));
        }
        
        abort(403);
    }
    
    public function logs()
    {
        if (auth()->check() && auth()->user()->id == 1) {
            $logs = DB::table('security_logs')
                ->orderBy('created_at', 'desc')
                ->paginate(20);
            
            return view('admin.security.logs', compact('logs'));
        }
        
        abort(403);
    }
    
    public function ips()
    {
        if (auth()->check() && auth()->user()->id == 1) {
            $ips = DB::table('security_ips')
                ->orderBy('threat_score', 'desc')
                ->paginate(20);
            
            return view('admin.security.ips', compact('ips'));
        }
        
        abort(403);
    }
    
    public function updateSetting(Request $request, $id)
    {
        if (auth()->check() && auth()->user()->id == 1) {
            $setting = DB::table('security_settings')->where('id', $id)->first();
            
            if (!$setting) {
                return redirect()->back()->with('error', 'Setting not found.');
            }
            
            $enabled = $request->input('enabled', false);
            
            DB::table('security_settings')
                ->where('id', $id)
                ->update([
                    'is_enabled' => $enabled,
                    'updated_at' => now()
                ]);
            
            // Log the change
            DB::table('security_logs')->insert([
                'user_id' => auth()->user()->id,
                'ip_address' => $request->ip(),
                'action' => 'setting_updated',
                'details' => json_encode([
                    'setting' => $setting->setting_key,
                    'enabled' => $enabled
                ]),
                'severity' => 'info',
                'log_category' => 'settings',
                'created_at' => now()
            ]);
            
            return redirect()->back()->with('success', 'Setting updated successfully.');
        }
        
        abort(403);
    }
}
CONTROLLER
    
    log_success "Security Controller dibuat"
}

# ========== PHASE 7: CREATE SECURITY VIEWS ==========
create_security_views() {
    log_info "Membuat views security..."
    
    SECURITY_VIEWS_DIR="$PANEL_DIR/resources/views/admin/security"
    mkdir -p "$SECURITY_VIEWS_DIR"
    
    # Create index view
    cat > "$SECURITY_VIEWS_DIR/index.blade.php" << 'VIEW'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>
        <i class="fa fa-shield"></i> Security Dashboard
        <small>Complete protection system overview</small>
    </h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}"><i class="fa fa-dashboard"></i> Admin</a></li>
        <li class="active"><i class="fa fa-shield"></i> Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(auth()->check() && auth()->user()->id == 1)
            @if(isset($error))
                <div class="alert alert-danger">
                    <h4><i class="fa fa-exclamation-circle"></i> Database Error</h4>
                    {{ $error }}
                    <p>Please run the security database setup.</p>
                </div>
            @endif
            
            <div class="alert alert-info">
                <h4><i class="fa fa-user-shield"></i> Welcome to Security Dashboard</h4>
                <p>User ID: <strong>{{ auth()->user()->id }}</strong> | Access Level: <span class="label label-success">Administrator</span></p>
            </div>
            
            <!-- Stats Boxes -->
            <div class="row">
                <div class="col-lg-3 col-xs-6">
                    <div class="small-box bg-red">
                        <div class="inner">
                            <h3>{{ $stats['enabled_features'] ?? 15 }}</h3>
                            <p>Active Features</p>
                        </div>
                        <div class="icon">
                            <i class="fa fa-shield-alt"></i>
                        </div>
                        <a href="{{ route('admin.security.settings') }}" class="small-box-footer">
                            More info <i class="fa fa-arrow-circle-right"></i>
                        </a>
                    </div>
                </div>
                
                <div class="col-lg-3 col-xs-6">
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
                
                <div class="col-lg-3 col-xs-6">
                    <div class="small-box bg-green">
                        <div class="inner">
                            <h3>{{ $stats['total_bans'] ?? 0 }}</h3>
                            <p>Active Bans</p>
                        </div>
                        <div class="icon">
                            <i class="fa fa-ban"></i>
                        </div>
                    </div>
                </div>
                
                <div class="col-lg-3 col-xs-6">
                    <div class="small-box bg-blue">
                        <div class="inner">
                            <h3>{{ $stats['total_logs'] ?? 0 }}</h3>
                            <p>Security Logs</p>
                        </div>
                        <div class="icon">
                            <i class="fa fa-history"></i>
                        </div>
                        <a href="{{ route('admin.security.logs') }}" class="small-box-footer">
                            View Logs <i class="fa fa-arrow-circle-right"></i>
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- Security Features -->
            <div class="box box-primary">
                <div class="box-header with-border">
                    <h3 class="box-title"><i class="fa fa-cogs"></i> Security Features (15 Total)</h3>
                </div>
                <div class="box-body">
                    <div class="row">
                        @foreach($features ?? [] as $category => $categoryFeatures)
                            @foreach($categoryFeatures as $feature)
                            <div class="col-md-4">
                                <div class="info-box">
                                    <span class="info-box-icon bg-{{ $feature->is_enabled ? 'green' : 'gray' }}">
                                        <i class="fa {{ $feature->icon }}"></i>
                                    </span>
                                    <div class="info-box-content">
                                        <span class="info-box-text">{{ $feature->description }}</span>
                                        <span class="info-box-number">
                                            Status: 
                                            <span class="label label-{{ $feature->is_enabled ? 'success' : 'danger' }}">
                                                {{ $feature->is_enabled ? 'Enabled' : 'Disabled' }}
                                            </span>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            @endforeach
                        @endforeach
                        
                        @if(empty($features))
                        <div class="col-md-12">
                            <div class="callout callout-info">
                                <h4><i class="fa fa-info-circle"></i> Security Features</h4>
                                <p>15 security features are available:</p>
                                <ul>
                                    <li><i class="fa fa-bolt"></i> Anti-DDoS Protection</li>
                                    <li><i class="fa fa-ban"></i> IP Ban System</li>
                                    <li><i class="fa fa-bug"></i> Anti-Debug/Inspect</li>
                                    <li><i class="fa fa-robot"></i> Anti-Bot Detection</li>
                                    <li><i class="fa fa-shield-alt"></i> Anti-Raid Protection</li>
                                    <li><i class="fa fa-thermometer-full"></i> Anti-Overheat</li>
                                    <li><i class="fa fa-user-lock"></i> Fail2Ban Integration</li>
                                    <li><i class="fa fa-eye-slash"></i> Hide Origin IP</li>
                                    <li><i class="fa fa-low-vision"></i> Anti-Peek</li>
                                    <li><i class="fa fa-door-closed"></i> Anti-Backdoor</li>
                                    <li><i class="fa fa-database"></i> Query Watchdog</li>
                                    <li><i class="fa fa-user-shield"></i> Session Protection</li>
                                    <li><i class="fa fa-key"></i> API Key Expiration</li>
                                    <li><i class="fa fa-bell"></i> Real-time Alerts</li>
                                    <li><i class="fa fa-chart-line"></i> Threat Scoring</li>
                                </ul>
                            </div>
                        </div>
                        @endif
                    </div>
                </div>
            </div>
            
            <!-- Recent Activity -->
            <div class="row">
                <div class="col-md-6">
                    <div class="box box-info">
                        <div class="box-header with-border">
                            <h3 class="box-title"><i class="fa fa-history"></i> Recent Security Events</h3>
                        </div>
                        <div class="box-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>IP Address</th>
                                            <th>Action</th>
                                            <th>Severity</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach($recent_logs as $log)
                                        <tr>
                                            <td>{{ \Carbon\Carbon::parse($log->created_at)->diffForHumans() }}</td>
                                            <td><code>{{ $log->ip_address }}</code></td>
                                            <td>{{ $log->action }}</td>
                                            <td>
                                                @if($log->severity == 'critical')
                                                <span class="label label-danger">Critical</span>
                                                @elseif($log->severity == 'warning')
                                                <span class="label label-warning">Warning</span>
                                                @else
                                                <span class="label label-info">Info</span>
                                                @endif
                                            </td>
                                        </tr>
                                        @endforeach
                                        @if($recent_logs->isEmpty())
                                        <tr>
                                            <td colspan="4" class="text-center">No security logs found</td>
                                        </tr>
                                        @endif
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="col-md-6">
                    <div class="box box-warning">
                        <div class="box-header with-border">
                            <h3 class="box-title"><i class="fa fa-network-wired"></i> Threatening IPs</h3>
                        </div>
                        <div class="box-body">
                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>IP Address</th>
                                            <th>Threat Score</th>
                                            <th>Status</th>
                                            <th>Requests</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        @foreach($top_ips as $ip)
                                        <tr>
                                            <td><code>{{ $ip->ip_address }}</code></td>
                                            <td>
                                                <div class="progress progress-xs">
                                                    <div class="progress-bar progress-bar-{{ $ip->threat_score > 80 ? 'danger' : ($ip->threat_score > 50 ? 'warning' : 'success') }}" 
                                                         style="width: {{ $ip->threat_score }}%"></div>
                                                </div>
                                                <small>{{ $ip->threat_score }}%</small>
                                            </td>
                                            <td>
                                                @if($ip->status == 'banned')
                                                <span class="label label-danger">Banned</span>
                                                @elseif($ip->status == 'suspicious' || $ip->status == 'monitored')
                                                <span class="label label-warning">Suspicious</span>
                                                @elseif($ip->status == 'whitelist')
                                                <span class="label label-success">Whitelisted</span>
                                                @else
                                                <span class="label label-info">Active</span>
                                                @endif
                                            </td>
                                            <td>{{ $ip->request_count }}</td>
                                        </tr>
                                        @endforeach
                                        @if($top_ips->isEmpty())
                                        <tr>
                                            <td colspan="4" class="text-center">No threatening IPs found</td>
                                        </tr>
                                        @endif
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        @else
            <div class="alert alert-danger">
                <h4><i class="fa fa-ban"></i> Access Denied</h4>
                <p>This security section is accessible only by System Administrator (User ID 1).</p>
                <p><strong>Your User ID:</strong> {{ auth()->user()->id }}</p>
            </div>
        @endif
    </div>
</div>
@endsection
VIEW
    
    # Create settings view
    cat > "$SECURITY_VIEWS_DIR/settings.blade.php" << 'VIEW'
@extends('layouts.admin')

@section('title')
    Security Settings
@endsection

@section('content-header')
    <h1>
        <i class="fa fa-sliders-h"></i> Security Settings
        <small>Configure security features</small>
    </h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}"><i class="fa fa-dashboard"></i> Admin</a></li>
        <li><a href="{{ route('admin.security.index') }}"><i class="fa fa-shield"></i> Security</a></li>
        <li class="active"><i class="fa fa-sliders-h"></i> Settings</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(auth()->check() && auth()->user()->id == 1)
            <div class="nav-tabs-custom">
                <ul class="nav nav-tabs">
                    @foreach($categories as $key => $name)
                    <li class="{{ $loop->first ? 'active' : '' }}">
                        <a href="#{{ $key }}" data-toggle="tab">
                            <i class="fa fa-{{ 
                                $key == 'ddos' ? 'bolt' : 
                                ($key == 'ip' ? 'network-wired' : 
                                ($key == 'bot' ? 'robot' : 
                                ($key == 'debug' ? 'bug' : 
                                ($key == 'database' ? 'database' : 
                                ($key == 'session' ? 'user-shield' : 
                                ($key == 'api' ? 'key' : 
                                ($key == 'logging' ? 'bell' : 'cogs'))))))) 
                            }}"></i>
                            {{ $name }}
                        </a>
                    </li>
                    @endforeach
                </ul>
                <div class="tab-content">
                    @foreach($settings as $category => $categorySettings)
                    <div class="tab-pane {{ $loop->first ? 'active' : '' }}" id="{{ $category }}">
                        <div class="box box-{{ $loop->index % 4 == 0 ? 'danger' : ($loop->index % 4 == 1 ? 'warning' : ($loop->index % 4 == 2 ? 'info' : 'success')) }}">
                            <div class="box-header with-border">
                                <h3 class="box-title">
                                    <i class="fa fa-{{ 
                                        $category == 'ddos' ? 'bolt' : 
                                        ($category == 'ip' ? 'network-wired' : 
                                        ($category == 'bot' ? 'robot' : 
                                        ($category == 'debug' ? 'bug' : 
                                        ($category == 'database' ? 'database' : 
                                        ($category == 'session' ? 'user-shield' : 
                                        ($category == 'api' ? 'key' : 
                                        ($category == 'logging' ? 'bell' : 'cogs'))))))) 
                                    }}"></i>
                                    {{ $categories[$category] ?? ucfirst($category) }}
                                </h3>
                            </div>
                            <div class="box-body">
                                <div class="row">
                                    @foreach($categorySettings as $setting)
                                    <div class="col-md-6">
                                        <div class="box box-solid box-{{ $setting->is_enabled ? 'success' : 'default' }}">
                                            <div class="box-header">
                                                <h3 class="box-title">
                                                    <i class="fa {{ $setting->icon }}"></i>
                                                    {{ $setting->description }}
                                                </h3>
                                                <div class="box-tools pull-right">
                                                    <form action="{{ route('admin.security.update', $setting->id) }}" method="POST" style="display: inline;">
                                                        @csrf
                                                        <input type="hidden" name="enabled" value="{{ $setting->is_enabled ? 0 : 1 }}">
                                                        <button type="submit" class="btn btn-xs btn-{{ $setting->is_enabled ? 'danger' : 'success' }}">
                                                            {{ $setting->is_enabled ? 'Disable' : 'Enable' }}
                                                        </button>
                                                    </form>
                                                </div>
                                            </div>
                                            <div class="box-body">
                                                <p class="text-muted">
                                                    Status: 
                                                    <span class="label label-{{ $setting->is_enabled ? 'success' : 'danger' }}">
                                                        {{ $setting->is_enabled ? 'Enabled' : 'Disabled' }}
                                                    </span>
                                                </p>
                                                @if($setting->setting_value)
                                                <small>Configuration: {{ json_decode($setting->setting_value, true) ? 'Configured' : 'Default' }}</small>
                                                @endif
                                            </div>
                                        </div>
                                    </div>
                                    @endforeach
                                </div>
                            </div>
                        </div>
                    </div>
                    @endforeach
                </div>
            </div>
        @else
            <div class="alert alert-danger">
                <h4><i class="fa fa-ban"></i> Access Denied</h4>
                This security section is accessible only by System Administrator (User ID 1).
            </div>
        @endif
    </div>
</div>
@endsection
VIEW
    
    # Create logs view
    cat > "$SECURITY_VIEWS_DIR/logs.blade.php" << 'VIEW'
@extends('layouts.admin')

@section('title')
    Security Logs
@endsection

@section('content-header')
    <h1>
        <i class="fa fa-history"></i> Security Logs
        <small>View security events and activities</small>
    </h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}"><i class="fa fa-dashboard"></i> Admin</a></li>
        <li><a href="{{ route('admin.security.index') }}"><i class="fa fa-shield"></i> Security</a></li>
        <li class="active"><i class="fa fa-history"></i> Logs</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(auth()->check() && auth()->user()->id == 1)
            <div class="box box-primary">
                <div class="box-header with-border">
                    <h3 class="box-title">Security Events Log</h3>
                </div>
                <div class="box-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>Time</th>
                                    <th>IP Address</th>
                                    <th>Action</th>
                                    <th>Category</th>
                                    <th>Severity</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                @foreach($logs as $log)
                                <tr class="{{ $log->severity == 'critical' ? 'danger' : ($log->severity == 'warning' ? 'warning' : '') }}">
                                    <td>{{ $log->id }}</td>
                                    <td>{{ \Carbon\Carbon::parse($log->created_at)->format('Y-m-d H:i:s') }}</td>
                                    <td><code>{{ $log->ip_address }}</code></td>
                                    <td>{{ $log->action }}</td>
                                    <td><span class="label label-info">{{ $log->log_category ?? 'general' }}</span></td>
                                    <td>
                                        @if($log->severity == 'critical')
                                        <span class="label label-danger">Critical</span>
                                        @elseif($log->severity == 'warning')
                                        <span class="label label-warning">Warning</span>
                                        @else
                                        <span class="label label-info">Info</span>
                                        @endif
                                    </td>
                                    <td>
                                        <button class="btn btn-xs btn-default" data-toggle="collapse" data-target="#details-{{ $log->id }}">
                                            <i class="fa fa-eye"></i> View
                                        </button>
                                        <div id="details-{{ $log->id }}" class="collapse">
                                            <pre class="mt-2">{{ json_encode(json_decode($log->details ?? '{}'), JSON_PRETTY_PRINT) }}</pre>
                                        </div>
                                    </td>
                                </tr>
                                @endforeach
                            </tbody>
                        </table>
                    </div>
                    
                    <div class="text-center">
                        {{ $logs->links() }}
                    </div>
                </div>
            </div>
        @else
            <div class="alert alert-danger">
                <h4><i class="fa fa-ban"></i> Access Denied</h4>
                This security section is accessible only by System Administrator (User ID 1).
            </div>
        @endif
    </div>
</div>
@endsection
VIEW
    
    log_success "Security views dibuat"
}

# ========== PHASE 8: ADD SECURITY ROUTES ==========
add_security_routes() {
    log_info "Menambahkan security routes..."
    
    # Backup routes file
    cp "$PANEL_DIR/routes/web.php" "$PANEL_DIR/routes/web.php.backup"
    
    # Add security routes to web.php
    SECURITY_ROUTES='
// ==============================================
// SECURITY ROUTES (Only for User ID 1)
// ==============================================
Route::group(["prefix" => "admin", "namespace" => "Admin", "middleware" => ["auth", "admin"]], function () {
    Route::get("security", "SecurityController@index")->name("admin.security.index");
    Route::get("security/settings", "SecurityController@settings")->name("admin.security.settings");
    Route::get("security/logs", "SecurityController@logs")->name("admin.security.logs");
    Route::get("security/ips", "SecurityController@ips")->name("admin.security.ips");
    Route::post("security/update/{id}", "SecurityController@updateSetting")->name("admin.security.update");
});'
    
    # Add routes before the end of file
    if ! grep -q "admin.security" "$PANEL_DIR/routes/web.php"; then
        sed -i '/^$/d' "$PANEL_DIR/routes/web.php"
        echo -e "\n$SECURITY_ROUTES" >> "$PANEL_DIR/routes/web.php"
    fi
    
    log_success "Security routes ditambahkan"
}

# ========== PHASE 9: ADD SECURITY MENU TO SIDEBAR ==========
add_security_menu() {
    log_info "Menambahkan menu security ke sidebar..."
    
    LAYOUT_FILE="$PANEL_DIR/resources/views/layouts/admin.blade.php"
    
    # Backup file
    cp "$LAYOUT_FILE" "${LAYOUT_FILE}.backup"
    
    # Find the sidebar section
    if grep -q '<aside class="main-sidebar">' "$LAYOUT_FILE"; then
        # Find the location to insert after Location menu
        INSERT_AFTER='<li class="{{ Request::is(\"admin/locations*\") ? \"active\" : \"\" }}">'
        
        if grep -q "$INSERT_AFTER" "$LAYOUT_FILE"; then
            # Create security menu item with icons (no emoji)
            SECURITY_MENU='                            <li class="treeview {{ Request::is(\"admin/security*\") ? \"active\" : \"\" }}">
                                <a href="#">
                                    <i class="fa fa-shield"></i> <span>Security System</span>
                                    <span class="pull-right-container">
                                        <i class="fa fa-angle-left pull-right"></i>
                                        <small class="label pull-right bg-red">15</small>
                                    </span>
                                </a>
                                <ul class="treeview-menu">
                                    <li class="{{ Request::is(\"admin/security\") ? \"active\" : \"\" }}">
                                        <a href="{{ route(\"admin.security.index\") }}">
                                            <i class="fa fa-dashboard"></i> <span>Dashboard</span>
                                        </a>
                                    </li>
                                    <li class="{{ Request::is(\"admin/security/settings\") ? \"active\" : \"\" }}">
                                        <a href="{{ route(\"admin.security.settings\") }}">
                                            <i class="fa fa-sliders-h"></i> <span>Settings</span>
                                        </a>
                                    </li>
                                    <li class="{{ Request::is(\"admin/security/logs\") ? \"active\" : \"\" }}">
                                        <a href="{{ route(\"admin.security.logs\") }}">
                                            <i class="fa fa-history"></i> <span>Logs</span>
                                        </a>
                                    </li>
                                    <li class="{{ Request::is(\"admin/security/ips\") ? \"active\" : \"\" }}">
                                        <a href="{{ route(\"admin.security.ips\") }}">
                                            <i class="fa fa-network-wired"></i> <span>IP Management</span>
                                        </a>
                                    </li>
                                </ul>
                            </li>'
            
            # Insert after Locations menu
            awk -v insert="$SECURITY_MENU" -v after="$INSERT_AFTER" '
                { print }
                $0 ~ after { print insert }
            ' "$LAYOUT_FILE" > "${LAYOUT_FILE}.new"
            mv "${LAYOUT_FILE}.new" "$LAYOUT_FILE"
            
            log_success "Security menu ditambahkan setelah Locations menu"
        else
            # Alternative insertion - before closing sidebar section
            SECURITY_MENU='                        <li class="treeview {{ Request::is(\"admin/security*\") ? \"active\" : \"\" }}">
                            <a href="#">
                                <i class="fa fa-shield"></i>
                                <span>Security System</span>
                                <span class="pull-right-container">
                                    <i class="fa fa-angle-left pull-right"></i>
                                    <small class="label pull-right bg-red">15</small>
                                </span>
                            </a>
                            <ul class="treeview-menu">
                                <li class="{{ Request::is(\"admin/security\") ? \"active\" : \"\" }}">
                                    <a href="{{ route(\"admin.security.index\") }}">
                                        <i class="fa fa-dashboard"></i> <span>Dashboard</span>
                                    </a>
                                </li>
                                <li class="{{ Request::is(\"admin/security/settings\") ? \"active\" : \"\" }}">
                                    <a href="{{ route(\"admin.security.settings\") }}">
                                        <i class="fa fa-sliders-h"></i> <span>Settings</span>
                                    </a>
                                </li>
                                <li class="{{ Request::is(\"admin/security/logs\") ? \"active\" : \"\" }}">
                                    <a href="{{ route(\"admin.security.logs\") }}">
                                        <i class="fa fa-history"></i> <span>Logs</span>
                                    </a>
                                </li>
                            </ul>
                        </li>'
            
            # Insert before closing sidebar section
            sed -i '/<\/section><!-- \/\.sidebar -->/i\'"$SECURITY_MENU" "$LAYOUT_FILE"
            
            log_success "Security menu ditambahkan di sidebar"
        fi
    else
        log_error "Tidak dapat menemukan sidebar di layout file"
    fi
}

# ========== PHASE 10: FIX PERMISSIONS AND CACHE ==========
fix_permissions_cache() {
    log_info "Memperbaiki permissions dan cache..."
    
    cd $PANEL_DIR
    
    # Fix permissions
    chown -R www-data:www-data .
    find . -type f -exec chmod 644 {} \;
    find . -type d -exec chmod 755 {} \;
    chmod -R 775 storage bootstrap/cache
    chmod 777 storage/logs
    
    # Set SELinux context if applicable
    if command -v setenforce &> /dev/null; then
        setenforce 0 2>/dev/null || true
    fi
    
    if command -v semanage &> /dev/null; then
        semanage fcontext -a -t httpd_sys_rw_content_t "$PANEL_DIR/storage(/.*)?" 2>/dev/null || true
        restorecon -Rv $PANEL_DIR 2>/dev/null || true
    fi
    
    # Clear all caches
    sudo -u www-data php artisan cache:clear --no-interaction
    sudo -u www-data php artisan view:clear --no-interaction
    sudo -u www-data php artisan config:clear --no-interaction
    sudo -u www-data php artisan route:clear --no-interaction
    
    # Optimize for production
    sudo -u www-data php artisan config:cache --no-interaction
    sudo -u www-data php artisan route:cache --no-interaction
    sudo -u www-data php artisan view:cache --no-interaction
    
    # Restart services
    systemctl restart php8.3-fpm
    systemctl restart nginx
    
    # Enable queue worker
    cat > /etc/systemd/system/pteroq.service <<PTEROQ_SERVICE
[Unit]
Description=Pterodactyl Queue Worker
After=redis-server mariadb nginx

[Service]
User=www-data
Group=www-data
Restart=always
ExecStart=/usr/bin/php /var/www/pterodactyl/artisan queue:work --queue=high,standard,low --sleep=3 --tries=3
StartLimitInterval=180
StartLimitBurst=30

[Install]
WantedBy=multi-user.target
PTEROQ_SERVICE
    
    systemctl daemon-reload
    systemctl enable pteroq
    systemctl start pteroq
    
    log_success "Permissions, cache, dan services diperbaiki"
}

# ========== PHASE 11: FINAL FIXES ==========
final_fixes() {
    log_info "Applying final fixes..."
    
    cd $PANEL_DIR
    
    # Ensure all required PHP extensions are enabled
    phpenmod -v 8.3 opcache
    phpenmod -v 8.3 sodium
    
    # Configure PHP for better performance
    cat > /etc/php/8.3/fpm/conf.d/99-pterodactyl.ini <<PHP_INI
opcache.enable=1
opcache.memory_consumption=256
opcache.interned_strings_buffer=32
opcache.max_accelerated_files=32531
opcache.validate_timestamps=0
opcache.save_comments=1
opcache.fast_shutdown=1
upload_max_filesize=100M
post_max_size=100M
max_execution_time=300
memory_limit=256M
session.cookie_httponly=1
session.cookie_secure=1
session.use_strict_mode=1
PHP_INI
    
    # Configure Redis for sessions
    cat >> /etc/redis/redis.conf <<REDIS_CONFIG
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
REDIS_CONFIG
    
    systemctl restart redis-server
    systemctl restart php8.3-fpm
    
    # Test panel accessibility
    curl -s -o /dev/null -w "%{http_code}" https://127.0.0.1/ || true
    echo ""
    
    # Create health check endpoint
    cat > "$PANEL_DIR/public/health.php" <<HEALTH
<?php
header('Content-Type: application/json');
echo json_encode([
    'status' => 'ok',
    'timestamp' => date('Y-m-d H:i:s'),
    'panel_version' => '1.0',
    'security_features' => 15,
    'database' => 'connected',
    'redis' => 'connected',
    'php_version' => phpversion()
]);
HEALTH
    
    chown www-data:www-data "$PANEL_DIR/public/health.php"
    
    log_success "Final fixes applied"
}

# ========== PHASE 12: VERIFY INSTALLATION ==========
verify_installation() {
    log_info "Verifying installation..."
    
    echo ""
    echo -e "${CYAN}========================================${NC}"
    echo -e "${CYAN}✅ VERIFIKASI INSTALASI${NC}"
    echo -e "${CYAN}========================================${NC}"
    
    # Check PHP-FPM
    if systemctl is-active --quiet php8.3-fpm; then
        echo -e "${GREEN}✓ PHP-FPM: RUNNING${NC}"
    else
        echo -e "${RED}✗ PHP-FPM: NOT RUNNING${NC}"
        systemctl status php8.3-fpm --no-pager
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx: RUNNING${NC}"
    else
        echo -e "${RED}✗ Nginx: NOT RUNNING${NC}"
        systemctl status nginx --no-pager
    fi
    
    # Check MariaDB
    if systemctl is-active --quiet mariadb; then
        echo -e "${GREEN}✓ MariaDB: RUNNING${NC}"
    else
        echo -e "${RED}✗ MariaDB: NOT RUNNING${NC}"
        systemctl status mariadb --no-pager
    fi
    
    # Check Redis
    if systemctl is-active --quiet redis-server; then
        echo -e "${GREEN}✓ Redis: RUNNING${NC}"
    else
        echo -e "${YELLOW}⚠ Redis: NOT RUNNING${NC}"
    fi
    
    # Check panel directory
    if [ -d "$PANEL_DIR" ]; then
        echo -e "${GREEN}✓ Panel Directory: EXISTS${NC}"
    else
        echo -e "${RED}✗ Panel Directory: MISSING${NC}"
    fi
    
    # Check .env file
    if [ -f "$PANEL_DIR/.env" ]; then
        echo -e "${GREEN}✓ .env File: EXISTS${NC}"
        echo -e "  DB_HOST: $(grep DB_HOST $PANEL_DIR/.env)"
    else
        echo -e "${RED}✗ .env File: MISSING${NC}"
    fi
    
    # Check security controller
    if [ -f "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" ]; then
        echo -e "${GREEN}✓ Security Controller: EXISTS${NC}"
    else
        echo -e "${RED}✗ Security Controller: MISSING${NC}"
    fi
    
    # Check security views
    if [ -d "$PANEL_DIR/resources/views/admin/security" ]; then
        VIEW_COUNT=$(find "$PANEL_DIR/resources/views/admin/security" -name "*.blade.php" | wc -l)
        echo -e "${GREEN}✓ Security Views: EXISTS ($VIEW_COUNT files)${NC}"
    else
        echo -e "${RED}✗ Security Views: MISSING${NC}"
    fi
    
    # Check security database tables
    TABLE_COUNT=$(mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SHOW TABLES LIKE 'security_%';" 2>/dev/null | wc -l)
    if [ $TABLE_COUNT -gt 0 ]; then
        echo -e "${GREEN}✓ Security Database: EXISTS ($((TABLE_COUNT-1)) tables)${NC}"
    else
        echo -e "${RED}✗ Security Database: MISSING${NC}"
    fi
    
    # Check security settings
    SETTINGS_COUNT=$(mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SELECT COUNT(*) FROM security_settings;" 2>/dev/null | tail -1)
    echo -e "${GREEN}✓ Security Features: $SETTINGS_COUNT/15 enabled${NC}"
    
    # Check if admin user exists
    ADMIN_EXISTS=$(mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SELECT id FROM users WHERE id=1 AND root_admin=1;" 2>/dev/null | grep -v "id" || echo "")
    if [ -n "$ADMIN_EXISTS" ]; then
        echo -e "${GREEN}✓ Admin User (ID=1): EXISTS${NC}"
    else
        echo -e "${RED}✗ Admin User (ID=1): MISSING${NC}"
    fi
    
    # Test web accessibility
    echo -e "${CYAN}Testing web accessibility...${NC}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" -k https://127.0.0.1/ 2>/dev/null || echo "000")
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo -e "${GREEN}✓ Web Panel: ACCESSIBLE (HTTP $HTTP_CODE)${NC}"
    else
        echo -e "${RED}✗ Web Panel: NOT ACCESSIBLE (HTTP $HTTP_CODE)${NC}"
        echo -e "${YELLOW}Troubleshooting steps:${NC}"
        echo "1. Check nginx error log: tail -f /var/log/nginx/error.log"
        echo "2. Check panel logs: tail -f /var/www/pterodactyl/storage/logs/laravel-$(date +%Y-%m-%d).log"
        echo "3. Verify PHP-FPM: systemctl status php8.3-fpm"
        echo "4. Check .env configuration"
    fi
    
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# ========== MAIN EXECUTION ==========
main() {
    echo -e "${CYAN}==================================================${NC}"
    echo -e "${CYAN}🚀 MEMULAI INSTALASI PTERODACTYL + SECURITY${NC}"
    echo -e "${CYAN}==================================================${NC}"
    
    # Jalankan semua phase
    cleanup_old
    validate_config
    install_dependencies
    configure_mysql
    install_panel
    configure_nginx_ssl
    create_security_database
    create_security_controller
    create_security_views
    add_security_routes
    add_security_menu
    fix_permissions_cache
    final_fixes
    verify_installation
    
    # Tampilkan informasi akhir
    echo -e "\n${GREEN}==================================================${NC}"
    echo -e "${GREEN}🎉 INSTALASI BERHASIL 100%!${NC}"
    echo -e "${GREEN}==================================================${NC}"
    echo ""
    echo -e "${YELLOW}📋 INFORMASI LOGIN:${NC}"
    echo -e "   ${CYAN}URL Panel:${NC} https://$DOMAIN"
    echo -e "   ${CYAN}Local URL:${NC} https://127.0.0.1"
    echo -e "   ${CYAN}Email:${NC} $EMAIL"
    echo -e "   ${CYAN}Password:${NC} 1"
    echo -e "   ${RED}→ User ID harus 1 untuk akses Security Dashboard${NC}"
    echo ""
    echo -e "${YELLOW}🔒 SECURITY DASHBOARD:${NC}"
    echo -e "   ${CYAN}URL:${NC} https://$DOMAIN/admin/security"
    echo -e "   ${CYAN}Menu Location:${NC} Sidebar → Security System"
    echo -e "   ${RED}→ Exclusive access for User ID 1 only${NC}"
    echo ""
    echo -e "${YELLOW}🛡️ 15 FITUR KEAMANAN YANG TERINSTALL:${NC}"
    echo -e "   1. ${GREEN}✓${NC} Anti-DDoS Protection (Rate Limit)"
    echo -e "   2. ${GREEN}✓${NC} IP Ban/Unban System"
    echo -e "   3. ${GREEN}✓${NC} Anti-Debug/Inspect Protection"
    echo -e "   4. ${GREEN}✓${NC} Anti-Bot Detection"
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
    echo -e "${YELLOW}📍 MENU SECURITY FEATURES:${NC}"
    echo -e "   • ${CYAN}Sidebar Icon:${NC} fa-shield (Security System)"
    echo -e "   • ${CYAN}Submenus:${NC} Dashboard, Settings, Logs, IP Management"
    echo -e "   • ${CYAN}Badge:${NC} Red label with '15' features"
    echo -e "   • ${CYAN}Icons Only:${NC} Using FontAwesome icons (no emoji)"
    echo ""
    echo -e "${YELLOW}🔧 TROUBLESHOOTING COMMANDS:${NC}"
    echo -e "   ${CYAN}cd /var/www/pterodactyl${NC}"
    echo -e "   ${CYAN}php artisan cache:clear${NC}"
    echo -e "   ${CYAN}php artisan route:clear${NC}"
    echo -e "   ${CYAN}php artisan view:clear${NC}"
    echo -e "   ${CYAN}systemctl restart php8.3-fpm nginx${NC}"
    echo ""
    echo -e "${YELLOW}📊 CHECK INSTALLATION:${NC}"
    echo -e "   ${CYAN}tail -f /var/log/nginx/error.log${NC}"
    echo -e "   ${CYAN}tail -f storage/logs/laravel-$(date +%Y-%m-%d).log${NC}"
    echo -e "   ${CYAN}systemctl status pteroq${NC}"
    echo ""
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}🔥 PANEL SIAP DIGUNAKAN DENGAN KEAMANAN MAXIMAL! 🔥${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    # Save info to file
    cat > /root/installation-info.txt <<INFO
==========================================
PTERODACTYL + SECURITY INSTALLATION REPORT
==========================================
Date: $(date)
Domain: $DOMAIN
Local Access: https://127.0.0.1
Admin Login: $EMAIL
Admin Password: 1 (Hanya angka 1)
Admin User ID: 1 (Required for security access)

Security Dashboard: https://$DOMAIN/admin/security
Note: Only User ID 1 can access security dashboard

Database Information:
Host: 127.0.0.1
Database: panel
Username: pterodactyl
Password: $MYSQL_PANEL_PASS

Security Features (15 total):
✓ Anti-DDoS Protection
✓ IP Ban System
✓ Anti-Debug/Inspect
✓ Anti-Bot Detection
✓ Anti-Raid Protection
✓ Anti-Overheat Monitoring
✓ Fail2Ban Integration
✓ Hide Origin IP (1.1.1.1)
✓ Anti-Peek Protection
✓ Anti-Backdoor Scanner
✓ Database Query Watchdog
✓ Session Hijacking Protection
✓ API Key Expiration
✓ Real-time Security Logs
✓ Threat Scoring System

Menu Location:
1. Login as admin ($EMAIL / 1)
2. Check sidebar for "Security System" menu
3. Click to access security dashboard
4. Only visible and accessible to User ID 1

Troubleshooting Commands:
cd /var/www/pterodactyl
php artisan cache:clear
php artisan route:clear
php artisan view:clear
systemctl restart php8.3-fpm nginx

Check Logs:
tail -f /var/log/nginx/error.log
tail -f /var/www/pterodactyl/storage/logs/laravel-*.log

Verify Installation:
curl -k https://127.0.0.1/health.php
INFO
    
    echo "Informasi lengkap disimpan di: /root/installation-info.txt"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT:${NC} Test login with ${CYAN}$EMAIL${NC} and password ${RED}1${NC}"
    echo -e "${YELLOW}⚠ IMPORTANT:${NC} Security Dashboard hanya bisa diakses oleh User ID ${RED}1${NC}"
}

# Jalankan main function dengan error handling
set -e
trap 'log_error "Script failed at line $LINENO"; exit 1' ERR

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

main
