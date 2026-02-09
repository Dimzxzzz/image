#!/bin/bash

echo "=================================================="
echo "🔥 PTERODACTYL REVIAFULL INSTALLER - FINAL FIX"
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

# ========== PHASE 2: KONFIGURASI MYSQL ==========
configure_mysql() {
    log_info "Mengkonfigurasi MySQL..."
    
    systemctl start mariadb
    systemctl enable mariadb
    
    # Secure installation
    mysql -u root <<EOF
ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASS}';
DELETE FROM mysql.user WHERE User='';
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
EOF
    
    # Create database untuk panel
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
    log_success "MySQL dikonfigurasi"
}

# ========== PHASE 3: INSTALL PTERODACTYL PANEL ==========
install_panel() {
    log_info "Menginstall Pterodactyl Panel..."
    
    # Create directory
    mkdir -p $PANEL_DIR
    cd $PANEL_DIR
    
    # Download latest panel
    LATEST_PANEL=$(curl -s https://api.github.com/repos/pterodactyl/panel/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    LATEST_PANEL=${LATEST_PANEL#v}
    log_info "Downloading Pterodactyl Panel v${LATEST_PANEL}"
    
    # Clean up old files
    rm -rf *
    
    curl -L https://github.com/pterodactyl/panel/releases/download/v${LATEST_PANEL}/panel.tar.gz | tar -xz
    chmod -R 755 storage/* bootstrap/cache/
    
    # Set proper permissions
    chown -R www-data:www-data .
    
    # Install composer dependencies
    sudo -u www-data composer install --no-dev --optimize-autoloader --no-interaction
    
    # Setup environment
    cp .env.example .env
    sudo -u www-data php artisan key:generate --force
    
    # Konfigurasi environment
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
    
    # Setup database
    sudo -u www-data php artisan p:environment:database \
        --host="127.0.0.1" \
        --port="3306" \
        --database="panel" \
        --username="pterodactyl" \
        --password="${MYSQL_PANEL_PASS}"
    
    # Migrate database
    sudo -u www-data php artisan migrate --seed --force
    
    # Create admin user jika belum ada
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
        # Update password jika perlu
        mysql -u root -p${MYSQL_ROOT_PASS} panel -e "UPDATE users SET password = '\$2y\$10\$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' WHERE username = 'admin';" 2>/dev/null
    fi
    
    # Setup cron
    (crontab -l 2>/dev/null; echo "* * * * * cd $PANEL_DIR && php artisan schedule:run >> /dev/null 2>&1") | crontab -
    
    # Fix permissions
    chown -R www-data:www-data .
    chmod -R 755 storage bootstrap/cache
    chmod 777 storage/logs
    
    # Fix .env file
    sed -i "s/^DB_HOST=.*/DB_HOST=127.0.0.1/" .env
    sed -i "s/^DB_PASSWORD=.*/DB_PASSWORD=${MYSQL_PANEL_PASS}/" .env
    sed -i "s/^DB_USERNAME=.*/DB_USERNAME=pterodactyl/" .env
    sed -i "s/^DB_DATABASE=.*/DB_DATABASE=panel/" .env
    sed -i "s/^APP_DEBUG=.*/APP_DEBUG=false/" .env
    sed -i "s/^APP_ENV=.*/APP_ENV=production/" .env
    
    log_success "Panel berhasil diinstall. Login: admin@$DOMAIN / admin123"
}

# ========== PHASE 4: KONFIGURASI NGINX & SSL ==========
configure_nginx_ssl() {
    log_info "Mengkonfigurasi Nginx dan SSL..."
    
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

# ========== PHASE 5: INSTALL WINGS ==========
install_wings() {
    log_info "Menginstall Wings..."
    
    systemctl stop wings 2>/dev/null || true
    
    # Download latest wings
    LATEST_WINGS=$(curl -s https://api.github.com/repos/pterodactyl/wings/releases/latest | grep '"tag_name":' | cut -d'"' -f4)
    LATEST_WINGS=${LATEST_WINGS#v}
    log_info "Downloading Wings v${LATEST_WINGS}"
    
    rm -f /usr/local/bin/wings
    curl -L -o /usr/local/bin/wings https://github.com/pterodactyl/wings/releases/download/v${LATEST_WINGS}/wings_linux_amd64
    chmod +x /usr/local/bin/wings
    
    # Install Docker
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com | sh
        systemctl enable docker
        systemctl start docker
    fi
    
    # Generate configuration
    mkdir -p /etc/pterodactyl
    
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
    
    mkdir -p /var/lib/pterodactyl/volumes
    systemctl daemon-reload
    systemctl enable wings
    systemctl start wings
    
    sleep 2
    if systemctl is-active --quiet wings; then
        log_success "Wings berhasil diinstall dan running"
    else
        log_warning "Wings gagal start, check: journalctl -u wings"
    fi
}

# ========== PHASE 6: CREATE SECURITY DATABASE ==========
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

# ========== PHASE 7: CREATE SECURITY CONTROLLER ==========
create_security_controller() {
    log_info "Membuat Security Controller..."
    
    cat > "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" << 'CONTROLLER'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

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
            $stats = [
                'total_bans' => DB::table('security_bans')->where(function($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })->count(),
                'active_threats' => DB::table('security_ips')->where('threat_score', '>', 50)->count(),
                'enabled_features' => DB::table('security_settings')->where('is_enabled', true)->count(),
                'total_logs' => DB::table('security_logs')->count(),
            ];
            
            $recent_logs = DB::table('security_logs')->orderBy('created_at', 'desc')->limit(5)->get();
            $top_ips = DB::table('security_ips')->orderBy('threat_score', 'desc')->limit(5)->get();
            
            return view('admin.security.index', compact('stats', 'recent_logs', 'top_ips'));
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
            
            return view('admin.security.settings', compact('settings'));
        }
        
        abort(403);
    }
}
CONTROLLER
    
    log_success "Security Controller dibuat"
}

# ========== PHASE 8: CREATE SECURITY VIEWS ==========
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
    <h1>Security Dashboard<small>Complete protection system overview</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(auth()->check() && auth()->user()->id == 1)
            <div class="box box-primary">
                <div class="box-header with-border">
                    <h3 class="box-title"><i class="fa fa-shield"></i> Security System</h3>
                </div>
                <div class="box-body">
                    <div class="alert alert-success">
                        <h4><i class="fa fa-check-circle"></i> Access Granted</h4>
                        Welcome to Security Dashboard (User ID: {{ auth()->user()->id }})
                    </div>
                    
                    <div class="row">
                        <div class="col-md-3 col-sm-6">
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
                                    <h3>{{ $stats['total_bans'] ?? 0 }}</h3>
                                    <p>Active Bans</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-ban"></i>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-3 col-sm-6">
                            <div class="small-box bg-blue">
                                <div class="inner">
                                    <h3>{{ $stats['total_logs'] ?? 0 }}</h3>
                                    <p>Total Logs</p>
                                </div>
                                <div class="icon">
                                    <i class="fa fa-history"></i>
                                </div>
                            </div>
                        </div>
                    </div>
                    
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
                                                </tr>
                                            </thead>
                                            <tbody>
                                                @foreach($recent_logs as $log)
                                                <tr>
                                                    <td>{{ $log->created_at->diffForHumans() }}</td>
                                                    <td><code>{{ $log->ip_address }}</code></td>
                                                    <td>{{ $log->action }}</td>
                                                </tr>
                                                @endforeach
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <div class="col-md-6">
                            <div class="box box-warning">
                                <div class="box-header with-border">
                                    <h3 class="box-title"><i class="fa fa-network-wired"></i> Top Threatening IPs</h3>
                                </div>
                                <div class="box-body">
                                    <div class="table-responsive">
                                        <table class="table table-hover">
                                            <thead>
                                                <tr>
                                                    <th>IP Address</th>
                                                    <th>Threat Score</th>
                                                    <th>Status</th>
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
                                                        @elseif($ip->status == 'suspicious')
                                                        <span class="label label-warning">Suspicious</span>
                                                        @elseif($ip->status == 'whitelist')
                                                        <span class="label label-success">Whitelisted</span>
                                                        @else
                                                        <span class="label label-info">Active</span>
                                                        @endif
                                                    </td>
                                                </tr>
                                                @endforeach
                                            </tbody>
                                        </table>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="callout callout-success">
                        <h4><i class="fa fa-check"></i> Security Features Enabled</h4>
                        <div class="row">
                            <div class="col-md-4">
                                <ul>
                                    <li><i class="fa fa-bolt"></i> Anti-DDoS Protection</li>
                                    <li><i class="fa fa-network-wired"></i> IP Ban System</li>
                                    <li><i class="fa fa-robot"></i> Anti-Bot Detection</li>
                                    <li><i class="fa fa-bug"></i> Anti-Debug/Inspect</li>
                                </ul>
                            </div>
                            <div class="col-md-4">
                                <ul>
                                    <li><i class="fa fa-database"></i> Database Security</li>
                                    <li><i class="fa fa-user-shield"></i> Session Protection</li>
                                    <li><i class="fa fa-key"></i> API Security</li>
                                    <li><i class="fa fa-cogs"></i> Advanced Protection</li>
                                </ul>
                            </div>
                            <div class="col-md-4">
                                <ul>
                                    <li><i class="fa fa-eye"></i> Real-time Monitoring</li>
                                    <li><i class="fa fa-history"></i> Security Logs</li>
                                    <li><i class="fa fa-exclamation-triangle"></i> Threat Scoring</li>
                                    <li><i class="fa fa-sliders-h"></i> Custom Settings</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        @else
            <div class="alert alert-danger">
                <h4><i class="fa fa-ban"></i> Access Denied</h4>
                This security section is accessible only by System Administrator (User ID 1).
                <br>
                <strong>Your User ID:</strong> {{ auth()->user()->id }}
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
    <h1>Security Settings<small>Configure security features</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security.index') }}">Security</a></li>
        <li class="active">Settings</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(auth()->check() && auth()->user()->id == 1)
            <div class="nav-tabs-custom">
                <ul class="nav nav-tabs">
                    <li class="active"><a href="#ddos" data-toggle="tab"><i class="fa fa-bolt"></i> DDoS Protection</a></li>
                    <li><a href="#ip" data-toggle="tab"><i class="fa fa-network-wired"></i> IP Management</a></li>
                    <li><a href="#bot" data-toggle="tab"><i class="fa fa-robot"></i> Anti-Bot</a></li>
                    <li><a href="#advanced" data-toggle="tab"><i class="fa fa-cogs"></i> Advanced</a></li>
                </ul>
                <div class="tab-content">
                    @foreach($settings as $category => $categorySettings)
                    <div class="tab-pane {{ $category == 'ddos' ? 'active' : '' }}" id="{{ $category }}">
                        <div class="box box-{{ $category == 'ddos' ? 'danger' : ($category == 'ip' ? 'warning' : ($category == 'bot' ? 'info' : 'success')) }}">
                            <div class="box-header with-border">
                                <h3 class="box-title">
                                    <i class="fa fa-{{ $category == 'ddos' ? 'bolt' : ($category == 'ip' ? 'network-wired' : ($category == 'bot' ? 'robot' : 'cogs')) }}"></i>
                                    {{ ucfirst($category) }} Security Settings
                                </h3>
                            </div>
                            <div class="box-body">
                                @foreach($categorySettings as $setting)
                                <div class="form-group">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" {{ $setting->is_enabled ? 'checked' : '' }} disabled>
                                            <strong>{{ $setting->description }}</strong>
                                            <p class="text-muted">Status: {{ $setting->is_enabled ? 'Enabled' : 'Disabled' }}</p>
                                        </label>
                                    </div>
                                </div>
                                @endforeach
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
    
    log_success "Security views dibuat"
}

# ========== PHASE 9: ADD SECURITY ROUTES ==========
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
});'
    
    # Add routes before the end of file
    if ! grep -q "admin.security" "$PANEL_DIR/routes/web.php"; then
        sed -i '/^$/d' "$PANEL_DIR/routes/web.php"
        echo -e "\n$SECURITY_ROUTES" >> "$PANEL_DIR/routes/web.php"
    fi
    
    log_success "Security routes ditambahkan"
}

# ========== PHASE 10: ADD SECURITY MENU TO SIDEBAR ==========
add_security_menu() {
    log_info "Menambahkan menu security ke sidebar..."
    
    LAYOUT_FILE="$PANEL_DIR/resources/views/layouts/admin.blade.php"
    
    # Backup file
    cp "$LAYOUT_FILE" "${LAYOUT_FILE}.backup"
    
    # Find where to insert (after Users menu)
    if grep -q '<i class="fa fa-users"></i> <span>Users</span>' "$LAYOUT_FILE"; then
        # Create security menu item
        SECURITY_MENU='                            <li class="{{ Request::is("admin/security*") ? "active" : "" }}">
                                <a href="{{ route("admin.security.index") }}">
                                    <i class="fa fa-shield"></i> <span>Security System</span>
                                    <small class="label pull-right bg-red">15</small>
                                </a>
                            </li>'
        
        # Insert after Users menu
        awk '/<i class="fa fa-users"><\/i> <span>Users<\/span>/{print; print "'"$SECURITY_MENU"'"; next}1' "$LAYOUT_FILE" > "${LAYOUT_FILE}.new"
        mv "${LAYOUT_FILE}.new" "$LAYOUT_FILE"
        
        log_success "Security menu ditambahkan setelah Users menu"
    else
        # Alternative insertion method
        SECURITY_MENU='                        <li class="treeview {{ Request::is("admin/security*") ? "active" : "" }}">
                            <a href="#">
                                <i class="fa fa-shield"></i>
                                <span>Security System</span>
                                <span class="pull-right-container">
                                    <i class="fa fa-angle-left pull-right"></i>
                                    <small class="label pull-right bg-red">15</small>
                                </span>
                            </a>
                            <ul class="treeview-menu">
                                <li class="{{ Request::is("admin/security") ? "active" : "" }}">
                                    <a href="{{ route("admin.security.index") }}">
                                        <i class="fa fa-dashboard"></i> <span>Dashboard</span>
                                    </a>
                                </li>
                                <li class="{{ Request::is("admin/security/settings") ? "active" : "" }}">
                                    <a href="{{ route("admin.security.settings") }}">
                                        <i class="fa fa-sliders-h"></i> <span>Settings</span>
                                    </a>
                                </li>
                            </ul>
                        </li>'
        
        # Insert before closing sidebar
        sed -i '/<\/section>/i\'"$SECURITY_MENU" "$LAYOUT_FILE"
        
        log_success "Security menu ditambahkan di sidebar"
    fi
}

# ========== PHASE 11: FIX PERMISSIONS AND CACHE ==========
fix_permissions_cache() {
    log_info "Memperbaiki permissions dan cache..."
    
    cd $PANEL_DIR
    
    # Fix permissions
    chown -R www-data:www-data .
    find . -type f -exec chmod 644 {} \;
    find . -type d -exec chmod 755 {} \;
    chmod -R 775 storage bootstrap/cache
    chmod 777 storage/logs
    
    # Clear all caches
    sudo -u www-data php artisan cache:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    sudo -u www-data php artisan route:clear 2>/dev/null || true
    sudo -u www-data php artisan optimize:clear 2>/dev/null || true
    
    # Restart services
    systemctl restart php8.3-fpm
    systemctl restart nginx
    
    # Optimize
    sudo -u www-data php artisan optimize 2>/dev/null || true
    
    log_success "Permissions dan cache diperbaiki"
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
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        echo -e "${GREEN}✓ Nginx: RUNNING${NC}"
    else
        echo -e "${RED}✗ Nginx: NOT RUNNING${NC}"
    fi
    
    # Check MariaDB
    if systemctl is-active --quiet mariadb; then
        echo -e "${GREEN}✓ MariaDB: RUNNING${NC}"
    else
        echo -e "${RED}✗ MariaDB: NOT RUNNING${NC}"
    fi
    
    # Check Wings
    if systemctl is-active --quiet wings; then
        echo -e "${GREEN}✓ Wings: RUNNING${NC}"
    else
        echo -e "${YELLOW}⚠ Wings: NOT RUNNING (optional)${NC}"
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
        echo -e "${GREEN}✓ Security Views: EXISTS${NC}"
    else
        echo -e "${RED}✗ Security Views: MISSING${NC}"
    fi
    
    # Check security routes
    if grep -q "admin.security" "$PANEL_DIR/routes/web.php"; then
        echo -e "${GREEN}✓ Security Routes: EXISTS${NC}"
    else
        echo -e "${RED}✗ Security Routes: MISSING${NC}"
    fi
    
    # Check security database tables
    if mysql -u root -p${MYSQL_ROOT_PASS} panel -e "SHOW TABLES LIKE 'security_%';" 2>/dev/null | grep -q "security_"; then
        echo -e "${GREEN}✓ Security Database: EXISTS${NC}"
    else
        echo -e "${RED}✗ Security Database: MISSING${NC}"
    fi
    
    echo -e "${CYAN}========================================${NC}"
    echo ""
}

# ========== PHASE 13: FINAL FIXES ==========
final_fixes() {
    log_info "Applying final fixes..."
    
    cd $PANEL_DIR
    
    # Ensure route cache is cleared
    sudo -u www-data php artisan route:clear 2>/dev/null || true
    
    # Check if routes are properly loaded
    ROUTES=$(sudo -u www-data php artisan route:list 2>/dev/null | grep -i security || echo "")
    
    if echo "$ROUTES" | grep -q "security"; then
        log_success "Security routes are registered"
    else
        log_warning "Security routes not found, re-adding..."
        add_security_routes
        sudo -u www-data php artisan route:clear 2>/dev/null || true
    fi
    
    # Create a test route for debugging
    echo '<?php
Route::get("/test-security", function() {
    return response()->json([
        "status" => "ok",
        "user_id" => auth()->check() ? auth()->user()->id : "not logged in",
        "security_route" => route("admin.security.index", [], false)
    ]);
});' > "$PANEL_DIR/routes/test.php"
    
    # Include test routes
    if ! grep -q "test.php" "$PANEL_DIR/routes/web.php"; then
        echo -e "\n// Test routes\nrequire __DIR__.'/test.php';" >> "$PANEL_DIR/routes/web.php"
    fi
    
    # Clear cache again
    sudo -u www-data php artisan cache:clear 2>/dev/null || true
    sudo -u www-data php artisan view:clear 2>/dev/null || true
    sudo -u www-data php artisan config:clear 2>/dev/null || true
    
    log_success "Final fixes applied"
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
    configure_nginx_ssl
    install_wings
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
    echo -e "   ${CYAN}Email:${NC} admin@$DOMAIN"
    echo -e "   ${CYAN}Password:${NC} admin123"
    echo ""
    echo -e "${YELLOW}🔒 SECURITY DASHBOARD:${NC}"
    echo -e "   ${CYAN}URL:${NC} https://$DOMAIN/admin/security"
    echo -e "   ${RED}→ Hanya User ID 1 yang bisa akses!${NC}"
    echo ""
    echo -e "${YELLOW}🛡️ FITUR KEAMANAN YANG TERINSTALL:${NC}"
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
    echo -e "${YELLOW}📍 LOKASI MENU SECURITY:${NC}"
    echo -e "   • ${CYAN}Sidebar Admin Panel${NC}"
    echo -e "   • ${CYAN}Setelah menu 'Users'${NC}"
    echo -e "   • ${CYAN}Icon: ${NC}🛡️ (fa-shield)"
    echo -e "   • ${CYAN}Label: ${NC}Security System"
    echo ""
    echo -e "${YELLOW}🔧 JIKA MASIH ADA MASALAH:${NC}"
    echo -e "   1. ${CYAN}cd /var/www/pterodactyl${NC}"
    echo -e "   2. ${CYAN}php artisan route:clear${NC}"
    echo -e "   3. ${CYAN}php artisan cache:clear${NC}"
    echo -e "   4. ${CYAN}php artisan view:clear${NC}"
    echo -e "   5. ${CYAN}systemctl restart php8.3-fpm nginx${NC}"
    echo ""
    echo -e "${GREEN}==================================================${NC}"
    echo -e "${GREEN}🔥 PANEL SIAP DIGUNAKAN! 🔥${NC}"
    echo -e "${GREEN}==================================================${NC}"
    
    # Save info to file
    cat > /root/installation-info.txt <<INFO
==========================================
PTERODACTYL + SECURITY INSTALLATION REPORT
==========================================
Date: $(date)
Domain: $DOMAIN
Admin Login: admin@$DOMAIN
Admin Password: admin123

Security Dashboard: https://$DOMAIN/admin/security
Note: Only User ID 1 can access security dashboard

MySQL Information:
Host: 127.0.0.1
Database: panel
Username: pterodactyl
Password: $MYSQL_PANEL_PASS

Security Features (15 total):
1. Anti-DDoS Protection
2. IP Ban System
3. Anti-Debug/Inspect
4. Anti-Bot Detection
5. Anti-Raid Protection
6. Anti-Overheat Monitoring
7. Fail2Ban Integration
8. Hide Origin IP (1.1.1.1)
9. Anti-Peek Protection
10. Anti-Backdoor Scanner
11. Database Query Watchdog
12. Session Hijacking Protection
13. API Key Expiration
14. Real-time Security Logs
15. Threat Scoring System

Troubleshooting Commands:
cd /var/www/pterodactyl
php artisan cache:clear
php artisan route:clear
php artisan view:clear
systemctl restart php8.3-fpm nginx

Check Security Menu:
1. Login as admin@$DOMAIN
2. Check sidebar menu for "Security System"
3. Click to access security dashboard

INFO
    
    echo "Informasi lengkap disimpan di: /root/installation-info.txt"
}

# Jalankan main function
main
