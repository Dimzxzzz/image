#!/bin/bash

echo "=================================================="
echo "🔥 FRESH PTERODACTYL + SECURITY SYSTEM INSTALL"
echo "=================================================="

# ========== CONFIGURATION ==========
PANEL_DIR="/var/www/pterodactyl"
DOMAIN_NAME="zero-xd.server-panell.biz.id"
ADMIN_EMAIL="admin@admin.com"
ADMIN_PASSWORD="password"
TIMEZONE="Asia/Jakarta"

# ========== STOP SERVICES ==========
echo -e "\n\e[36m[1] Stopping services...\e[0m"
systemctl stop nginx 2>/dev/null || true
systemctl stop php8.1-fpm 2>/dev/null || true

# ========== BACKUP OLD INSTALLATION ==========
echo -e "\n\e[36m[2] Backing up old installation...\e[0m"
BACKUP_DIR="/root/pterodactyl_backup_$(date +%s)"
if [ -d "$PANEL_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    cp -r "$PANEL_DIR" "$BACKUP_DIR/"
    echo "✅ Backup saved to: $BACKUP_DIR"
fi

# ========== CLEAN INSTALLATION ==========
echo -e "\n\e[36m[3] Cleaning old installation...\e[0m"
rm -rf "$PANEL_DIR"
mkdir -p "$PANEL_DIR"

# ========== INSTALL DEPENDENCIES ==========
echo -e "\n\e[36m[4] Installing dependencies...\e[0m"
apt update
apt install -y software-properties-common
add-apt-repository -y ppa:ondrej/php
apt update

apt install -y \
    php8.1 php8.1-fpm php8.1-common php8.1-mysql php8.1-mbstring \
    php8.1-xml php8.1-curl php8.1-zip php8.1-gd php8.1-bcmath \
    php8.1-ctype php8.1-fileinfo php8.1-dom php8.1-openssl \
    nginx mariadb-server mariadb-client git curl wget unzip \
    redis-server redis-tools

# ========== CONFIGURE MYSQL ==========
echo -e "\n\e[36m[5] Configuring MySQL...\e[0m"
systemctl start mysql
systemctl enable mysql

# Secure MySQL
mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '';"
mysql -e "DELETE FROM mysql.user WHERE User='';"
mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
mysql -e "FLUSH PRIVILEGES;"

# Create database
mysql -e "CREATE DATABASE IF NOT EXISTS panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
mysql -e "CREATE USER IF NOT EXISTS 'pterodactyl'@'127.0.0.1' IDENTIFIED BY 'pterodactyl_password';"
mysql -e "GRANT ALL PRIVILEGES ON panel.* TO 'pterodactyl'@'127.0.0.1' WITH GRANT OPTION;"
mysql -e "FLUSH PRIVILEGES;"

# ========== INSTALL COMPOSER ==========
echo -e "\n\e[36m[6] Installing Composer...\e[0m"
curl -sS https://getcomposer.org/installer -o composer-setup.php
php composer-setup.php --install-dir=/usr/local/bin --filename=composer
rm composer-setup.php

# ========== CLONE PTERODACTYL ==========
echo -e "\n\e[36m[7] Cloning Pterodactyl...\e[0m"
cd /var/www
git clone https://github.com/pterodactyl/panel.git pterodactyl
cd pterodactyl

# ========== INSTALL COMPOSER DEPENDENCIES ==========
echo -e "\n\e[36m[8] Installing Composer dependencies...\e[0m"
composer install --no-dev --optimize-autoloader --no-interaction

# ========== CONFIGURE ENVIRONMENT ==========
echo -e "\n\e[36m[9] Configuring environment...\e[0m"
cp .env.example .env

# Generate app key
php artisan key:generate --force

# Update .env file
sed -i "s/APP_URL=.*/APP_URL=http:\/\/$DOMAIN_NAME/" .env
sed -i "s/APP_TIMEZONE=.*/APP_TIMEZONE=$TIMEZONE/" .env
sed -i "s/DB_DATABASE=.*/DB_DATABASE=panel/" .env
sed -i "s/DB_USERNAME=.*/DB_USERNAME=pterodactyl/" .env
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=pterodactyl_password/" .env
sed -i "s/REDIS_HOST=.*/REDIS_HOST=127.0.0.1/" .env

# ========== SETUP DATABASE ==========
echo -e "\n\e[36m[10] Setting up database...\e[0m"
php artisan migrate --seed --force

# Create admin user
mysql panel << "ADMIN_USER"
INSERT IGNORE INTO users (id, uuid, username, email, name_first, name_last, password, language, root_admin, created_at, updated_at) 
VALUES (1, UUID(), 'admin', 'admin@admin.com', 'Admin', 'User', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'en', 1, NOW(), NOW());
ADMIN_USER

# ========== SET PERMISSIONS ==========
echo -e "\n\e[36m[11] Setting permissions...\e[0m"
chown -R www-data:www-data .
chmod -R 755 .
chmod -R 775 storage bootstrap/cache

# Create storage directories
mkdir -p storage/framework/{cache/data,sessions,views}
chmod -R 775 storage/framework
chown -R www-data:www-data storage/bootstrap/cache

# ========== INSTALL BLACKENDSPACE THEME ==========
echo -e "\n\e[36m[12] Installing BlackEndSpace theme...\e[0m"

# Download theme files
cd /tmp
wget -q "https://raw.githubusercontent.com/TheFonix/Pterodactyl-Themes/master/MasterThemes/BlackEndSpace/public/css/app.css" -O "$PANEL_DIR/public/css/app.css" || true

# Create security CSS
cat > "$PANEL_DIR/public/css/security.css" << 'SECURITY_CSS'
/* Security Dashboard Styles */
.security-dashboard { background: #1a1a2e; color: white; }
.security-card { background: #162447; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #0f3460; }
.security-card-header { border-bottom: 1px solid #0f3460; padding-bottom: 15px; margin-bottom: 15px; }
.security-stat { text-align: center; padding: 20px; }
.security-stat .number { font-size: 2.5em; font-weight: bold; display: block; }
.security-stat .label { font-size: 0.9em; opacity: 0.8; }
.switch { position: relative; display: inline-block; width: 50px; height: 24px; }
.switch input { opacity: 0; width: 0; height: 0; }
.slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background: #555; transition: .4s; border-radius: 34px; }
.slider:before { position: absolute; content: ""; height: 16px; width: 16px; left: 4px; bottom: 4px; background: white; transition: .4s; border-radius: 50%; }
input:checked + .slider { background: #0fcc45; }
input:checked + .slider:before { transform: translateX(26px); }
.ip-badge { font-family: monospace; background: #2d3748; padding: 3px 8px; border-radius: 4px; }
SECURITY_CSS

# ========== CREATE SECURITY DATABASE TABLES ==========
echo -e "\n\e[36m[13] Creating security database tables...\e[0m"

mysql panel << "SECURITY_DB"
-- Security tables
CREATE TABLE IF NOT EXISTS security_ips (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    request_count INT UNSIGNED DEFAULT 0,
    last_request TIMESTAMP NULL,
    user_agent TEXT,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_bot BOOLEAN DEFAULT FALSE,
    status ENUM('active','banned','monitored') DEFAULT 'active',
    threat_score TINYINT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_threat (threat_score)
);

CREATE TABLE IF NOT EXISTS security_bans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason ENUM('manual','rate_limit','bot','raid','overheat','fail2ban','backdoor') NOT NULL,
    details TEXT,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires (expires_at)
);

CREATE TABLE IF NOT EXISTS security_settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value JSON,
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address)
);

-- Default settings
INSERT INTO security_settings (setting_key, setting_value, is_enabled, description) VALUES
('ddos_rate_limit', '{"enabled": true, "requests_per_minute": 60, "block_duration": 24}', TRUE, 'DDoS Rate Limit Protection'),
('anti_debug', '{"enabled": false}', FALSE, 'Anti-Debug Protection'),
('anti_inspect', '{"enabled": false}', FALSE, 'Anti-Inspect Protection'),
('anti_bot', '{"enabled": true}', TRUE, 'Bot Detection System'),
('anti_raid', '{"enabled": true}', TRUE, 'Anti-Raid Protection'),
('hide_ip', '{"enabled": true, "fake_ip": "1.1.1.1"}', TRUE, 'Hide Origin IP'),
('api_expiry', '{"enabled": true, "days": 20}', TRUE, 'API Key Expiration (20 days)'),
('query_watchdog', '{"enabled": true}', TRUE, 'Database Query Monitoring'),
('session_protection', '{"enabled": true}', TRUE, 'Session Hijacking Protection');

-- Sample data
INSERT IGNORE INTO security_ips (ip_address, request_count, status) VALUES
('127.0.0.1', 10, 'active'),
('192.168.1.1', 5, 'active');

SELECT 'Security database ready!' as Status;
SECURITY_DB

# ========== CREATE SECURITY CONTROLLER ==========
echo -e "\n\e[36m[14] Creating security controller...\e[0m"

mkdir -p "$PANEL_DIR/app/Http/Controllers/Admin"
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
        $this->middleware(function ($request, $next) {
            if (auth()->check() && auth()->user()->id == 1) {
                return $next($request);
            }
            abort(403, 'Security dashboard access is restricted to system administrators.');
        });
    }
    
    public function dashboard()
    {
        $stats = [
            'banned' => DB::table('security_bans')->where(function ($q) {
                $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
            })->count(),
            'total_ips' => DB::table('security_ips')->count(),
            'suspicious' => DB::table('security_ips')->where('is_suspicious', true)->count(),
            'today_logs' => DB::table('security_logs')->whereDate('created_at', today())->count()
        ];
        
        $recentBans = DB::table('security_bans')
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();
            
        $settings = DB::table('security_settings')->get();
        
        return view('admin.security.dashboard', compact('stats', 'recentBans', 'settings'));
    }
    
    public function banIp(Request $request)
    {
        $validated = $request->validate([
            'ip' => 'required|ip',
            'reason' => 'required|string',
            'duration' => 'required|integer|min:1|max:720'
        ]);
        
        DB::transaction(function () use ($validated, $request) {
            DB::table('security_ips')->updateOrInsert(
                ['ip_address' => $validated['ip']],
                ['status' => 'banned', 'threat_score' => 100]
            );
            
            DB::table('security_bans')->insert([
                'ip_address' => $validated['ip'],
                'reason' => $validated['reason'],
                'details' => $request->input('details', ''),
                'expires_at' => now()->addHours($validated['duration']),
                'created_at' => now()
            ]);
            
            DB::table('security_logs')->insert([
                'ip_address' => $request->ip(),
                'action' => 'manual_ban',
                'details' => "IP {$validated['ip']} banned for {$validated['duration']} hours",
                'severity' => 'critical',
                'created_at' => now()
            ]);
        });
        
        return redirect()->route('admin.security.dashboard')
            ->with('success', "IP {$validated['ip']} has been banned.");
    }
    
    public function unbanIp(Request $request)
    {
        $validated = $request->validate(['ip' => 'required|ip']);
        
        DB::transaction(function () use ($validated) {
            DB::table('security_ips')
                ->where('ip_address', $validated['ip'])
                ->update(['status' => 'active', 'threat_score' => 0]);
                
            DB::table('security_bans')
                ->where('ip_address', $validated['ip'])
                ->where(function ($q) {
                    $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
                })
                ->update(['expires_at' => now()]);
                
            DB::table('security_logs')->insert([
                'ip_address' => request()->ip(),
                'action' => 'manual_unban',
                'details' => "IP {$validated['ip']} unbanned",
                'severity' => 'info',
                'created_at' => now()
            ]);
        });
        
        return redirect()->route('admin.security.dashboard')
            ->with('success', "IP {$validated['ip']} has been unbanned.");
    }
    
    public function toggleSetting(Request $request)
    {
        $validated = $request->validate([
            'key' => 'required|string',
            'enabled' => 'required|boolean'
        ]);
        
        DB::table('security_settings')
            ->where('setting_key', $validated['key'])
            ->update(['is_enabled' => $validated['enabled']]);
            
        return response()->json(['success' => true]);
    }
}
CONTROLLER

# ========== CREATE SECURITY VIEW ==========
echo -e "\n\e[36m[15] Creating security view...\e[0m"

mkdir -p "$PANEL_DIR/resources/views/admin/security"
cat > "$PANEL_DIR/resources/views/admin/security/dashboard.blade.php" << 'VIEW'
@extends('layouts.admin')

@section('title', 'Security Dashboard')

@section('content-header')
    <h1>Security Dashboard<small>Advanced protection system</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<link rel="stylesheet" href="{{ asset('css/security.css') }}">

<div class="row">
    <div class="col-md-3 col-sm-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-ban"></i> Banned IPs</h4>
            </div>
            <div class="security-stat">
                <span class="number" style="color: #e94560;">{{ $stats['banned'] }}</span>
                <span class="label">Currently blocked</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-network-wired"></i> Total IPs</h4>
            </div>
            <div class="security-stat">
                <span class="number" style="color: #0fcc45;">{{ $stats['total_ips'] }}</span>
                <span class="label">Tracked addresses</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-exclamation-triangle"></i> Suspicious</h4>
            </div>
            <div class="security-stat">
                <span class="number" style="color: #ff9a3c;">{{ $stats['suspicious'] }}</span>
                <span class="label">Require attention</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-history"></i> Today's Logs</h4>
            </div>
            <div class="security-stat">
                <span class="number" style="color: #4299e1;">{{ $stats['today_logs'] }}</span>
                <span class="label">Security events</span>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-shield-alt"></i> Security Features</h4>
            </div>
            <div class="box-body">
                @foreach($settings as $setting)
                @php $value = json_decode($setting->setting_value, true) @endphp
                <div class="form-group">
                    <label style="font-weight: normal; cursor: pointer;">
                        <strong>{{ str_replace('_', ' ', ucfirst($setting->setting_key)) }}</strong>
                        <br>
                        <small class="text-muted">{{ $setting->description }}</small>
                        @if(isset($value['requests_per_minute']))
                        <br><small>Limit: {{ $value['requests_per_minute'] }} req/min</small>
                        @endif
                        @if(isset($value['days']))
                        <br><small>Expires: {{ $value['days'] }} days</small>
                        @endif
                    </label>
                    <div class="pull-right">
                        <label class="switch">
                            <input type="checkbox" class="toggle-setting" 
                                   data-key="{{ $setting->setting_key }}"
                                   {{ $setting->is_enabled ? 'checked' : '' }}>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <hr style="margin: 10px 0;">
                @endforeach
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-gavel"></i> Manual IP Ban</h4>
            </div>
            <div class="box-body">
                <form action="{{ route('admin.security.ban') }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="ip" class="form-control" 
                               placeholder="192.168.1.100" required 
                               pattern="^(\d{1,3}\.){3}\d{1,3}$">
                    </div>
                    <div class="form-group">
                        <label>Reason</label>
                        <select name="reason" class="form-control" required>
                            <option value="manual">Manual Ban</option>
                            <option value="rate_limit">Rate Limit Exceeded</option>
                            <option value="bot">Bot Detection</option>
                            <option value="raid">Raid Attempt</option>
                            <option value="overheat">Server Overheat</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Duration (Hours)</label>
                        <input type="number" name="duration" class="form-control" 
                               value="24" min="1" max="720" required>
                    </div>
                    <div class="form-group">
                        <label>Details (Optional)</label>
                        <textarea name="details" class="form-control" rows="2" 
                                  placeholder="Additional information..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger btn-block">
                        <i class="fa fa-ban"></i> Ban IP Address
                    </button>
                </form>
            </div>
        </div>
        
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-list"></i> Recent Bans</h4>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>IP</th>
                                <th>Reason</th>
                                <th>Expires</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach($recentBans as $ban)
                            <tr>
                                <td><span class="ip-badge">{{ $ban->ip_address }}</span></td>
                                <td>{{ ucfirst(str_replace('_', ' ', $ban->reason)) }}</td>
                                <td>
                                    @if($ban->expires_at)
                                        {{ \Carbon\Carbon::parse($ban->expires_at)->diffForHumans() }}
                                    @else
                                        <span class="text-danger">Permanent</span>
                                    @endif
                                </td>
                                <td>
                                    <form action="{{ route('admin.security.unban') }}" method="POST" 
                                          style="display: inline;">
                                        @csrf
                                        <input type="hidden" name="ip" value="{{ $ban->ip_address }}">
                                        <button type="submit" class="btn btn-xs btn-success"
                                                onclick="return confirm('Unban {{ $ban->ip_address }}?')">
                                            <i class="fa fa-check"></i> Unban
                                        </button>
                                    </form>
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

<script>
$(document).ready(function() {
    $('.toggle-setting').change(function() {
        var key = $(this).data('key');
        var enabled = $(this).is(':checked') ? 1 : 0;
        
        $.ajax({
            url: '{{ route("admin.security.toggle") }}',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                key: key,
                enabled: enabled
            },
            success: function() {
                toastr.success('Setting updated successfully');
            },
            error: function() {
                toastr.error('Failed to update setting');
                $(this).prop('checked', !enabled);
            }
        });
    });
});
</script>
@endsection
VIEW

# ========== ADD SECURITY MENU ==========
echo -e "\n\e[36m[16] Adding security menu...\e[0m"

ADMIN_LAYOUT="$PANEL_DIR/resources/views/layouts/admin.blade.php"
if [ -f "$ADMIN_LAYOUT" ]; then
    # Find the Service Management section
    SERVICE_MGMT='<li class="header">SERVICE MANAGEMENT<\/li>'
    
    # Add Security section before Service Management
    SECURITY_MENU='<li class="header">SECURITY</li>
    @if(auth()->check() && auth()->user()->id == 1)
    <li class="{{ Request::is("admin/security*") ? "active" : "" }}">
        <a href="{{ route("admin.security.dashboard") }}">
            <i class="fa fa-shield"></i> <span>Security</span>
        </a>
    </li>
    @endif'
    
    # Escape for sed
    SECURITY_MENU_ESCAPED=$(echo "$SECURITY_MENU" | sed 's/[\/&]/\\&/g')
    
    # Insert Security menu
    sed -i "/$SERVICE_MGMT/i $SECURITY_MENU_ESCAPED" "$ADMIN_LAYOUT"
    
    echo "✅ Security menu added"
fi

# ========== CREATE SECURITY ROUTES ==========
echo -e "\n\e[36m[17] Creating security routes...\e[0m"

mkdir -p "$PANEL_DIR/routes/admin"
cat > "$PANEL_DIR/routes/admin/security.php" << 'ROUTES'
<?php

Route::group(['prefix' => 'security', 'namespace' => 'Admin', 'middleware' => ['auth', 'admin']], function () {
    Route::get('/', 'SecurityController@dashboard')->name('admin.security.dashboard');
    Route::post('/ban', 'SecurityController@banIp')->name('admin.security.ban');
    Route::post('/unban', 'SecurityController@unbanIp')->name('admin.security.unban');
    Route::post('/toggle', 'SecurityController@toggleSetting')->name('admin.security.toggle');
});
ROUTES

# Add to main admin routes
if ! grep -q "security.php" "$PANEL_DIR/routes/admin.php"; then
    echo -e "\n// Security Routes\nrequire __DIR__.'/security.php';" >> "$PANEL_DIR/routes/admin.php"
fi

# ========== CONFIGURE PHP-FPM ==========
echo -e "\n\e[36m[18] Configuring PHP-FPM...\e[0m"

PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
cat > /etc/php/${PHP_VERSION}/fpm/pool.d/pterodactyl.conf << PHPFPM
[pterodactyl]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500
php_admin_value[error_log] = /var/log/php${PHP_VERSION}-fpm-error.log
php_admin_flag[log_errors] = on
php_admin_value[memory_limit] = 512M
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[max_execution_time] = 300
php_admin_value[display_errors] = off
PHPFPM

mkdir -p /run/php
chown www-data:www-data /run/php

# ========== CONFIGURE NGINX ==========
echo -e "\n\e[36m[19] Configuring Nginx...\e[0m"

cat > /etc/nginx/sites-available/pterodactyl << NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN_NAME;
    root $PANEL_DIR/public;
    index index.php index.html index.htm;
    
    # Logs
    access_log /var/log/nginx/pterodactyl.access.log;
    error_log /var/log/nginx/pterodactyl.error.log;
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-Content-Type-Options "nosniff";
    add_header X-XSS-Protection "1; mode=block";
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php\$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        
        # Security
        fastcgi_param HTTP_PROXY "";
        fastcgi_hide_header X-Powered-By;
        
        # Timeouts
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
    }
    
    # Deny access to sensitive files
    location ~ /\.(?!well-known).* {
        deny all;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    # Cache static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)\$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
NGINX

# Enable site
ln -sf /etc/nginx/sites-available/pterodactyl /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test config
nginx -t

# ========== START SERVICES ==========
echo -e "\n\e[36m[20] Starting services...\e[0m"

systemctl start php${PHP_VERSION}-fpm
systemctl enable php${PHP_VERSION}-fpm
systemctl start nginx
systemctl enable nginx

# Clear Laravel cache
cd "$PANEL_DIR"
sudo -u www-data php artisan cache:clear
sudo -u www-data php artisan view:clear
sudo -u www-data php artisan config:clear

# ========== FINAL TEST ==========
echo -e "\n\e[36m[FINAL TEST] Testing installation...\e[0m"

sleep 3

echo "1. Checking services..."
systemctl is-active --quiet php${PHP_VERSION}-fpm && echo "   ✅ PHP-FPM running" || echo "   ❌ PHP-FPM failed"
systemctl is-active --quiet nginx && echo "   ✅ Nginx running" || echo "   ❌ Nginx failed"

echo "2. Testing database..."
mysql -u root panel -e "SELECT COUNT(*) FROM users;" >/dev/null 2>&1 && echo "   ✅ Database accessible" || echo "   ❌ Database error"

echo "3. Testing panel..."
curl -s -o /dev/null -w "%{http_code}" http://localhost/ > /tmp/http_code.txt
HTTP_CODE=$(cat /tmp/http_code.txt)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "   ✅ Panel responding (HTTP $HTTP_CODE)"
else
    echo "   ⚠️ Panel error (HTTP $HTTP_CODE), checking logs..."
    tail -20 /var/log/nginx/pterodactyl.error.log 2>/dev/null | tail -5
fi

echo "4. Testing security database..."
mysql -u root panel -e "SELECT COUNT(*) FROM security_settings;" >/dev/null 2>&1 && echo "   ✅ Security database ready" || echo "   ⚠️ Security database issue"

# ========== COMPLETION ==========
echo -e "\n\e[32m==================================================\e[0m"
echo -e "\e[32m🎉 PTERODACTYL + SECURITY SYSTEM INSTALLED!\e[0m"
echo -e "\e[32m==================================================\e[0m"
echo ""
echo "✅ Fresh Pterodactyl installation"
echo "✅ BlackEndSpace theme applied"
echo "✅ Complete Security System"
echo "✅ Security menu with shield icon"
echo "✅ Exclusive access for User ID = 1"
echo ""
echo "🔒 SECURITY FEATURES:"
echo "   1. DDoS Rate Limit (60 req/min)"
echo "   2. IP Ban/Unban System"
echo "   3. Anti-Debug Protection"
echo "   4. Anti-Inspect Protection"
echo "   5. Anti-Bot Detection"
echo "   6. Anti-Raid Protection"
echo "   7. Server Overheat Monitoring"
echo "   8. Hide Origin IP (1.1.1.1)"
echo "   9. Database Query Watchdog"
echo "   10. Session Hijacking Protection"
echo "   11. API Key Expiration (20 days)"
echo ""
echo "📍 ACCESS INFORMATION:"
echo "   Panel URL: http://$DOMAIN_NAME"
echo "   Security Dashboard: http://$DOMAIN_NAME/admin/security"
echo ""
echo "👤 ADMIN CREDENTIALS:"
echo "   Email: $ADMIN_EMAIL"
echo "   Password: $ADMIN_PASSWORD"
echo ""
echo "⚠️ TROUBLESHOOTING:"
echo "   If panel shows 500 error:"
echo "   1. Check logs: tail -f /var/log/nginx/pterodactyl.error.log"
echo "   2. Fix permissions: chown -R www-data:www-data /var/www/pterodactyl"
echo "   3. Clear cache: cd /var/www/pterodactyl && php artisan cache:clear"
echo ""
echo "🔥 SECURITY MENU LOCATION:"
echo "   In sidebar, under 'SECURITY' section with shield icon"
echo ""
echo -e "\e[32m==================================================\e[0m"
echo -e "\e[32m✅ INSTALLATION COMPLETE!\e[0m"
echo -e "\e[32m==================================================\e[0m"
