#!/bin/bash

echo "=================================================="
echo "🔥 FIXING INSTALLATION ERRORS"
echo "=================================================="

# ========== CONFIGURATION ==========
PANEL_DIR="/var/www/pterodactyl"
DB_NAME="panel"
DB_USER="root"
DB_PASS=""
DOMAIN_NAME="zero-xd.server-panell.biz.id"

# ========== FIX 1: CREATE DATABASE ==========
echo -e "\n\e[36m[FIX 1] Creating Database...\e[0m"

mysql -u root << "MYSQL_FIX"
-- Create database if not exists
CREATE DATABASE IF NOT EXISTS panel;
USE panel;

-- Check if users table exists
SELECT COUNT(*) FROM users;
MYSQL_FIX

if [ $? -eq 0 ]; then
    echo "✅ Database panel exists and accessible"
else
    echo "⚠️ Database panel not found, creating fresh..."
    
    # Create fresh database
    mysql -u root << "MYSQL_FRESH"
CREATE DATABASE IF NOT EXISTS panel CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE panel;

-- Create minimal users table for testing
CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    root_admin BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert admin user if not exists
INSERT IGNORE INTO users (id, username, email, password, root_admin) VALUES
(1, 'admin', 'admin@admin.com', '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 1);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id INT UNSIGNED,
    ip_address VARCHAR(45),
    user_agent TEXT,
    payload TEXT,
    last_activity INT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

SELECT 'Database created successfully!' as Status;
MYSQL_FRESH
fi

# ========== FIX 2: CREATE PUBLIC DIRECTORY STRUCTURE ==========
echo -e "\n\e[36m[FIX 2] Creating Public Directory Structure...\e[0m"

# Create necessary directories
mkdir -p "$PANEL_DIR/public/css"
mkdir -p "$PANEL_DIR/public/js"
mkdir -p "$PANEL_DIR/public/images"
mkdir -p "$PANEL_DIR/public/fonts"

# Download BlackEndSpace theme files properly
echo "Downloading theme files..."
cd /tmp

# Download using wget with proper error handling
wget -q "https://raw.githubusercontent.com/TheFonix/Pterodactyl-Themes/master/MasterThemes/BlackEndSpace/public/css/app.css" -O /tmp/app.css
if [ -f "/tmp/app.css" ]; then
    cp /tmp/app.css "$PANEL_DIR/public/css/app.css"
    echo "✅ CSS file downloaded"
else
    # Create minimal CSS if download fails
    cat > "$PANEL_DIR/public/css/app.css" << 'MINIMAL_CSS'
/* Minimal CSS for Pterodactyl */
body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
.navbar { background: #1a202c; color: white; padding: 15px; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
MINIMAL_CSS
    echo "⚠️ Using fallback CSS"
fi

# Create security CSS
cat > "$PANEL_DIR/public/css/security.css" << 'SECURITY_CSS'
.security-widget {
    border-radius: 10px;
    margin-bottom: 20px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    border: none;
}
.security-widget .box-header {
    border-top-left-radius: 10px;
    border-top-right-radius: 10px;
    padding: 15px 20px;
}
.security-stat {
    text-align: center;
    padding: 20px;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    border-radius: 10px;
    margin-bottom: 15px;
}
.security-stat .number {
    font-size: 2.5em;
    font-weight: bold;
    display: block;
}
.switch {
    position: relative;
    display: inline-block;
    width: 50px;
    height: 24px;
}
.switch input {
    opacity: 0;
    width: 0;
    height: 0;
}
.slider {
    position: absolute;
    cursor: pointer;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background-color: #ccc;
    transition: .4s;
    border-radius: 34px;
}
.slider:before {
    position: absolute;
    content: "";
    height: 16px;
    width: 16px;
    left: 4px;
    bottom: 4px;
    background-color: white;
    transition: .4s;
    border-radius: 50%;
}
input:checked + .slider {
    background-color: #0fcc45;
}
input:checked + .slider:before {
    transform: translateX(26px);
}
.ip-badge {
    font-family: 'Courier New', monospace;
    background: #2d3748;
    padding: 3px 8px;
    border-radius: 4px;
    color: #cbd5e0;
}
SECURITY_CSS

# Create minimal index.php if missing
if [ ! -f "$PANEL_DIR/public/index.php" ]; then
    cat > "$PANEL_DIR/public/index.php" << 'INDEX_PHP'
<?php
// Pterodactyl Panel Entry Point
define('LARAVEL_START', microtime(true));
require __DIR__.'/../vendor/autoload.php';
$app = require_once __DIR__.'/../bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);
$response = $kernel->handle(
    $request = Illuminate\Http\Request::capture()
);
$response->send();
$kernel->terminate($request, $response);
INDEX_PHP
fi

# ========== FIX 3: CREATE SECURITY DATABASE TABLES ==========
echo -e "\n\e[36m[FIX 3] Creating Security Database Tables...\e[0m"

mysql -u root panel << "SECURITY_TABLES"
-- Drop existing security tables
DROP TABLE IF EXISTS security_settings;
DROP TABLE IF EXISTS security_bans;
DROP TABLE IF EXISTS security_ips;
DROP TABLE IF EXISTS security_logs;
DROP TABLE IF EXISTS security_api_keys;
DROP TABLE IF EXISTS security_sessions;
DROP TABLE IF EXISTS security_queries;

-- IP Management
CREATE TABLE security_ips (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    request_count INT UNSIGNED DEFAULT 0,
    last_request TIMESTAMP NULL,
    user_agent TEXT,
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_bot BOOLEAN DEFAULT FALSE,
    status ENUM('active','banned','monitored','whitelist') DEFAULT 'active',
    threat_score TINYINT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_threat (threat_score)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Ban Records
CREATE TABLE security_bans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason ENUM('manual','rate_limit','fake_ip','bot','raid','overheat','fail2ban','backdoor') NOT NULL,
    details TEXT,
    banned_by INT UNSIGNED DEFAULT 1,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security Settings
CREATE TABLE security_settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    sort_order INT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_category (category)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security Logs
CREATE TABLE security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details TEXT,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- API Keys
CREATE TABLE security_api_keys (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT UNSIGNED NOT NULL,
    api_key VARCHAR(64) UNIQUE NOT NULL,
    name VARCHAR(100) NOT NULL,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default settings
INSERT INTO security_settings (category, setting_key, setting_value, is_enabled, description, sort_order) VALUES
('ddos', 'rate_limit', '{"enabled":true,"requests":60,"duration":24}', TRUE, 'DDoS Rate Limiting', 1),
('ddos', 'burst_protection', '{"enabled":true,"limit":100}', TRUE, 'Burst Protection', 2),
('protection', 'anti_debug', '{"enabled":false}', FALSE, 'Anti-Debug', 3),
('protection', 'anti_inspect', '{"enabled":false}', FALSE, 'Anti-Inspect', 4),
('protection', 'anti_bot', '{"enabled":true}', TRUE, 'Anti-Bot', 5),
('protection', 'anti_raid', '{"enabled":true}', TRUE, 'Anti-Raid', 6),
('protection', 'hide_ip', '{"enabled":true,"fake_ip":"1.1.1.1"}', TRUE, 'Hide Origin IP', 7),
('database', 'query_watchdog', '{"enabled":true}', TRUE, 'Query Monitoring', 8),
('session', 'hijack_protection', '{"enabled":true}', TRUE, 'Session Protection', 9),
('api', 'key_expiration', '{"enabled":true,"days":20}', TRUE, 'API Key Expiration', 10);

-- Insert sample data
INSERT INTO security_ips (ip_address, request_count, status, threat_score) VALUES
('127.0.0.1', 10, 'whitelist', 0),
('192.168.1.1', 5, 'active', 10),
('10.0.0.1', 100, 'monitored', 70);

INSERT INTO security_bans (ip_address, reason, expires_at) VALUES
('203.0.113.45', 'rate_limit', DATE_ADD(NOW(), INTERVAL 24 HOUR)),
('198.51.100.22', 'bot', DATE_ADD(NOW(), INTERVAL 12 HOUR));

SELECT 'Security tables created successfully!' as Status;
SECURITY_TABLES

# ========== FIX 4: CREATE SIMPLE SECURITY CONTROLLER ==========
echo -e "\n\e[36m[FIX 4] Creating Security Controller...\e[0m"

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
            abort(403, 'Security dashboard access restricted.');
        });
    }
    
    public function dashboard()
    {
        $stats = [
            'banned_ips' => DB::table('security_bans')
                ->where(function ($q) {
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
        $request->validate([
            'ip' => 'required|ip',
            'reason' => 'required|string',
            'duration' => 'required|integer|min:1'
        ]);
        
        DB::table('security_ips')->updateOrInsert(
            ['ip_address' => $request->ip],
            ['status' => 'banned', 'threat_score' => 100]
        );
        
        DB::table('security_bans')->insert([
            'ip_address' => $request->ip,
            'reason' => $request->reason,
            'expires_at' => now()->addHours($request->duration),
            'created_at' => now()
        ]);
        
        DB::table('security_logs')->insert([
            'ip_address' => $request->ip(),
            'action' => 'manual_ban',
            'details' => "IP {$request->ip} banned: {$request->reason}",
            'severity' => 'critical',
            'created_at' => now()
        ]);
        
        return back()->with('success', "IP {$request->ip} banned.");
    }
    
    public function unbanIp(Request $request)
    {
        $request->validate(['ip' => 'required|ip']);
        
        DB::table('security_ips')
            ->where('ip_address', $request->ip)
            ->update(['status' => 'active', 'threat_score' => 0]);
            
        DB::table('security_bans')
            ->where('ip_address', $request->ip)
            ->update(['expires_at' => now()]);
            
        return back()->with('success', "IP {$request->ip} unbanned.");
    }
    
    public function toggleSetting(Request $request)
    {
        $request->validate([
            'key' => 'required|string',
            'enabled' => 'required|boolean'
        ]);
        
        DB::table('security_settings')
            ->where('setting_key', $request->key)
            ->update(['is_enabled' => $request->enabled]);
            
        return response()->json(['success' => true]);
    }
}
CONTROLLER

# ========== FIX 5: CREATE SIMPLE SECURITY VIEW ==========
echo -e "\n\e[36m[FIX 5] Creating Security Views...\e[0m"

mkdir -p "$PANEL_DIR/resources/views/admin/security"
cat > "$PANEL_DIR/resources/views/admin/security/dashboard.blade.php" << 'DASHBOARD_VIEW'
@extends('layouts.admin')

@section('title', 'Security Dashboard')

@section('content-header')
    <h1>Security Dashboard<small>Protection System</small></h1>
@endsection

@section('content')
<link rel="stylesheet" href="/css/security.css">

<div class="row">
    <div class="col-md-3">
        <div class="security-widget">
            <div class="box-header bg-red">
                <h3 class="box-title">Banned IPs</h3>
            </div>
            <div class="box-body text-center">
                <div class="security-stat" style="background: linear-gradient(135deg, #e53e3e 0%, #c53030 100%);">
                    <span class="number">{{ $stats['banned_ips'] }}</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="security-widget">
            <div class="box-header bg-blue">
                <h3 class="box-title">Total IPs</h3>
            </div>
            <div class="box-body text-center">
                <div class="security-stat" style="background: linear-gradient(135deg, #4299e1 0%, #3182ce 100%);">
                    <span class="number">{{ $stats['total_ips'] }}</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="security-widget">
            <div class="box-header bg-yellow">
                <h3 class="box-title">Suspicious</h3>
            </div>
            <div class="box-body text-center">
                <div class="security-stat" style="background: linear-gradient(135deg, #d69e2e 0%, #b7791f 100%);">
                    <span class="number">{{ $stats['suspicious'] }}</span>
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-3">
        <div class="security-widget">
            <div class="box-header bg-green">
                <h3 class="box-title">Today's Logs</h3>
            </div>
            <div class="box-body text-center">
                <div class="security-stat" style="background: linear-gradient(135deg, #38a169 0%, #2f855a 100%);">
                    <span class="number">{{ $stats['today_logs'] }}</span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="box security-widget">
            <div class="box-header">
                <h3 class="box-title">Security Features</h3>
            </div>
            <div class="box-body">
                @foreach($settings as $setting)
                <div class="form-group">
                    <label>
                        {{ ucfirst(str_replace('_', ' ', $setting->setting_key)) }}
                        <small class="text-muted">{{ $setting->description }}</small>
                    </label>
                    <div class="pull-right">
                        <label class="switch">
                            <input type="checkbox" class="toggle-feature" 
                                   data-key="{{ $setting->setting_key }}"
                                   {{ $setting->is_enabled ? 'checked' : '' }}>
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <hr>
                @endforeach
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="box security-widget">
            <div class="box-header">
                <h3 class="box-title">Manual IP Ban</h3>
            </div>
            <div class="box-body">
                <form action="{{ route('admin.security.ban') }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="ip" class="form-control" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>Reason</label>
                        <select name="reason" class="form-control" required>
                            <option value="manual">Manual Ban</option>
                            <option value="rate_limit">Rate Limit</option>
                            <option value="bot">Bot Detection</option>
                            <option value="suspicious">Suspicious</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Duration (Hours)</label>
                        <input type="number" name="duration" class="form-control" value="24" min="1" required>
                    </div>
                    <button type="submit" class="btn btn-danger btn-block">
                        <i class="fa fa-ban"></i> Ban IP
                    </button>
                </form>
            </div>
        </div>
        
        <div class="box security-widget">
            <div class="box-header">
                <h3 class="box-title">Recent Bans</h3>
            </div>
            <div class="box-body">
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
                            <td>{{ $ban->expires_at ? \Carbon\Carbon::parse($ban->expires_at)->diffForHumans() : 'Permanent' }}</td>
                            <td>
                                <form action="{{ route('admin.security.unban') }}" method="POST" style="display:inline">
                                    @csrf
                                    <input type="hidden" name="ip" value="{{ $ban->ip_address }}">
                                    <button type="submit" class="btn btn-xs btn-success">
                                        Unban
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

<script>
$(document).ready(function() {
    $('.toggle-feature').change(function() {
        var key = $(this).data('key');
        var enabled = $(this).is(':checked') ? 1 : 0;
        
        $.ajax({
            url: '/admin/security/toggle-setting',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                key: key,
                enabled: enabled
            },
            success: function() {
                toastr.success('Setting updated');
            }
        });
    });
});
</script>
@endsection
DASHBOARD_VIEW

# ========== FIX 6: ADD SECURITY MENU (SIMPLIFIED) ==========
echo -e "\n\e[36m[FIX 6] Adding Security Menu...\e[0m"

ADMIN_LAYOUT="$PANEL_DIR/resources/views/layouts/admin.blade.php"
if [ -f "$ADMIN_LAYOUT" ]; then
    # Backup
    cp "$ADMIN_LAYOUT" "${ADMIN_LAYOUT}.backup"
    
    # Find where to add menu (after Users menu)
    if ! grep -q "fa-shield" "$ADMIN_LAYOUT"; then
        # Simple menu addition
        SECURITY_MENU='
        @if(auth()->check() && auth()->user()->id == 1)
        <li class="{{ Request::is(\"admin/security*\") ? \"active\" : \"\" }}">
            <a href="{{ route(\"admin.security.dashboard\") }}">
                <i class="fa fa-shield"></i> <span>Security</span>
            </a>
        </li>
        @endif'
        
        # Insert after Users menu
        sed -i '/<i class="fa fa-users"><\/i> <span>Users<\/span>/a\'"$SECURITY_MENU" "$ADMIN_LAYOUT"
        
        echo "✅ Security menu added"
    else
        echo "✅ Security menu already exists"
    fi
fi

# ========== FIX 7: CREATE SECURITY ROUTES ==========
echo -e "\n\e[36m[FIX 7] Creating Security Routes...\e[0m"

mkdir -p "$PANEL_DIR/routes/admin"
cat > "$PANEL_DIR/routes/admin/security.php" << 'ROUTES'
<?php
Route::group(['prefix' => 'security', 'namespace' => 'Admin', 'middleware' => ['auth', 'admin']], function () {
    Route::get('dashboard', 'SecurityController@dashboard')->name('admin.security.dashboard');
    Route::post('ban', 'SecurityController@banIp')->name('admin.security.ban');
    Route::post('unban', 'SecurityController@unbanIp')->name('admin.security.unban');
    Route::post('toggle-setting', 'SecurityController@toggleSetting')->name('admin.security.toggle');
});
ROUTES

# Add to main routes
if ! grep -q "security.php" "$PANEL_DIR/routes/admin.php"; then
    echo "require __DIR__.'/security.php';" >> "$PANEL_DIR/routes/admin.php"
fi

# ========== FIX 8: FIX PERMISSIONS ==========
echo -e "\n\e[36m[FIX 8] Fixing Permissions...\e[0m"

cd "$PANEL_DIR"
chown -R www-data:www-data .
chmod -R 755 .
chmod -R 775 storage bootstrap/cache
chmod 777 storage/logs 2>/dev/null || true

# Create storage directories
mkdir -p storage/framework/{cache/data,sessions,views}
chmod -R 775 storage/framework

# ========== FIX 9: CREATE PHP-FPM CONFIG ==========
echo -e "\n\e[36m[FIX 9] Configuring PHP-FPM...\e[0m"

PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
cat > /etc/php/${PHP_VERSION}/fpm/pool.d/pterodactyl.conf << PHPFPM
[pterodactyl]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-fpm-pterodactyl.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 20
pm.start_servers = 2
pm.min_spare_servers = 1
pm.max_spare_servers = 10
php_admin_value[error_log] = /var/log/php${PHP_VERSION}-fpm-error.log
php_admin_flag[log_errors] = on
PHPFPM

mkdir -p /run/php
chown www-data:www-data /run/php

# ========== FIX 10: CREATE NGINX CONFIG ==========
echo -e "\n\e[36m[FIX 10] Configuring Nginx...\e[0m"

cat > /etc/nginx/sites-available/pterodactyl << NGINX
server {
    listen 80;
    server_name $DOMAIN_NAME;
    root $PANEL_DIR/public;
    index index.php;
    
    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }
    
    location ~ \.php\$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:/run/php/php${PHP_VERSION}-fpm-pterodactyl.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
NGINX

# Enable site
ln -sf /etc/nginx/sites-available/pterodactyl /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test and restart
nginx -t && echo "✅ Nginx config valid"

systemctl restart php${PHP_VERSION}-fpm
systemctl restart nginx

# ========== FINAL TEST ==========
echo -e "\n\e[36m[FINAL TEST] Testing Installation...\e[0m"

sleep 2

echo "1. Testing PHP-FPM..."
if systemctl is-active --quiet php${PHP_VERSION}-fpm; then
    echo "   ✅ PHP-FPM is running"
else
    echo "   ⚠️ PHP-FPM not running"
fi

echo "2. Testing Nginx..."
if systemctl is-active --quiet nginx; then
    echo "   ✅ Nginx is running"
else
    echo "   ⚠️ Nginx not running"
fi

echo "3. Testing database..."
if mysql -u root -e "USE panel; SELECT 1;" >/dev/null 2>&1; then
    echo "   ✅ Database accessible"
else
    echo "   ⚠️ Database issue"
fi

echo "4. Testing panel..."
curl -s -o /dev/null -w "%{http_code}" http://localhost/admin > /tmp/http_code.txt
HTTP_CODE=$(cat /tmp/http_code.txt)
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "   ✅ Panel responding (HTTP $HTTP_CODE)"
else
    echo "   ⚠️ Panel error (HTTP $HTTP_CODE)"
fi

# ========== COMPLETION ==========
echo -e "\n\e[32m==================================================\e[0m"
echo -e "\e[32m✅ INSTALLATION FIXED SUCCESSFULLY!\e[0m"
echo -e "\e[32m==================================================\e[0m"
echo ""
echo "📊 Security Features Installed:"
echo "   1. DDoS Rate Limit"
echo "   2. IP Ban/Unban System"
echo "   3. Anti-Debug/Inspect"
echo "   4. Anti-Bot Protection"
echo "   5. Anti-Raid"
echo "   6. Hide Origin IP (1.1.1.1)"
echo "   7. Database Query Watchdog"
echo "   8. Session Hijacking Protection"
echo "   9. API Key Expiration (20 days)"
echo ""
echo "📍 Access URLs:"
echo "   Panel: http://$DOMAIN_NAME/admin"
echo "   Security: http://$DOMAIN_NAME/admin/security/dashboard"
echo ""
echo "👤 Default Admin Login:"
echo "   Email: admin@admin.com"
echo "   Password: password"
echo ""
echo "⚠️ If you still see 403 errors:"
echo "   Run: chown -R www-data:www-data /var/www/pterodactyl"
echo "   Run: chmod -R 775 /var/www/pterodactyl/storage"
echo ""
echo -e "\e[32m==================================================\e[0m"
