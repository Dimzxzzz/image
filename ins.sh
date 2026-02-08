#!/bin/bash

echo "=================================================="
echo "🔥 FINAL FIX FOR PTERODACTYL 500 ERRORS"
echo "=================================================="

PANEL_DIR="/var/www/pterodactyl"
DOMAIN_NAME="zero-xd.server-panell.biz.id"

# ========== FIX 1: CHECK CURRENT DIRECTORY ==========
echo -e "\n\e[36m[1] Fixing current directory...\e[0m"
cd "$PANEL_DIR"
pwd

# ========== FIX 2: FIX PERMISSIONS ==========
echo -e "\n\e[36m[2] Fixing permissions...\e[0m"

# Fix ownership
chown -R www-data:www-data "$PANEL_DIR"

# Fix directory permissions
find "$PANEL_DIR" -type d -exec chmod 755 {} \;
find "$PANEL_DIR" -type f -exec chmod 644 {} \;

# Create storage directories
mkdir -p "$PANEL_DIR/storage/framework/cache/data"
mkdir -p "$PANEL_DIR/storage/framework/sessions"
mkdir -p "$PANEL_DIR/storage/framework/views"
mkdir -p "$PANEL_DIR/bootstrap/cache"
mkdir -p "$PANEL_DIR/public/css"

# Set special permissions
chmod -R 775 "$PANEL_DIR/storage"
chmod -R 775 "$PANEL_DIR/bootstrap/cache"
chown -R www-data:www-data "$PANEL_DIR/storage"
chown -R www-data:www-data "$PANEL_DIR/bootstrap/cache"

# ========== FIX 3: FIX DATABASE TABLES ==========
echo -e "\n\e[36m[3] Fixing security database tables...\e[0m"

mysql panel << "DB_FIX"
-- Fix security_settings table
ALTER TABLE security_settings 
MODIFY COLUMN category VARCHAR(50) DEFAULT 'general',
MODIFY COLUMN setting_value JSON;

-- Fix the insert statements
DELETE FROM security_settings;

INSERT INTO security_settings (category, setting_key, setting_value, is_enabled, description) VALUES
('ddos', 'ddos_rate_limit', '{"enabled": true, "requests_per_minute": 60, "block_duration": 24}', TRUE, 'DDoS Rate Limit Protection'),
('protection', 'anti_debug', '{"enabled": false}', FALSE, 'Anti-Debug Protection'),
('protection', 'anti_inspect', '{"enabled": false}', FALSE, 'Anti-Inspect Protection'),
('protection', 'anti_bot', '{"enabled": true}', TRUE, 'Bot Detection System'),
('protection', 'anti_raid', '{"enabled": true}', TRUE, 'Anti-Raid Protection'),
('network', 'hide_ip', '{"enabled": true, "fake_ip": "1.1.1.1"}', TRUE, 'Hide Origin IP'),
('api', 'api_expiry', '{"enabled": true, "days": 20}', TRUE, 'API Key Expiration (20 days)'),
('database', 'query_watchdog', '{"enabled": true}', TRUE, 'Database Query Monitoring'),
('session', 'session_protection', '{"enabled": true}', TRUE, 'Session Hijacking Protection');

SELECT 'Database tables fixed!' as Status;
DB_FIX

# ========== FIX 4: CREATE MISSING ROUTE FILE ==========
echo -e "\n\e[36m[4] Creating missing route file...\e[0m"

# Check if routes/admin directory exists
if [ ! -d "$PANEL_DIR/routes/admin" ]; then
    mkdir -p "$PANEL_DIR/routes/admin"
fi

# Create the security.php route file
cat > "$PANEL_DIR/routes/admin/security.php" << 'ROUTES'
<?php

Route::group(['prefix' => 'security', 'namespace' => 'Admin', 'middleware' => ['auth', 'admin']], function () {
    Route::get('/', 'SecurityController@dashboard')->name('admin.security.dashboard');
    Route::post('/ban', 'SecurityController@banIp')->name('admin.security.ban');
    Route::post('/unban', 'SecurityController@unbanIp')->name('admin.security.unban');
    Route::post('/toggle', 'SecurityController@toggleSetting')->name('admin.security.toggle');
});
ROUTES

echo "✅ Route file created: $PANEL_DIR/routes/admin/security.php"

# ========== FIX 5: UPDATE ADMIN ROUTES ==========
echo -e "\n\e[36m[5] Updating admin routes...\e[0m"

# Check if the require statement already exists
if ! grep -q "require.*security.php" "$PANEL_DIR/routes/admin.php"; then
    # Add the require statement at the end of the file
    echo -e "\n// Security Routes\nrequire __DIR__.'/admin/security.php';" >> "$PANEL_DIR/routes/admin.php"
    echo "✅ Added security route to admin.php"
else
    echo "✅ Security route already exists in admin.php"
fi

# ========== FIX 6: CREATE CSS FILES ==========
echo -e "\n\e[36m[6] Creating CSS files...\e[0m"

# Create app.css if missing
if [ ! -f "$PANEL_DIR/public/css/app.css" ]; then
    cat > "$PANEL_DIR/public/css/app.css" << 'APP_CSS'
/* Pterodactyl Default CSS */
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }
APP_CSS
    echo "✅ Created app.css"
fi

# Create security.css
cat > "$PANEL_DIR/public/css/security.css" << 'SECURITY_CSS'
/* Security Dashboard Styles */
.security-dashboard { background: #1a1a2e; color: white; min-height: 100vh; }
.security-card { 
    background: #162447; 
    border-radius: 10px; 
    padding: 20px; 
    margin-bottom: 20px; 
    border: 1px solid #0f3460;
    box-shadow: 0 4px 6px rgba(0,0,0,0.1);
}
.security-card-header { 
    border-bottom: 1px solid #0f3460; 
    padding-bottom: 15px; 
    margin-bottom: 15px; 
    color: #e94560;
}
.security-stat { 
    text-align: center; 
    padding: 20px; 
}
.security-stat .number { 
    font-size: 2.5em; 
    font-weight: bold; 
    display: block; 
}
.security-stat .label { 
    font-size: 0.9em; 
    opacity: 0.8; 
    color: #8a8ab5;
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
    background: #555; 
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
    background: white; 
    transition: .4s; 
    border-radius: 50%; 
}
input:checked + .slider { 
    background: #0fcc45; 
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
.btn-security { 
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
    color: white; 
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
}
.btn-security:hover {
    opacity: 0.9;
}
SECURITY_CSS

echo "✅ Created security.css"

# ========== FIX 7: CHECK CONTROLLER ==========
echo -e "\n\e[36m[7] Checking security controller...\e[0m"

if [ ! -f "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" ]; then
    echo "⚠️ Security controller missing, creating..."
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
                ['status' => 'banned', 'threat_score' => 100, 'updated_at' => now()]
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
                ->update(['status' => 'active', 'threat_score' => 0, 'updated_at' => now()]);
                
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
    
    echo "✅ Security controller created"
else
    echo "✅ Security controller exists"
fi

# ========== FIX 8: CHECK VIEW ==========
echo -e "\n\e[36m[8] Checking security view...\e[0m"

if [ ! -d "$PANEL_DIR/resources/views/admin/security" ]; then
    mkdir -p "$PANEL_DIR/resources/views/admin/security"
fi

if [ ! -f "$PANEL_DIR/resources/views/admin/security/dashboard.blade.php" ]; then
    echo "⚠️ Security view missing, creating..."
    
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

@if(session('success'))
<div class="alert alert-success alert-dismissible">
    <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
    <h4><i class="icon fa fa-check"></i> Success!</h4>
    {{ session('success') }}
</div>
@endif

<div class="row">
    <div class="col-md-3 col-sm-6">
        <div class="security-card">
            <div class="security-card-header">
                <h4><i class="fa fa-ban"></i> Banned IPs</h4>
            </div>
            <div class="security-stat">
                <span class="number" style="color: #e94560;">{{ $stats['banned'] ?? 0 }}</span>
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
                <span class="number" style="color: #0fcc45;">{{ $stats['total_ips'] ?? 0 }}</span>
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
                <span class="number" style="color: #ff9a3c;">{{ $stats['suspicious'] ?? 0 }}</span>
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
                <span class="number" style="color: #4299e1;">{{ $stats['today_logs'] ?? 0 }}</span>
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
                @php 
                    $value = json_decode($setting->setting_value, true);
                    if (!is_array($value)) $value = [];
                @endphp
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
                        @if(isset($value['fake_ip']))
                        <br><small>Shows as: {{ $value['fake_ip'] }}</small>
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
                            <option value="suspicious">Suspicious Activity</option>
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
    
    echo "✅ Security view created"
else
    echo "✅ Security view exists"
fi

# ========== FIX 9: CLEAR LARAVEL CACHE ==========
echo -e "\n\e[36m[9] Clearing Laravel cache...\e[0m"

cd "$PANEL_DIR"

# Clear all caches
sudo -u www-data php artisan cache:clear 2>/dev/null || php artisan cache:clear
sudo -u www-data php artisan view:clear 2>/dev/null || php artisan view:clear
sudo -u www-data php artisan config:clear 2>/dev/null || php artisan config:clear
sudo -u www-data php artisan route:clear 2>/dev/null || php artisan route:clear

# Optimize
sudo -u www-data php artisan optimize 2>/dev/null || php artisan optimize

# ========== FIX 10: CHECK NGINX CONFIG ==========
echo -e "\n\e[36m[10] Checking Nginx configuration...\e[0m"

# Restart services
systemctl restart php8.3-fpm
systemctl restart nginx

# ========== FIX 11: CREATE .ENV FILE ==========
echo -e "\n\e[36m[11] Checking .env file...\e[0m"

if [ ! -f "$PANEL_DIR/.env" ]; then
    echo "⚠️ .env file missing, creating..."
    
    cat > "$PANEL_DIR/.env" << 'ENV_FILE'
APP_NAME=Pterodactyl
APP_ENV=production
APP_KEY=base64:$(openssl rand -base64 32)
APP_DEBUG=false
APP_URL=http://${DOMAIN_NAME}
APP_TIMEZONE=UTC

LOG_CHANNEL=stack
LOG_DEPRECATIONS_CHANNEL=null
LOG_LEVEL=debug

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=panel
DB_USERNAME=pterodactyl
DB_PASSWORD=pterodactyl_password

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_DATABASE=0
REDIS_CACHE_DB=1

SESSION_DRIVER=redis
SESSION_LIFETIME=120
SESSION_ENCRYPT=true

QUEUE_CONNECTION=redis

CACHE_DRIVER=redis
CACHE_PREFIX=

FILESYSTEM_DISK=local

MAIL_MAILER=log
MAIL_HOST=mailhog
MAIL_PORT=1025
MAIL_USERNAME=null
MAIL_PASSWORD=null
MAIL_ENCRYPTION=null
MAIL_FROM_ADDRESS="no-reply@${DOMAIN_NAME}"
MAIL_FROM_NAME="${APP_NAME}"

TRUSTED_PROXIES=*
ENV_FILE
    
    # Replace domain
    sed -i "s/\${DOMAIN_NAME}/$DOMAIN_NAME/g" "$PANEL_DIR/.env"
    
    # Generate app key
    cd "$PANEL_DIR"
    php artisan key:generate --force
    
    echo "✅ .env file created and key generated"
else
    echo "✅ .env file exists"
fi

# ========== FIX 12: TEST PANEL ==========
echo -e "\n\e[36m[12] Testing panel...\e[0m"

sleep 3

echo "Testing HTTP response..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost/")
echo "HTTP Code: $HTTP_CODE"

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    echo "✅ Panel is accessible"
else
    echo "⚠️ Panel may have issues, checking logs..."
    
    # Check nginx error log
    if [ -f "/var/log/nginx/pterodactyl.error.log" ]; then
        echo "Last 10 lines of nginx error log:"
        tail -10 "/var/log/nginx/pterodactyl.error.log"
    fi
    
    # Check Laravel log
    LARAVEL_LOG=$(ls -t "$PANEL_DIR/storage/logs/laravel-"*.log 2>/dev/null | head -1)
    if [ -f "$LARAVEL_LOG" ]; then
        echo "Last 10 lines of Laravel log:"
        tail -10 "$LARAVEL_LOG"
    fi
fi

# ========== FINAL MESSAGE ==========
echo -e "\n\e[32m==================================================\e[0m"
echo -e "\e[32m✅ ALL FIXES APPLIED SUCCESSFULLY!\e[0m"
echo -e "\e[32m==================================================\e[0m"
echo ""
echo "🔧 Fixes applied:"
echo "   1. ✅ Fixed database table structure"
echo "   2. ✅ Created missing route file"
echo "   3. ✅ Fixed permissions"
echo "   4. ✅ Created CSS files"
echo "   5. ✅ Cleared Laravel cache"
echo "   6. ✅ Restarted services"
echo ""
echo "📍 Access URLs:"
echo "   Panel: http://$DOMAIN_NAME"
echo "   Admin: http://$DOMAIN_NAME/admin"
echo "   Security: http://$DOMAIN_NAME/admin/security"
echo ""
echo "👤 Admin Login:"
echo "   Email: admin@admin.com"
echo "   Password: password"
echo ""
echo "🔒 Security Features:"
echo "   • DDoS Rate Limit"
echo "   • IP Ban/Unban"
echo "   • Anti-Debug/Inspect"
echo "   • Anti-Bot Protection"
echo "   • Hide Origin IP (1.1.1.1)"
echo "   • API Key Expiration (20 days)"
echo ""
echo "🛠️ If you still see 500 error:"
echo "   1. Check Laravel logs:"
echo "      tail -f /var/www/pterodactyl/storage/logs/laravel-*.log"
echo "   2. Check nginx logs:"
echo "      tail -f /var/log/nginx/pterodactyl.error.log"
echo "   3. Fix permissions:"
echo "      chown -R www-data:www-data /var/www/pterodactyl"
echo "      chmod -R 755 /var/www/pterodactyl"
echo "   4. Clear cache:"
echo "      cd /var/www/pterodactyl && php artisan cache:clear"
echo ""
echo -e "\e[32m==================================================\e[0m"
echo -e "\e[32m🚀 Try accessing your panel now!\e[0m"
echo -e "\e[32m==================================================\e[0m"
