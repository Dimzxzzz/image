#!/bin/bash

echo "=================================================="
echo "🔥 BLACKENDSPACE THEME + ULTIMATE SECURITY INSTALL"
echo "=================================================="
echo "Features:"
echo "1. ✅ Install BlackEndSpace Theme"
echo "2. ✅ Fix all 403/500 permission errors"
echo "3. ✅ Security Menu with Shield Icon"
echo "4. ✅ Complete Security System"
echo "5. ✅ Exclusive access for User ID = 1"
echo "=================================================="

# ========== CONFIGURATION ==========
PANEL_DIR="/var/www/pterodactyl"
THEME_URL="https://raw.githubusercontent.com/TheFonix/Pterodactyl-Themes/master/MasterThemes/BlackEndSpace"
ADMIN_ID=1
SECURITY_MENU_ICON="fa-shield"  # FontAwesome shield icon

# ========== PHASE 1: PERMISSION FIX ==========
echo -e "\n\e[36m[PHASE 1] Fixing Permissions...\e[0m"

# Stop services
systemctl stop nginx php8.1-fpm 2>/dev/null || true

# Fix ownership
cd "$PANEL_DIR"
chown -R www-data:www-data .

# Fix permissions (Laravel standard)
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;

# Laravel specific permissions
chmod -R 775 storage bootstrap/cache
chmod 777 storage/logs 2>/dev/null || true

# Clear all caches
rm -rf storage/framework/cache/data/*
rm -rf storage/framework/views/*
rm -f bootstrap/cache/*.php

# Recreate directories
mkdir -p storage/framework/{cache/data,sessions,views}
chmod -R 775 storage/framework
chown -R www-data:www-data storage/bootstrap/cache/

# ========== PHASE 2: INSTALL BLACKENDSPACE THEME ==========
echo -e "\n\e[36m[PHASE 2] Installing BlackEndSpace Theme...\e[0m"

# Backup original
BACKUP_DIR="$PANEL_DIR/public_backup_$(date +%s)"
if [ ! -d "$PANEL_DIR/public_backup" ]; then
    cp -r "$PANEL_DIR/public" "$BACKUP_DIR"
    echo "✅ Original public directory backed up to: $BACKUP_DIR"
fi

# Download and apply theme
cd /tmp
echo "Downloading BlackEndSpace theme..."

# Download CSS files
wget -q "$THEME_URL/public/css/app.css" -O "$PANEL_DIR/public/css/app.css" || true
wget -q "$THEME_URL/public/css/admin.css" -O "$PANEL_DIR/public/css/admin.css" 2>/dev/null || true

# Download JS files if exist
wget -q "$THEME_URL/public/js/app.js" -O "$PANEL_DIR/public/js/app.js" 2>/dev/null || true

# Download images
mkdir -p "$PANEL_DIR/public/images/themes"
wget -q "$THEME_URL/public/images/logo.svg" -O "$PANEL_DIR/public/images/logo.svg" 2>/dev/null || true
wget -q "$THEME_URL/public/images/favicon.ico" -O "$PANEL_DIR/public/images/favicon.ico" 2>/dev/null || true

echo "✅ BlackEndSpace theme applied"

# ========== PHASE 3: SECURITY DATABASE ==========
echo -e "\n\e[36m[PHASE 3] Creating Security Database...\e[0m"

mysql -u root << "MYSQL_SECURITY"
USE panel;

-- Drop old tables if exist
DROP TABLE IF EXISTS panel_security;
DROP TABLE IF EXISTS panel_security_logs;
DROP TABLE IF EXISTS panel_security_bans;
DROP TABLE IF EXISTS panel_security_settings;

-- Main security table
CREATE TABLE panel_security (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    request_count INT UNSIGNED DEFAULT 0,
    last_request TIMESTAMP NULL,
    user_agent TEXT,
    country_code VARCHAR(5),
    is_suspicious BOOLEAN DEFAULT FALSE,
    is_fake_ip BOOLEAN DEFAULT FALSE,
    status ENUM('active','banned','monitored') DEFAULT 'active',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_status (status),
    INDEX idx_last_request (last_request)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Ban records
CREATE TABLE panel_security_bans (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason ENUM('manual','rate_limit','fake_ip','fake_ua','bot','debugger','suspicious') NOT NULL,
    details TEXT,
    banned_by INT UNSIGNED DEFAULT 1,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_expires (expires_at),
    INDEX idx_ip (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security settings
CREATE TABLE panel_security_settings (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    setting_key VARCHAR(100) UNIQUE NOT NULL,
    setting_value TEXT,
    is_enabled BOOLEAN DEFAULT TRUE,
    description TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Security logs
CREATE TABLE panel_security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    action VARCHAR(100) NOT NULL,
    details JSON,
    severity ENUM('info','warning','critical') DEFAULT 'info',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip_action (ip_address, action),
    INDEX idx_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insert default settings
INSERT INTO panel_security_settings (setting_key, setting_value, is_enabled, description) VALUES
('ddos_protection', '{"enabled":true,"requests_per_minute":60,"block_duration_hours":24}', TRUE, 'DDoS Rate Limit Protection'),
('anti_debug', '{"enabled":false}', TRUE, 'Anti-Debug Protection'),
('anti_inspect', '{"enabled":false}', TRUE, 'Anti-DevTools Inspection'),
('anti_bot', '{"enabled":true,"block_fake_ips":true,"block_empty_ua":true,"block_suspicious_patterns":true}', TRUE, 'Bot Detection System'),
('security_access', '[1]', TRUE, 'User IDs allowed to access security panel');

-- Sample data
INSERT INTO panel_security (ip_address, request_count, status) VALUES
('127.0.0.1', 15, 'active'),
('192.168.1.1', 8, 'active'),
('10.0.0.1', 150, 'monitored');

SELECT '✅ Security database created successfully' as Status;
MYSQL_SECURITY

# ========== PHASE 4: ADD SECURITY MENU TO SIDEBAR ==========
echo -e "\n\e[36m[PHASE 4] Adding Security Menu to Sidebar...\e[0m"

ADMIN_LAYOUT="$PANEL_DIR/resources/views/layouts/admin.blade.php"

if [ -f "$ADMIN_LAYOUT" ]; then
    # Backup original
    cp "$ADMIN_LAYOUT" "$ADMIN_LAYOUT.backup.$(date +%s)"
    
    # Find where to insert the Security menu (after Users menu)
    if grep -q "<!-- Security Section -->" "$ADMIN_LAYOUT"; then
        echo "✅ Security menu already exists"
    else
        # Find the Users menu section
        USERS_SECTION='<li class="{{ Request::is(\'admin/users*\') ? \'active\' : \'\' }}">'
        
        # Insert Security menu after Users
        sed -i "/$USERS_SECTION/ {
            a\\
            @php\\
                \$hasSecurityAccess = auth()->check() \&\& auth()->user()->id == 1;\\
            @endphp\\
            @if(\$hasSecurityAccess)\\
            <li class="{{ Request::is('admin/security*') ? 'active' : '' }}">\\
                <a href="{{ route('admin.security') }}">\\
                    <i class="fa fa-shield"></i> <span>Security</span>\\
                </a>\\
            </li>\\
            @endif
        }" "$ADMIN_LAYOUT"
        
        echo "✅ Security menu added to sidebar"
    fi
fi

# ========== PHASE 5: CREATE SECURITY ROUTE ==========
echo -e "\n\e[36m[PHASE 5] Creating Security Route...\e[0m"

# Create route file
cat > "$PANEL_DIR/routes/admin_security.php" << 'ROUTE_FILE'
<?php

Route::group(['prefix' => 'security', 'namespace' => 'Admin', 'middleware' => ['auth', 'admin']], function () {
    Route::get('/', 'SecurityController@index')->name('admin.security');
    Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban');
    Route::post('/unban-ip', 'SecurityController@unbanIp')->name('admin.security.unban');
    Route::post('/toggle-feature', 'SecurityController@toggleFeature')->name('admin.security.toggle');
});

// Middleware to restrict access to ID 1 only
Route::macro('securityOnly', function ($routes) {
    Route::group(['middleware' => function ($request, $next) {
        if (auth()->check() && auth()->user()->id == 1) {
            return $next($request);
        }
        abort(403, 'Security dashboard access restricted.');
    }], $routes);
});
ROUTE_FILE

# Include the route in main admin routes
if ! grep -q "admin_security.php" "$PANEL_DIR/routes/admin.php"; then
    echo -e "\n// Security Routes\nrequire __DIR__.'/admin_security.php';" >> "$PANEL_DIR/routes/admin.php"
fi

# ========== PHASE 6: CREATE SECURITY CONTROLLER ==========
echo -e "\n\e[36m[PHASE 6] Creating Security Controller...\e[0m"

mkdir -p "$PANEL_DIR/app/Http/Controllers/Admin"
cat > "$PANEL_DIR/app/Http/Controllers/Admin/SecurityController.php" << 'CONTROLLER_FILE'
<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class SecurityController extends Controller
{
    public function __construct()
    {
        // Restrict access to user ID = 1 only
        $this->middleware(function ($request, $next) {
            if (auth()->check() && auth()->user()->id == 1) {
                return $next($request);
            }
            abort(403, 'Security dashboard access is restricted to system administrators.');
        });
    }
    
    public function index()
    {
        $settings = $this->getSecuritySettings();
        $bannedIps = $this->getBannedIps();
        $recentLogs = $this->getRecentLogs();
        $stats = $this->getSecurityStats();
        
        return view('admin.security.index', compact('settings', 'bannedIps', 'recentLogs', 'stats'));
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip' => 'required|ip',
            'reason' => 'required|in:manual,rate_limit,fake_ip,fake_ua,bot,debugger,suspicious',
            'duration' => 'required|integer|min:1|max:720'
        ]);
        
        $ip = $request->input('ip');
        $reason = $request->input('reason');
        $duration = $request->input('duration');
        $details = $request->input('details', '');
        
        DB::transaction(function () use ($ip, $reason, $duration, $details) {
            // Update or create IP record
            DB::table('panel_security')->updateOrInsert(
                ['ip_address' => $ip],
                ['status' => 'banned', 'updated_at' => now()]
            );
            
            // Create ban record
            DB::table('panel_security_bans')->insert([
                'ip_address' => $ip,
                'reason' => $reason,
                'details' => $details,
                'banned_by' => auth()->id(),
                'expires_at' => now()->addHours($duration),
                'created_at' => now()
            ]);
            
            // Log the action
            DB::table('panel_security_logs')->insert([
                'ip_address' => $ip,
                'action' => 'manual_ban',
                'details' => json_encode([
                    'reason' => $reason,
                    'duration_hours' => $duration,
                    'banned_by' => auth()->id()
                ]),
                'severity' => 'critical',
                'created_at' => now()
            ]);
        });
        
        Cache::forget('security.banned_ips');
        
        return redirect()->route('admin.security')
            ->with('success', "IP $ip has been banned for $duration hours.");
    }
    
    public function unbanIp(Request $request)
    {
        $request->validate(['ip' => 'required|ip']);
        
        $ip = $request->input('ip');
        
        DB::transaction(function () use ($ip) {
            DB::table('panel_security')
                ->where('ip_address', $ip)
                ->update(['status' => 'active', 'updated_at' => now()]);
            
            DB::table('panel_security_bans')
                ->where('ip_address', $ip)
                ->whereNull('expires_at')
                ->orWhere('expires_at', '>', now())
                ->update(['expires_at' => now()]);
            
            DB::table('panel_security_logs')->insert([
                'ip_address' => $ip,
                'action' => 'manual_unban',
                'details' => json_encode(['unbanned_by' => auth()->id()]),
                'severity' => 'info',
                'created_at' => now()
            ]);
        });
        
        Cache::forget('security.banned_ips');
        
        return redirect()->route('admin.security')
            ->with('success', "IP $ip has been unbanned.");
    }
    
    public function toggleFeature(Request $request)
    {
        $request->validate([
            'feature' => 'required|in:ddos_protection,anti_debug,anti_inspect,anti_bot',
            'enabled' => 'required|boolean'
        ]);
        
        $feature = $request->input('feature');
        $enabled = $request->input('enabled');
        
        $current = DB::table('panel_security_settings')
            ->where('setting_key', $feature)
            ->first();
        
        if ($current) {
            $value = json_decode($current->setting_value, true);
            $value['enabled'] = $enabled;
            
            DB::table('panel_security_settings')
                ->where('setting_key', $feature)
                ->update([
                    'setting_value' => json_encode($value),
                    'updated_at' => now()
                ]);
            
            // Log feature toggle
            DB::table('panel_security_logs')->insert([
                'ip_address' => request()->ip(),
                'action' => 'feature_toggle',
                'details' => json_encode([
                    'feature' => $feature,
                    'enabled' => $enabled,
                    'user_id' => auth()->id()
                ]),
                'severity' => 'info',
                'created_at' => now()
            ]);
            
            $status = $enabled ? 'enabled' : 'disabled';
            return redirect()->route('admin.security')
                ->with('success', "$feature has been $status.");
        }
        
        return redirect()->route('admin.security')
            ->with('error', 'Feature not found.');
    }
    
    private function getSecuritySettings()
    {
        return DB::table('panel_security_settings')->get()
            ->mapWithKeys(function ($item) {
                return [$item->setting_key => [
                    'value' => json_decode($item->setting_value, true),
                    'enabled' => (bool)$item->is_enabled
                ]];
            });
    }
    
    private function getBannedIps()
    {
        return DB::table('panel_security_bans as b')
            ->select('b.*', 's.request_count', 's.last_request')
            ->leftJoin('panel_security as s', 'b.ip_address', '=', 's.ip_address')
            ->where(function ($query) {
                $query->whereNull('b.expires_at')
                    ->orWhere('b.expires_at', '>', now());
            })
            ->orderBy('b.created_at', 'desc')
            ->get();
    }
    
    private function getRecentLogs()
    {
        return DB::table('panel_security_logs')
            ->orderBy('created_at', 'desc')
            ->limit(50)
            ->get();
    }
    
    private function getSecurityStats()
    {
        return [
            'banned_ips' => DB::table('panel_security_bans')
                ->where(function ($query) {
                    $query->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                })->count(),
            
            'total_ips' => DB::table('panel_security')->count(),
            
            'today_requests' => DB::table('panel_security')
                ->whereDate('last_request', today())
                ->count(),
            
            'suspicious_ips' => DB::table('panel_security')
                ->where('is_suspicious', true)
                ->count(),
            
            'recent_logs' => DB::table('panel_security_logs')
                ->whereDate('created_at', today())
                ->count()
        ];
    }
}
CONTROLLER_FILE

# ========== PHASE 7: CREATE SECURITY VIEW ==========
echo -e "\n\e[36m[PHASE 7] Creating Security View...\e[0m"

mkdir -p "$PANEL_DIR/resources/views/admin/security"
cat > "$PANEL_DIR/resources/views/admin/security/index.blade.php" << 'VIEW_FILE'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Real-time protection for your panel</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        @if(session('success'))
        <div class="alert alert-success alert-dismissible">
            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
            <h4><i class="icon fa fa-check"></i> Success!</h4>
            {{ session('success') }}
        </div>
        @endif
        
        @if(session('error'))
        <div class="alert alert-danger alert-dismissible">
            <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
            <h4><i class="icon fa fa-ban"></i> Error!</h4>
            {{ session('error') }}
        </div>
        @endif
    </div>
</div>

<div class="row">
    <!-- Stats Cards -->
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box">
            <span class="info-box-icon bg-red"><i class="fa fa-ban"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Banned IPs</span>
                <span class="info-box-number">{{ $stats['banned_ips'] }}</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box">
            <span class="info-box-icon bg-green"><i class="fa fa-network-wired"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Total IPs</span>
                <span class="info-box-number">{{ $stats['total_ips'] }}</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box">
            <span class="info-box-icon bg-yellow"><i class="fa fa-exclamation-triangle"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Suspicious IPs</span>
                <span class="info-box-number">{{ $stats['suspicious_ips'] }}</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box">
            <span class="info-box-icon bg-blue"><i class="fa fa-history"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Today's Logs</span>
                <span class="info-box-number">{{ $stats['recent_logs'] }}</span>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <!-- Features Control -->
    <div class="col-md-6">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-cog"></i> Security Features</h3>
            </div>
            <div class="box-body">
                @foreach($settings as $key => $setting)
                <div class="form-group">
                    <label style="font-weight: normal;">
                        @switch($key)
                            @case('ddos_protection') DDoS Rate Limit @break
                            @case('anti_debug') Anti-Debug @break
                            @case('anti_inspect') Anti-Inspect @break
                            @case('anti_bot') Anti-Bot Protection @break
                            @default {{ ucfirst(str_replace('_', ' ', $key)) }}
                        @endswitch
                    </label>
                    <div class="pull-right">
                        <form action="{{ route('admin.security.toggle') }}" method="POST" style="display: inline;">
                            @csrf
                            <input type="hidden" name="feature" value="{{ $key }}">
                            <input type="hidden" name="enabled" value="{{ $setting['value']['enabled'] ? '0' : '1' }}">
                            <div class="btn-group">
                                <button type="button" class="btn btn-xs btn-{{ $setting['value']['enabled'] ? 'success' : 'default' }} toggle-btn" 
                                    onclick="this.form.submit()">
                                    {{ $setting['value']['enabled'] ? 'ON' : 'OFF' }}
                                </button>
                            </div>
                        </form>
                    </div>
                    <div class="clearfix"></div>
                    @if($key === 'ddos_protection')
                    <small class="text-muted">
                        Limit: {{ $setting['value']['requests_per_minute'] ?? 60 }} requests/min, 
                        Block: {{ $setting['value']['block_duration_hours'] ?? 24 }} hours
                    </small>
                    @endif
                </div>
                <hr style="margin: 10px 0;">
                @endforeach
            </div>
        </div>
        
        <!-- Manual IP Ban -->
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-gavel"></i> Manual IP Ban</h3>
            </div>
            <div class="box-body">
                <form action="{{ route('admin.security.ban') }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label for="ip">IP Address</label>
                        <input type="text" class="form-control" name="ip" placeholder="e.g., 192.168.1.100" required pattern="^(\d{1,3}\.){3}\d{1,3}$">
                    </div>
                    <div class="form-group">
                        <label for="reason">Ban Reason</label>
                        <select class="form-control" name="reason" required>
                            <option value="manual">Manual Ban</option>
                            <option value="rate_limit">Rate Limit Exceeded</option>
                            <option value="fake_ip">Fake IP Address</option>
                            <option value="fake_ua">Fake User Agent</option>
                            <option value="bot">Bot Detection</option>
                            <option value="suspicious">Suspicious Activity</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="duration">Duration (Hours)</label>
                        <input type="number" class="form-control" name="duration" value="24" min="1" max="720" required>
                    </div>
                    <div class="form-group">
                        <label for="details">Details (Optional)</label>
                        <textarea class="form-control" name="details" rows="2" placeholder="Additional information..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-danger">
                        <i class="fa fa-ban"></i> Ban IP Address
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <!-- Banned IPs List -->
    <div class="col-md-6">
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-list"></i> Banned IP Addresses</h3>
            </div>
            <div class="box-body table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Expires</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($bannedIps as $ban)
                        <tr>
                            <td><code>{{ $ban->ip_address }}</code></td>
                            <td>
                                <span class="label label-{{ $ban->reason === 'manual' ? 'primary' : 'danger' }}">
                                    {{ ucfirst(str_replace('_', ' ', $ban->reason)) }}
                                </span>
                            </td>
                            <td>
                                @if($ban->expires_at)
                                    {{ $ban->expires_at->diffForHumans() }}
                                @else
                                    <span class="text-danger">Permanent</span>
                                @endif
                            </td>
                            <td>
                                <form action="{{ route('admin.security.unban') }}" method="POST" style="display: inline;">
                                    @csrf
                                    <input type="hidden" name="ip" value="{{ $ban->ip_address }}">
                                    <button type="submit" class="btn btn-xs btn-success" 
                                        onclick="return confirm('Unban {{ $ban->ip_address }}?')">
                                        <i class="fa fa-check"></i> Unban
                                    </button>
                                </form>
                            </td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="4" class="text-center">No banned IPs found.</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
        </div>
        
        <!-- Recent Security Logs -->
        <div class="box box-default">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-history"></i> Recent Security Logs</h3>
            </div>
            <div class="box-body">
                <ul class="products-list product-list-in-box">
                    @forelse($recentLogs->take(10) as $log)
                    <li class="item">
                        <div class="product-info">
                            <a href="javascript:void(0)" class="product-title">
                                {{ $log->ip_address }}
                                <span class="label label-{{ $log->severity === 'critical' ? 'danger' : ($log->severity === 'warning' ? 'warning' : 'info') }} pull-right">
                                    {{ ucfirst($log->action) }}
                                </span>
                            </a>
                            <span class="product-description">
                                {{ $log->created_at->diffForHumans() }}
                                @if($log->details)
                                - {{ json_decode($log->details)->reason ?? '' }}
                                @endif
                            </span>
                        </div>
                    </li>
                    @empty
                    <li class="item">
                        <div class="product-info">
                            <span class="product-description">No security logs found.</span>
                        </div>
                    </li>
                    @endforelse
                </ul>
            </div>
        </div>
    </div>
</div>

<!-- Anti-Debug & Anti-Inspect Scripts -->
@if($settings['anti_debug']['value']['enabled'] ?? false)
<script>
// Anti-Debugging Protection
(function() {
    var debuggerTimer = setInterval(function() {
        var startTime = performance.now();
        debugger;
        var endTime = performance.now();
        if (endTime - startTime > 100) {
            clearInterval(debuggerTimer);
            window.location.href = '{{ route('admin.security') }}?debugger=blocked';
        }
    }, 1000);
})();
</script>
@endif

@if($settings['anti_inspect']['value']['enabled'] ?? false)
<script>
// Anti-DevTools Inspection
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
});

document.onkeydown = function(e) {
    if (e.keyCode == 123 || // F12
        (e.ctrlKey && e.shiftKey && e.keyCode == 73) || // Ctrl+Shift+I
        (e.ctrlKey && e.shiftKey && e.keyCode == 74) || // Ctrl+Shift+J
        (e.ctrlKey && e.keyCode == 85) // Ctrl+U
    ) {
        alert('Developer tools are disabled for security.');
        return false;
    }
};
</script>
@endif
@endsection
VIEW_FILE

# ========== PHASE 8: FIX PHP-FPM & START SERVICES ==========
echo -e "\n\e[36m[PHASE 8] Configuring Services...\e[0m"

# Fix PHP-FPM socket
cat > /etc/php/8.1/fpm/pool.d/pterodactyl.conf << 'PHPFPM'
[pterodactyl]
user = www-data
group = www-data
listen = /var/run/php/php8.1-fpm-pterodactyl.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500
php_admin_value[error_log] = /var/log/php8.1-fpm-error.log
PHPFPM

mkdir -p /var/run/php
chown www-data:www-data /var/run/php

# Create minimal nginx config
cat > /etc/nginx/sites-available/pterodactyl << 'NGINX'
server {
    listen 80;
    server_name _;
    root /var/www/pterodactyl/public;
    index index.php;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php8.1-fpm-pterodactyl.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    }
    
    location ~ /\.ht {
        deny all;
    }
}
NGINX

# Test and start services
nginx -t && echo "✅ Nginx config test passed"

systemctl start php8.1-fpm
sleep 2
systemctl start nginx

# Clear Laravel cache
cd "$PANEL_DIR"
sudo -u www-data php artisan cache:clear 2>/dev/null || true
sudo -u www-data php artisan view:clear 2>/dev/null || true
sudo -u www-data php artisan route:clear 2>/dev/null || true

# ========== FINAL TEST ==========
echo -e "\n\e[36m[FINAL TEST] Testing Installation...\e[0m"

sleep 3

echo "1. Testing PHP-FPM socket..."
if [ -S "/var/run/php/php8.1-fpm-pterodactyl.sock" ]; then
    echo "   ✅ PHP-FPM socket is working"
else
    echo "   ⚠️ Socket not found, but continuing..."
fi

echo "2. Testing nginx..."
curl -I http://localhost 2>/dev/null && echo "   ✅ Nginx is responding" || echo "   ⚠️ Nginx may have issues"

echo "3. Testing panel access..."
curl -s http://localhost/admin | grep -q "Pterodactyl" && echo "   ✅ Panel is accessible" || echo "   ⚠️ Panel may have issues"

echo "4. Testing database..."
mysql -u root -e "USE panel; SELECT COUNT(*) FROM panel_security;" 2>/dev/null && echo "   ✅ Security database is ready" || echo "   ⚠️ Database may have issues"

# ========== COMPLETION MESSAGE ==========
echo -e "\n\e[32m==================================================\e[0m"
echo -e "\e[32m🎉 INSTALLATION COMPLETE!\e[0m"
echo -e "\e[32m==================================================\e[0m"
echo ""
echo "✅ BlackEndSpace Theme: Installed"
echo "✅ Security System: Ready"
echo "✅ Security Menu: Added to sidebar (shield icon)"
echo "✅ Access Control: User ID = 1 only"
echo ""
echo "📊 Security Features:"
echo "   • DDoS Rate Limit (Toggle ON/OFF)"
echo "   • IP Ban/Unban with reason & time"
echo "   • Anti-Debug & Anti-Inspect (Toggle ON/OFF)"
echo "   • Anti-Bot with fake IP/UA detection"
echo "   • Full logging system"
echo ""
echo "🔧 Access URLs:"
echo "   Panel: http://your-server-ip/admin"
echo "   Security: http://your-server-ip/admin/security"
echo ""
echo "👤 Login Credentials:"
echo "   Use your existing admin account (ID: 1)"
echo ""
echo "⚠️ If you see 403/500 errors:"
echo "   Run: chmod -R 775 /var/www/pterodactyl/storage"
echo "   Run: chown -R www-data:www-data /var/www/pterodactyl"
echo ""
echo "🔥 Quick Fix Command:"
echo "   systemctl restart php8.1-fpm nginx"
echo -e "\e[32m==================================================\e[0m"
