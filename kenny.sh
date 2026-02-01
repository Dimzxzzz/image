#!/bin/bash

echo "Selesaikan Instalasi Security System"
echo "======================================"

# 1. Buat tabel security_banned_ips secara manual
echo "1. Membuat tabel security_banned_ips..."
mysql -u root -p -e "
USE panel;
CREATE TABLE IF NOT EXISTS security_banned_ips (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason VARCHAR(255) NULL,
    banned_by BIGINT UNSIGNED NULL,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    metadata TEXT NULL,
    created_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip_active (ip_address, is_active),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SHOW TABLES LIKE 'security_banned_ips';
"

# 2. Tambahkan route ke SecurityController
echo "2. Memastikan routes security..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

# Cari baris terakhir sebelum penutup
if grep -q "Route::group(\['prefix' => 'settings'\]" "$ROUTES_FILE"; then
    echo "Routes sudah ada"
else
    # Tambahkan routes di bagian yang tepat
    sed -i "/Route::group(\['prefix' => 'settings'\], function () {/,/});/ {
        /});/i \
        // Security Routes\n        Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {\n            Route::get('/', 'SecurityController@index')->name('admin.security');\n            Route::get('/banned-ips', 'SecurityController@bannedIps')->name('admin.security.banned-ips');\n            Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban-ip');\n            Route::post('/unban-ip/{id}', 'SecurityController@unbanIp')->name('admin.security.unban-ip');\n            Route::get('/rate-limits', 'SecurityController@rateLimits')->name('admin.security.rate-limits');\n            Route::post('/toggle-rate-limit/{id}', 'SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');\n            Route::post('/update-rate-limit/{id}', 'SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');\n            Route::get('/stats', 'SecurityController@getStats')->name('admin.security.stats');\n        });
    }" "$ROUTES_FILE"
    echo "✅ Routes ditambahkan"
fi

# 3. Buat sidebar menu
echo "3. Membuat sidebar menu..."
SIDEBAR_FILE="/var/www/pterodactyl/resources/views/admin/partials/navigation.blade.php"

if [ -f "$SIDEBAR_FILE" ]; then
    # Cek apakah menu sudah ada
    if ! grep -q "Security Settings" "$SIDEBAR_FILE"; then
        # Backup dulu
        cp "$SIDEBAR_FILE" "${SIDEBAR_FILE}.backup"
        
        # Tambahkan setelah Settings
        sed -i '/<i class="fa fa-gears"><\/i> <span>Settings<\/span>/,/<\/a>/ {
            /<\/a>/a\
            @if(auth()->user()->id === 1)\
            <li class="{{ $active === '\''security'\'' ? '\''active'\'' : '\'''\'' }}">\
                <a href="{{ route('\''admin.security'\'') }}">\
                    <i class="fa fa-shield"></i> <span>Security Settings</span>\
                </a>\
            </li>\
            @endif
        }' "$SIDEBAR_FILE"
        echo "✅ Sidebar menu ditambahkan"
    else
        echo "⚠️  Menu sudah ada"
    fi
else
    echo "⚠️  File sidebar tidak ditemukan: $SIDEBAR_FILE"
fi

# 4. Perbaiki controller yang sudah ada
echo "4. Memperbaiki controller..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"

if [ -f "$CONTROLLER_FILE" ]; then
    # Backup controller
    cp "$CONTROLLER_FILE" "${CONTROLLER_FILE}.backup"
    
    # Buat controller baru yang lebih sederhana
    cat > "$CONTROLLER_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class SecurityController extends Controller
{
    public function index()
    {
        $bannedIPs = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();
        
        $rateLimits = [
            'api' => Cache::get('rate_limit:enabled:api', true),
            'login' => Cache::get('rate_limit:enabled:login', true),
            'files' => Cache::get('rate_limit:enabled:files', true),
        ];
        
        // Get suspicious IPs from logs
        $suspiciousIPs = [];
        $logFile = storage_path('logs/laravel.log');
        if (file_exists($logFile)) {
            $logs = shell_exec("grep -i 'failed\|attempt' $logFile | tail -20");
            if ($logs) {
                $lines = explode("\n", trim($logs));
                foreach ($lines as $line) {
                    if (preg_match('/(\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
                        $ip = $matches[1];
                        $suspiciousIPs[$ip] = isset($suspiciousIPs[$ip]) ? $suspiciousIPs[$ip] + 1 : 1;
                    }
                }
            }
        }
        
        return view('admin.security.index', [
            'bannedIPs' => $bannedIPs,
            'rateLimits' => $rateLimits,
            'suspiciousIPs' => $suspiciousIPs,
            'totalBanned' => DB::table('security_banned_ips')->where('is_active', true)->count(),
        ]);
    }
    
    public function bannedIps(Request $request)
    {
        $search = $request->get('search');
        $query = DB::table('security_banned_ips');
        
        if ($search) {
            $query->where('ip_address', 'like', "%{$search}%")
                  ->orWhere('reason', 'like', "%{$search}%");
        }
        
        $ips = $query->orderBy('created_at', 'desc')->paginate(20);
            
        return view('admin.security.banned-ips', [
            'ips' => $ips,
            'search' => $search
        ]);
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|in:1hour,1day,1week,1month,permanent'
        ]);
        
        $expiresAt = null;
        switch ($request->duration) {
            case '1hour':
                $expiresAt = now()->addHour();
                break;
            case '1day':
                $expiresAt = now()->addDay();
                break;
            case '1week':
                $expiresAt = now()->addWeek();
                break;
            case '1month':
                $expiresAt = now()->addMonth();
                break;
        }
        
        DB::table('security_banned_ips')->updateOrInsert(
            ['ip_address' => $request->ip_address],
            [
                'reason' => $request->reason,
                'banned_by' => $request->user()->id,
                'expires_at' => $expiresAt,
                'is_active' => true,
                'updated_at' => now()
            ]
        );
        
        return redirect()->back()->with('success', "IP {$request->ip_address} has been banned.");
    }
    
    public function unbanIp($id)
    {
        DB::table('security_banned_ips')
            ->where('id', $id)
            ->update(['is_active' => false]);
            
        return redirect()->back()->with('success', 'IP has been unbanned.');
    }
    
    public function rateLimits()
    {
        $limits = [
            [
                'id' => 'api',
                'name' => 'API Rate Limit',
                'description' => 'Limit requests to API endpoints',
                'enabled' => Cache::get('rate_limit:enabled:api', true),
                'config' => Cache::get('rate_limit:config:api', ['max' => 60, 'window' => 60])
            ],
            [
                'id' => 'login',
                'name' => 'Login Rate Limit',
                'description' => 'Limit login attempts',
                'enabled' => Cache::get('rate_limit:enabled:login', true),
                'config' => Cache::get('rate_limit:config:login', ['max' => 5, 'window' => 300])
            ],
            [
                'id' => 'files',
                'name' => 'File Operations',
                'description' => 'Limit file operations',
                'enabled' => Cache::get('rate_limit:enabled:files', true),
                'config' => Cache::get('rate_limit:config:files', ['max' => 30, 'window' => 60])
            ]
        ];
        
        return view('admin.security.rate-limits', compact('limits'));
    }
    
    public function toggleRateLimit(Request $request, $id)
    {
        $current = Cache::get("rate_limit:enabled:$id", true);
        Cache::put("rate_limit:enabled:$id", !$current);
        
        return response()->json([
            'success' => true,
            'enabled' => !$current
        ]);
    }
    
    public function updateRateLimit(Request $request, $id)
    {
        $request->validate([
            'max_requests' => 'required|integer|min:1|max:1000',
            'time_window' => 'required|integer|min:1|max:86400'
        ]);
        
        Cache::put("rate_limit:config:$id", [
            'max' => $request->max_requests,
            'window' => $request->time_window
        ]);
        
        return redirect()->back()->with('success', 'Rate limit updated.');
    }
    
    public function getStats()
    {
        $stats = [
            'banned_ips' => DB::table('security_banned_ips')->where('is_active', true)->count(),
            'total_bans' => DB::table('security_banned_ips')->count(),
            'rate_limits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ]
        ];
        
        return response()->json($stats);
    }
}
EOF
    echo "✅ Controller diperbarui"
fi

# 5. Buat views sederhana
echo "5. Membuat views..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view
cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Security
@endsection

@section('content-header')
    <h1>Security<small>Security management</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.settings') }}">Settings</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-4">
        <div class="info-box bg-red">
            <span class="info-box-icon"><i class="fa fa-ban"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Banned IPs</span>
                <span class="info-box-number">{{ $totalBanned }}</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="info-box bg-yellow">
            <span class="info-box-icon"><i class="fa fa-exclamation-triangle"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Suspicious IPs</span>
                <span class="info-box-number">{{ count($suspiciousIPs) }}</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="info-box bg-green">
            <span class="info-box-icon"><i class="fa fa-shield"></i></span>
            <div class="info-box-content">
                @php $active = 0; @endphp
                @foreach($rateLimits as $limit)
                    @if($limit) @php $active++; @endphp @endif
                @endforeach
                <span class="info-box-text">Active Protections</span>
                <span class="info-box-number">{{ $active }}/3</span>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="box">
            <div class="box-header">
                <h3 class="box-title">Banned IPs</h3>
            </div>
            <div class="box-body">
                <table class="table">
                    <thead>
                        <tr>
                            <th>IP</th>
                            <th>Reason</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($bannedIPs as $ip)
                        <tr>
                            <td><code>{{ $ip->ip_address }}</code></td>
                            <td>{{ $ip->reason ?: 'No reason' }}</td>
                            <td>{{ \Carbon\Carbon::parse($ip->created_at)->format('Y-m-d H:i') }}</td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
                <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-primary btn-block">Manage Banned IPs</a>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="box">
            <div class="box-header">
                <h3 class="box-title">Rate Limits</h3>
            </div>
            <div class="box-body">
                <table class="table">
                    @foreach($rateLimits as $key => $enabled)
                    <tr>
                        <td>{{ ucfirst($key) }}</td>
                        <td>
                            <span class="label label-{{ $enabled ? 'success' : 'danger' }}">
                                {{ $enabled ? 'ENABLED' : 'DISABLED' }}
                            </span>
                        </td>
                        <td>
                            <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-xs btn-default">Configure</a>
                        </td>
                    </tr>
                    @endforeach
                </table>
                <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">Rate Limit Settings</a>
            </div>
        </div>
        
        <div class="box">
            <div class="box-header">
                <h3 class="box-title">Quick Actions</h3>
            </div>
            <div class="box-body">
                <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-danger btn-block">Manage IP Bans</a>
                <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">Configure Rate Limits</a>
                <button onclick="window.location.reload()" class="btn btn-info btn-block">Refresh</button>
            </div>
        </div>
    </div>
</div>
@endsection
EOF

# Banned IPs view
cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Banned IPs
@endsection

@section('content-header')
    <h1>Banned IPs<small>Manage banned IPs</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Banned IPs</li>
    </ol>
@endsection

@section('content')
<div class="box">
    <div class="box-header">
        <h3 class="box-title">Banned IP Addresses</h3>
        <div class="box-tools">
            <form method="GET" class="form-inline">
                <input type="text" name="search" class="form-control" placeholder="Search..." value="{{ $search }}">
                <button class="btn btn-default">Search</button>
            </form>
        </div>
    </div>
    <div class="box-body">
        @if(session('success'))
        <div class="alert alert-success">{{ session('success') }}</div>
        @endif
        
        <table class="table table-hover">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Reason</th>
                    <th>Banned At</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                @foreach($ips as $ip)
                <tr>
                    <td><code>{{ $ip->ip_address }}</code></td>
                    <td>{{ $ip->reason ?: '-' }}</td>
                    <td>{{ \Carbon\Carbon::parse($ip->banned_at)->format('Y-m-d H:i') }}</td>
                    <td>
                        @if($ip->expires_at)
                            {{ \Carbon\Carbon::parse($ip->expires_at)->diffForHumans() }}
                        @else
                            Permanent
                        @endif
                    </td>
                    <td>
                        @if($ip->is_active)
                        <span class="label label-danger">Active</span>
                        @else
                        <span class="label label-success">Inactive</span>
                        @endif
                    </td>
                    <td>
                        @if($ip->is_active)
                        <form action="{{ route('admin.security.unban-ip', $ip->id) }}" method="POST" style="display:inline">
                            @csrf
                            <button type="submit" class="btn btn-xs btn-success" onclick="return confirm('Unban this IP?')">Unban</button>
                        </form>
                        @endif
                    </td>
                </tr>
                @endforeach
            </tbody>
        </table>
        
        <div class="text-center">
            {{ $ips->links() }}
        </div>
        
        <div class="text-right">
            <button class="btn btn-danger" data-toggle="modal" data-target="#banModal">Ban New IP</button>
        </div>
    </div>
</div>

<div class="modal fade" id="banModal">
    <div class="modal-dialog">
        <div class="modal-content">
            <form action="{{ route('admin.security.ban-ip') }}" method="POST">
                @csrf
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Ban IP Address</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="ip_address" class="form-control" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>Reason (Optional)</label>
                        <input type="text" name="reason" class="form-control" placeholder="DDoS attempt">
                    </div>
                    <div class="form-group">
                        <label>Duration</label>
                        <select name="duration" class="form-control">
                            <option value="1hour">1 Hour</option>
                            <option value="1day">1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="permanent">Permanent</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Ban IP</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection
EOF

# Rate Limits view
cat > "${VIEWS_DIR}/rate-limits.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Rate Limits
@endsection

@section('content-header')
    <h1>Rate Limits<small>Configure rate limits</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Rate Limits</li>
    </ol>
@endsection

@section('content')
<div class="row">
    @foreach($limits as $limit)
    <div class="col-md-6">
        <div class="box box-{{ $limit['enabled'] ? 'success' : 'default' }}">
            <div class="box-header">
                <h3 class="box-title">{{ $limit['name'] }}</h3>
                <div class="box-tools">
                    <button class="btn btn-xs btn-{{ $limit['enabled'] ? 'success' : 'default' }} toggle-limit" data-id="{{ $limit['id'] }}">
                        {{ $limit['enabled'] ? 'ENABLED' : 'DISABLED' }}
                    </button>
                </div>
            </div>
            <div class="box-body">
                <p>{{ $limit['description'] }}</p>
                <form action="{{ route('admin.security.update-rate-limit', $limit['id']) }}" method="POST">
                    @csrf
                    <div class="row">
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Max Requests</label>
                                <input type="number" name="max_requests" class="form-control" value="{{ $limit['config']['max'] }}" min="1" max="1000">
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="form-group">
                                <label>Time Window (seconds)</label>
                                <input type="number" name="time_window" class="form-control" value="{{ $limit['config']['window'] }}" min="1" max="86400">
                            </div>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-primary">Save</button>
                </form>
            </div>
        </div>
    </div>
    @endforeach
</div>

<div class="box">
    <div class="box-header">
        <h3 class="box-title">Quick Actions</h3>
    </div>
    <div class="box-body">
        <button class="btn btn-success" onclick="enableAll()">Enable All</button>
        <button class="btn btn-default" onclick="disableAll()">Disable All</button>
        <a href="{{ route('admin.security') }}" class="btn btn-info">Back to Security</a>
    </div>
</div>
@endsection

@section('footer-scripts')
<script>
function enableAll() {
    if (confirm('Enable all rate limits?')) {
        @foreach($limits as $limit)
        $.post('{{ route('admin.security.toggle-rate-limit', $limit['id']) }}', {_token: '{{ csrf_token() }}'});
        @endforeach
        setTimeout(() => location.reload(), 500);
    }
}

function disableAll() {
    if (confirm('Disable all rate limits?')) {
        @foreach($limits as $limit)
        $.post('{{ route('admin.security.toggle-rate-limit', $limit['id']) }}', {_token: '{{ csrf_token() }}'});
        @endforeach
        setTimeout(() => location.reload(), 500);
    }
}

$('.toggle-limit').click(function() {
    const id = $(this).data('id');
    $.post('{{ url('admin/security/toggle-rate-limit') }}/' + id, {_token: '{{ csrf_token() }}'}, function() {
        location.reload();
    });
});
</script>
@endsection
EOF

echo "✅ Views dibuat"

# 6. Clear cache
echo "6. Membersihkan cache..."
cd /var/www/pterodactyl
sudo -u www-data php artisan view:clear
sudo -u www-data php artisan config:clear
sudo -u www-data php artisan route:clear

# 7. Fix permission
echo "7. Memperbaiki permission..."
chown -R www-data:www-data /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

echo "======================================"
echo "INSTALASI SELESAI!"
echo "======================================"
echo ""
echo "Fitur Security telah diinstal:"
echo "1. Banned IP Management"
echo "2. Rate Limit Control"
echo "3. Security Dashboard"
echo ""
echo "Akses: /admin/security"
echo "Hanya user dengan ID 1 yang bisa akses"
echo ""
echo "Untuk test:"
echo "1. Login sebagai owner (ID 1)"
echo "2. Buka Settings → Security Settings"
echo "3. Coba ban IP: 127.0.0.1 (test)"
echo ""
echo "Jika tidak muncul:"
echo "- php artisan route:list | grep security"
echo "- Cek file controller di app/Http/Controllers/Admin/SecurityController.php"
echo "- Clear cache: php artisan cache:clear"
echo "======================================"
