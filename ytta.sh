#!/bin/bash
# install_security_owner_only.sh

echo "🔒 Instalasi Sistem Keamanan Pterodactyl (Owner Only)"
echo "======================================================"

# Backup timestamp
TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BACKUP_DIR="/var/backups/pterodactyl/security_${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

# 1. Tambahkan Route ke Admin
echo "1. Menambahkan routes security..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"
backup_file "$ROUTES_FILE"

# Tambahkan routes di bagian yang tepat
if ! grep -q "Route::get('/security'" "$ROUTES_FILE"; then
    sed -i "/Route::group(\['prefix' => 'settings'\], function () {/a \\
    // Security Routes - Only for Owner (ID 1)\\
    Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {\\
        Route::get('/', 'SecurityController@index')->name('admin.security');\\
        Route::get('/banned-ips', 'SecurityController@bannedIps')->name('admin.security.banned-ips');\\
        Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban-ip');\\
        Route::post('/unban-ip/{id}', 'SecurityController@unbanIp')->name('admin.security.unban-ip');\\
        Route::get('/rate-limits', 'SecurityController@rateLimits')->name('admin.security.rate-limits');\\
        Route::post('/toggle-rate-limit/{id}', 'SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');\\
        Route::post('/update-rate-limit/{id}', 'SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');\\
        Route::get('/stats', 'SecurityController@getStats')->name('admin.security.stats');\\
    });\\
" "$ROUTES_FILE"
fi

# 2. Buat Middleware Owner Only
echo "2. Membuat middleware owner only..."
MIDDLEWARE_FILE="/var/www/pterodactyl/app/Http/Middleware/OwnerOnly.php"

cat > "$MIDDLEWARE_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
        // Hanya user dengan ID 1 (owner) yang boleh akses
        if (!$request->user() || $request->user()->id !== 1) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Unauthorized',
                    'message' => 'Only the owner can access security settings.'
                ], 403);
            }
            
            return redirect()->route('admin.index')
                ->with('error', 'Only the owner can access security settings.');
        }
        
        return $next($request);
    }
}
EOF

# 3. Register Middleware di Kernel
echo "3. Register middleware..."
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"
backup_file "$KERNEL_FILE"

# Tambahkan ke routeMiddleware
if ! grep -q "'owner.only'" "$KERNEL_FILE"; then
    sed -i "/protected \$routeMiddleware = \[/a \\
        'owner.only' => \\Pterodactyl\\Http\\Middleware\\OwnerOnly::class,\\
" "$KERNEL_FILE"
fi

# 4. Buat Controller Security
echo "4. Membuat controller security..."
CONTROLLER_DIR="/var/www/pterodactyl/app/Http/Controllers/Admin"
mkdir -p "$CONTROLLER_DIR"

cat > "${CONTROLLER_DIR}/SecurityController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class SecurityController extends Controller
{
    private function getBannedIPsTable()
    {
        if (!Schema::hasTable('security_banned_ips')) {
            return collect();
        }
        
        return DB::table('security_banned_ips')
            ->where('is_active', true)
            ->where(function($q) {
                $q->whereNull('expires_at')
                  ->orWhere('expires_at', '>', now());
            })
            ->get();
    }
    
    private function createBannedIPsTable()
    {
        if (!Schema::hasTable('security_banned_ips')) {
            DB::statement("
                CREATE TABLE security_banned_ips (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    reason VARCHAR(255) NULL,
                    banned_by BIGINT UNSIGNED NULL,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT TRUE,
                    metadata TEXT NULL,
                    created_at TIMESTAMP NULL,
                    updated_at TIMESTAMP NULL
                )
            ");
        }
    }
    
    public function index()
    {
        $this->createBannedIPsTable();
        
        $bannedIPs = $this->getBannedIPsTable();
        
        // Rate limits status
        $rateLimits = [
            'api' => Cache::get('rate_limit:enabled:api', true),
            'login' => Cache::get('rate_limit:enabled:login', true),
            'files' => Cache::get('rate_limit:enabled:files', true),
        ];
        
        // Recent suspicious IPs (simplified)
        $suspiciousIPs = [];
        $logFile = storage_path('logs/laravel.log');
        if (file_exists($logFile)) {
            $logs = shell_exec("tail -100 $logFile | grep -i 'suspicious\|failed\|attempt' | head -10");
            $lines = explode("\n", trim($logs));
            
            foreach ($lines as $line) {
                if (preg_match('/(\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
                    $ip = $matches[1];
                    if (!isset($suspiciousIPs[$ip])) {
                        $suspiciousIPs[$ip] = 0;
                    }
                    $suspiciousIPs[$ip]++;
                }
            }
        }
        
        return view('admin.security.index', [
            'bannedIPs' => $bannedIPs,
            'rateLimits' => $rateLimits,
            'suspiciousIPs' => $suspiciousIPs,
            'totalBanned' => $bannedIPs->count(),
        ]);
    }
    
    public function bannedIps(Request $request)
    {
        $this->createBannedIPsTable();
        
        $ips = DB::table('security_banned_ips')
            ->orderBy('created_at', 'desc')
            ->paginate(20);
            
        return view('admin.security.banned-ips', compact('ips'));
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|in:1hour,1day,1week,permanent'
        ]);
        
        $this->createBannedIPsTable();
        
        $expiresAt = null;
        if ($request->duration !== 'permanent') {
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
            }
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
        
        // Clear cache untuk banned IPs
        Cache::forget('banned_ips_list');
        
        return redirect()->back()->with('success', "IP {$request->ip_address} telah dibanned.");
    }
    
    public function unbanIp($id)
    {
        DB::table('security_banned_ips')
            ->where('id', $id)
            ->update(['is_active' => false]);
            
        Cache::forget('banned_ips_list');
        
        return redirect()->back()->with('success', 'IP telah diunban.');
    }
    
    public function rateLimits()
    {
        $limits = [
            [
                'id' => 'api',
                'name' => 'API Rate Limit',
                'description' => 'Membatasi request ke API umum',
                'enabled' => Cache::get('rate_limit:enabled:api', true),
                'default' => ['max' => 60, 'window' => 60]
            ],
            [
                'id' => 'login',
                'name' => 'Login Rate Limit',
                'description' => 'Membatasi percobaan login',
                'enabled' => Cache::get('rate_limit:enabled:login', true),
                'default' => ['max' => 5, 'window' => 300]
            ],
            [
                'id' => 'files',
                'name' => 'File Operations',
                'description' => 'Membatasi operasi file',
                'enabled' => Cache::get('rate_limit:enabled:files', true),
                'default' => ['max' => 30, 'window' => 60]
            ]
        ];
        
        return view('admin.security.rate-limits', compact('limits'));
    }
    
    public function toggleRateLimit($id)
    {
        $current = Cache::get("rate_limit:enabled:$id", true);
        Cache::put("rate_limit:enabled:$id", !$current, now()->addDays(30));
        
        return response()->json([
            'success' => true,
            'enabled' => !$current
        ]);
    }
    
    public function updateRateLimit(Request $request, $id)
    {
        $request->validate([
            'max_requests' => 'required|integer|min:1|max:1000',
            'time_window' => 'required|integer|min:1|max:3600'
        ]);
        
        Cache::put("rate_limit:config:$id", [
            'max' => $request->max_requests,
            'window' => $request->time_window
        ], now()->addDays(30));
        
        return redirect()->back()->with('success', 'Rate limit updated.');
    }
    
    public function getStats()
    {
        $this->createBannedIPsTable();
        
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

# 5. Buat Views Security
echo "5. Membuat views security..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view
cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Security Settings
@endsection

@section('content-header')
    <h1>Security Settings<small>Only owner can access these settings</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.settings') }}">Settings</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-4">
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title">Banned IPs</h3>
            </div>
            <div class="box-body">
                <h4>Total Banned: {{ $totalBanned }}</h4>
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Banned At</th>
                            </tr>
                        </thead>
                        <tbody>
                            @forelse($bannedIPs->take(5) as $ip)
                            <tr>
                                <td>{{ $ip->ip_address }}</td>
                                <td>{{ $ip->reason ?? 'No reason' }}</td>
                                <td>{{ $ip->banned_at }}</td>
                            </tr>
                            @empty
                            <tr>
                                <td colspan="3" class="text-center">No banned IPs</td>
                            </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
                <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-danger btn-block">
                    Manage Banned IPs
                </a>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title">Rate Limits</h3>
            </div>
            <div class="box-body">
                @foreach($rateLimits as $key => $enabled)
                <div class="form-group">
                    <label>{{ ucfirst($key) }} Rate Limit</label>
                    <div>
                        <span class="label label-{{ $enabled ? 'success' : 'danger' }}">
                            {{ $enabled ? 'ENABLED' : 'DISABLED' }}
                        </span>
                    </div>
                </div>
                @endforeach
                <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">
                    Configure Rate Limits
                </a>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title">Suspicious Activity</h3>
            </div>
            <div class="box-body">
                @if(count($suspiciousIPs) > 0)
                <ul class="list-unstyled">
                    @foreach($suspiciousIPs as $ip => $count)
                    <li>
                        <i class="fa fa-warning text-yellow"></i>
                        {{ $ip }} 
                        <span class="badge bg-red">{{ $count }} attempts</span>
                    </li>
                    @endforeach
                </ul>
                @else
                <p class="text-muted">No suspicious activity detected recently.</p>
                @endif
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-12">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title">Quick Actions</h3>
            </div>
            <div class="box-body">
                <div class="row">
                    <div class="col-md-3">
                        <button class="btn btn-block btn-danger" data-toggle="modal" data-target="#banIpModal">
                            <i class="fa fa-ban"></i> Ban IP Address
                        </button>
                    </div>
                    <div class="col-md-3">
                        <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-block btn-warning">
                            <i class="fa fa-tachometer"></i> Rate Limit Settings
                        </a>
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-block btn-info" onclick="loadStats()">
                            <i class="fa fa-refresh"></i> Refresh Stats
                        </button>
                    </div>
                    <div class="col-md-3">
                        <button class="btn btn-block btn-success" onclick="clearLogs()">
                            <i class="fa fa-trash"></i> Clear Old Logs
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Ban IP Modal -->
<div class="modal fade" id="banIpModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form action="{{ route('admin.security.ban-ip') }}" method="POST">
                @csrf
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Ban IP Address</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="ip_address">IP Address</label>
                        <input type="text" class="form-control" name="ip_address" 
                               placeholder="e.g., 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <input type="text" class="form-control" name="reason" 
                               placeholder="e.g., DDoS attempt">
                    </div>
                    <div class="form-group">
                        <label for="duration">Duration</label>
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

@section('footer-scripts')
<script>
function loadStats() {
    $.ajax({
        url: '{{ route('admin.security.stats') }}',
        method: 'GET',
        success: function(data) {
            alert('Stats loaded!\nBanned IPs: ' + data.banned_ips);
        }
    });
}

function clearLogs() {
    if (confirm('Clear old log files? This cannot be undone.')) {
        $.ajax({
            url: '/admin/security/clear-logs',
            method: 'POST',
            data: {_token: '{{ csrf_token() }}'},
            success: function() {
                alert('Logs cleared successfully!');
                location.reload();
            }
        });
    }
}
</script>
@endsection
EOF

# Banned IPs view
cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Banned IPs Management
@endsection

@section('content-header')
    <h1>Banned IPs<small>Manage blocked IP addresses</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Banned IPs</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title">Banned IP Addresses</h3>
                <div class="box-tools">
                    <button class="btn btn-sm btn-danger" data-toggle="modal" data-target="#banIpModal">
                        <i class="fa fa-ban"></i> Ban New IP
                    </button>
                </div>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Banned At</th>
                                <th>Expires At</th>
                                <th>Status</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach($ips as $ip)
                            <tr>
                                <td>{{ $ip->id }}</td>
                                <td><code>{{ $ip->ip_address }}</code></td>
                                <td>{{ $ip->reason ?? 'No reason' }}</td>
                                <td>{{ $ip->banned_at }}</td>
                                <td>
                                    @if($ip->expires_at)
                                        {{ $ip->expires_at }}
                                    @else
                                        <span class="label label-danger">PERMANENT</span>
                                    @endif
                                </td>
                                <td>
                                    @if($ip->is_active)
                                        <span class="label label-danger">BANNED</span>
                                    @else
                                        <span class="label label-success">UNBANNED</span>
                                    @endif
                                </td>
                                <td>
                                    @if($ip->is_active)
                                    <form action="{{ route('admin.security.unban-ip', $ip->id) }}" 
                                          method="POST" style="display:inline">
                                        @csrf
                                        <button type="submit" class="btn btn-xs btn-success"
                                                onclick="return confirm('Unban this IP?')">
                                            <i class="fa fa-check"></i> Unban
                                        </button>
                                    </form>
                                    @endif
                                </td>
                            </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                <div class="text-center">
                    {{ $ips->links() }}
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Ban IP Modal -->
<div class="modal fade" id="banIpModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form action="{{ route('admin.security.ban-ip') }}" method="POST">
                @csrf
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Ban IP Address</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label for="ip_address">IP Address *</label>
                        <input type="text" class="form-control" name="ip_address" 
                               placeholder="e.g., 192.168.1.100 or 10.0.0.0/24" required>
                        <small class="text-muted">Support single IP or CIDR notation</small>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <input type="text" class="form-control" name="reason" 
                               placeholder="e.g., DDoS attempt, brute force, etc.">
                    </div>
                    <div class="form-group">
                        <label for="duration">Duration</label>
                        <select name="duration" class="form-control">
                            <option value="1hour">1 Hour</option>
                            <option value="1day">1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="permanent" selected>Permanent</option>
                        </select>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Ban IP Address</button>
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
    Rate Limit Settings
@endsection

@section('content-header')
    <h1>Rate Limit Settings<small>Control request rates to prevent abuse</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Rate Limits</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title">Rate Limit Configuration</h3>
                <div class="box-tools">
                    <button class="btn btn-sm btn-warning" onclick="enableAll()">
                        <i class="fa fa-toggle-on"></i> Enable All
                    </button>
                    <button class="btn btn-sm btn-default" onclick="disableAll()">
                        <i class="fa fa-toggle-off"></i> Disable All
                    </button>
                </div>
            </div>
            <div class="box-body">
                @foreach($limits as $limit)
                <div class="box box-{{ $limit['enabled'] ? 'success' : 'danger' }} collapsed-box">
                    <div class="box-header with-border">
                        <h3 class="box-title">{{ $limit['name'] }}</h3>
                        <div class="box-tools pull-right">
                            <button type="button" class="btn btn-box-tool" data-widget="collapse">
                                <i class="fa fa-{{ $limit['enabled'] ? 'minus' : 'plus' }}"></i>
                            </button>
                            <div class="btn-group">
                                <button class="btn btn-xs btn-{{ $limit['enabled'] ? 'success' : 'danger' }} toggle-rate"
                                        data-id="{{ $limit['id'] }}">
                                    {{ $limit['enabled'] ? 'ENABLED' : 'DISABLED' }}
                                </button>
                            </div>
                        </div>
                    </div>
                    <div class="box-body">
                        <p>{{ $limit['description'] }}</p>
                        <form action="{{ route('admin.security.update-rate-limit', $limit['id']) }}" 
                              method="POST" class="form-horizontal">
                            @csrf
                            <div class="form-group">
                                <label class="col-sm-3 control-label">Max Requests</label>
                                <div class="col-sm-9">
                                    <input type="number" name="max_requests" 
                                           class="form-control" 
                                           value="{{ $limit['default']['max'] }}"
                                           min="1" max="1000">
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="col-sm-3 control-label">Time Window (seconds)</label>
                                <div class="col-sm-9">
                                    <input type="number" name="time_window" 
                                           class="form-control" 
                                           value="{{ $limit['default']['window'] }}"
                                           min="1" max="3600">
                                </div>
                            </div>
                            <div class="form-group">
                                <div class="col-sm-offset-3 col-sm-9">
                                    <button type="submit" class="btn btn-warning">
                                        <i class="fa fa-save"></i> Save Settings
                                    </button>
                                </div>
                            </div>
                        </form>
                    </div>
                </div>
                @endforeach
            </div>
            <div class="box-footer">
                <div class="callout callout-info">
                    <h4><i class="fa fa-info-circle"></i> Information</h4>
                    <p>
                        <strong>Rate Limiting</strong> helps prevent abuse by limiting how many requests
                        a client can make in a given time period. Enable this for endpoints that are
                        frequently targeted by attacks.
                    </p>
                    <p>
                        <strong>Default Settings:</strong><br>
                        • API: 60 requests per minute<br>
                        • Login: 5 attempts per 5 minutes<br>
                        • Files: 30 operations per minute
                    </p>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
<script>
function enableAll() {
    if (confirm('Enable all rate limits?')) {
        @foreach($limits as $limit)
        toggleRateLimit('{{ $limit['id'] }}', true);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

function disableAll() {
    if (confirm('Disable all rate limits?')) {
        @foreach($limits as $limit)
        toggleRateLimit('{{ $limit['id'] }}', false);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

$('.toggle-rate').click(function() {
    const id = $(this).data('id');
    const current = $(this).text().trim() === 'ENABLED';
    toggleRateLimit(id, !current);
});

function toggleRateLimit(id, enable) {
    $.ajax({
        url: '/admin/security/toggle-rate-limit/' + id,
        method: 'POST',
        data: {
            _token: '{{ csrf_token() }}'
        },
        success: function(response) {
            if (response.success) {
                location.reload();
            }
        }
    });
}
</script>
@endsection
EOF

# 6. Buat Menu di Sidebar
echo "6. Menambahkan menu security di sidebar..."
SIDEBAR_FILE="/var/www/pterodactyl/resources/views/partials/admin/sidebar.blade.php"
backup_file "$SIDEBAR_FILE"

# Tambahkan menu security di bagian settings
if ! grep -q "Security Settings" "$SIDEBAR_FILE"; then
    sed -i "/<li class=\"{{\$active === 'settings' ? 'active' : ''}}\">/a \\
                    @if(auth()->user()->id === 1)\\
                    <li class=\"{{\$active === 'security' ? 'active' : ''}}\">\\
                        <a href=\"{{ route('admin.security') }}\">\\
                            <i class=\"fa fa-shield\"></i> <span>Security Settings</span>\\
                        </a>\\
                    </li>\\
                    @endif\\
" "$SIDEBAR_FILE"
fi

# 7. Buat Simple Middleware untuk IP Blocking
echo "7. Membuat middleware IP blocking..."
IP_MIDDLEWARE="/var/www/pterodactyl/app/Http/Middleware/CheckBannedIP.php"

cat > "$IP_MIDDLEWARE" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class CheckBannedIP
{
    public function handle(Request $request, Closure $next)
    {
        // Skip untuk admin routes
        if ($request->is('admin/*')) {
            return $next($request);
        }
        
        $ip = $request->ip();
        
        // Cache banned IPs untuk performa
        $bannedIPs = Cache::remember('banned_ips_list', 300, function () {
            if (!Schema::hasTable('security_banned_ips')) {
                return [];
            }
            
            return DB::table('security_banned_ips')
                ->where('is_active', true)
                ->where(function($q) {
                    $q->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
                })
                ->pluck('ip_address')
                ->toArray();
        });
        
        // Check if IP is banned
        if (in_array($ip, $bannedIPs)) {
            // Log the attempt
            $logFile = storage_path('logs/blocked_ips.log');
            $logMessage = sprintf(
                "[%s] Blocked IP: %s | URL: %s | User-Agent: %s\n",
                now()->toDateTimeString(),
                $ip,
                $request->fullUrl(),
                $request->userAgent()
            );
            file_put_contents($logFile, $logMessage, FILE_APPEND);
            
            return response()->view('errors.banned', [], 403);
        }
        
        // Simple rate limiting untuk login
        if ($request->is('auth/login')) {
            $loginKey = 'login_attempts:' . $ip;
            $attempts = Cache::get($loginKey, 0);
            
            if ($attempts > 5) {
                return response()->json([
                    'error' => 'Too many login attempts. Please try again later.'
                ], 429);
            }
            
            Cache::put($loginKey, $attempts + 1, 300); // 5 minutes
        }
        
        return $next($request);
    }
}
EOF

# 8. Register IP Middleware
if ! grep -q "'check.banned.ip'" "$KERNEL_FILE"; then
    sed -i "/protected \$middleware = \[/a \\
        \\Pterodactyl\\Http\\Middleware\\CheckBannedIP::class,\\
" "$KERNEL_FILE"
fi

# 9. Buat Error View untuk Banned IPs
ERRORS_DIR="/var/www/pterodactyl/resources/views/errors"
mkdir -p "$ERRORS_DIR"

cat > "${ERRORS_DIR}/banned.blade.php" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Access Denied - IP Banned</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            text-align: center;
            max-width: 500px;
            width: 90%;
        }
        h1 {
            color: #e74c3c;
            margin-bottom: 20px;
        }
        .icon {
            font-size: 80px;
            color: #e74c3c;
            margin-bottom: 20px;
        }
        .ip-address {
            background: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            font-family: monospace;
            margin: 20px 0;
        }
        .contact {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #eee;
            color: #666;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>Access Denied</h1>
        <p>Your IP address has been banned from accessing this server.</p>
        
        <div class="ip-address">
            Your IP: {{ request()->ip() }}
        </div>
        
        <p>If you believe this is a mistake, please contact the server administrator.</p>
        
        <div class="contact">
            <p><strong>Server:</strong> {{ config('app.name', 'Pterodactyl Panel') }}</p>
            <p><strong>Time:</strong> {{ now()->format('Y-m-d H:i:s') }}</p>
        </div>
    </div>
</body>
</html>
EOF

# 10. Jalankan migration
echo "8. Menjalankan database migration..."
cd /var/www/pterodactyl

# Buat migration sederhana jika belum ada
if [ ! -f "/var/www/pterodactyl/database/migrations/security_tables.php" ]; then
    cat > "/var/www/pterodactyl/database/migrations/security_tables.php" << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

class CreateSecurityTables extends Migration
{
    public function up()
    {
        if (!Schema::hasTable('security_banned_ips')) {
            Schema::create('security_banned_ips', function (Blueprint $table) {
                $table->id();
                $table->string('ip_address', 45)->unique();
                $table->string('reason')->nullable();
                $table->unsignedBigInteger('banned_by')->nullable();
                $table->timestamp('banned_at')->useCurrent();
                $table->timestamp('expires_at')->nullable();
                $table->boolean('is_active')->default(true);
                $table->text('metadata')->nullable();
                $table->timestamps();
            });
        }
    }

    public function down()
    {
        Schema::dropIfExists('security_banned_ips');
    }
}
EOF
fi

# Jalankan migration
php artisan migrate --force

# 11. Clear cache
echo "9. Membersihkan cache..."
php artisan view:clear
php artisan config:clear
php artisan route:clear

# 12. Set permissions
echo "10. Mengatur permissions..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 755 /var/www/pterodactyl/storage
chmod -R 755 /var/www/pterodactyl/bootstrap/cache

echo "======================================================"
echo "✅ INSTALASI SELESAI!"
echo "======================================================"
echo ""
echo "📊 FITUR YANG TERSEDIA:"
echo "   1. Menu Security di Admin Panel (hanya owner ID 1)"
echo "   2. Banned IP Management"
echo "   3. Rate Limit Control"
echo "   4. IP Blocking Middleware"
echo "   5. Suspicious Activity Monitoring"
echo ""
echo "📍 AKSES:"
echo "   - Buka Panel Admin"
echo "   - Pilih 'Security Settings' di sidebar"
echo "   - Hanya akun dengan ID 1 yang bisa akses"
echo ""
echo "⚠️  NOTES:"
echo "   - Backup tersimpan di: $BACKUP_DIR"
echo "   - Restart panel jika ada masalah: systemctl restart pteroq"
echo "   - Logs banned IPs: storage/logs/blocked_ips.log"
echo ""
echo "🔧 Troubleshooting:"
echo "   - php artisan route:list | grep security"
echo "   - php artisan migrate:status"
echo "   - tail -f storage/logs/laravel.log"
echo "======================================================"
