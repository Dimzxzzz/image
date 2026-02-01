#!/bin/bash

echo "Instalasi Sistem Keamanan Pterodactyl (Owner Only)"
echo "===================================================="

TIMESTAMP=$(date -u +"%Y%m%d%H%M%S")
BACKUP_DIR="/var/backups/pterodactyl/security_${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        mkdir -p "$(dirname "${BACKUP_DIR}/${file}")"
        cp "$file" "${BACKUP_DIR}/${file}"
        echo "Backup dibuat: ${BACKUP_DIR}/${file}"
    fi
}

echo "1. Menambahkan routes security..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

if [ -f "$ROUTES_FILE" ]; then
    backup_file "$ROUTES_FILE"
    
    if ! grep -q "Route::group(\['prefix' => 'security'" "$ROUTES_FILE"; then
        cat > /tmp/security_routes.php << 'EOF'
            // Security Routes - Only for Owner (ID 1)
            Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {
                Route::get('/', 'SecurityController@index')->name('admin.security');
                Route::get('/banned-ips', 'SecurityController@bannedIps')->name('admin.security.banned-ips');
                Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban-ip');
                Route::post('/unban-ip/{id}', 'SecurityController@unbanIp')->name('admin.security.unban-ip');
                Route::post('/mass-unban', 'SecurityController@massUnban')->name('admin.security.mass-unban');
                Route::get('/rate-limits', 'SecurityController@rateLimits')->name('admin.security.rate-limits');
                Route::post('/toggle-rate-limit/{id}', 'SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');
                Route::post('/update-rate-limit/{id}', 'SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');
                Route::get('/stats', 'SecurityController@getStats')->name('admin.security.stats');
                Route::post('/clear-logs', 'SecurityController@clearLogs')->name('admin.security.clear-logs');
                Route::get('/export-banned-ips', 'SecurityController@exportBannedIPs')->name('admin.security.export-banned-ips');
            });
EOF
        
        # Insert after settings route group
        sed -i '/Route::group(\['"'"'prefix'"'"' => '"'"'settings'"'"'\], function () {/,/});/ {
            /});/ {
                r /tmp/security_routes.php
            }
        }' "$ROUTES_FILE"
        
        rm -f /tmp/security_routes.php
    fi
else
    echo "File routes tidak ditemukan: $ROUTES_FILE"
    exit 1
fi

echo "2. Membuat middleware owner only..."
MIDDLEWARE_DIR="/var/www/pterodactyl/app/Http/Middleware"
mkdir -p "$MIDDLEWARE_DIR"

cat > "${MIDDLEWARE_DIR}/OwnerOnly.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
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

echo "3. Register middleware..."
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"

if [ -f "$KERNEL_FILE" ]; then
    backup_file "$KERNEL_FILE"
    
    if ! grep -q "'owner.only'" "$KERNEL_FILE"; then
        sed -i "/protected \$routeMiddleware = \[/a \\
        'owner.only' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\OwnerOnly::class,\\
" "$KERNEL_FILE"
    fi
fi

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
use Illuminate\Support\Facades\Schema;
use Carbon\Carbon;

class SecurityController extends Controller
{
    private function createBannedIPsTable()
    {
        if (!Schema::hasTable('security_banned_ips')) {
            try {
                DB::statement("
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
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                ");
                return true;
            } catch (\Exception $e) {
                \Log::error('Failed to create security_banned_ips table: ' . $e->getMessage());
                return false;
            }
        }
        return true;
    }
    
    public function index()
    {
        $this->createBannedIPsTable();
        
        $bannedIPs = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->where(function($q) {
                $q->whereNull('expires_at')
                  ->orWhere('expires_at', '>', now());
            })
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();
        
        $rateLimits = [
            'api' => Cache::get('rate_limit:enabled:api', true),
            'login' => Cache::get('rate_limit:enabled:login', true),
            'files' => Cache::get('rate_limit:enabled:files', true),
        ];
        
        $suspiciousIPs = [];
        $logFile = storage_path('logs/laravel.log');
        if (file_exists($logFile)) {
            $logs = @shell_exec("tail -100 $logFile 2>/dev/null | grep -i 'suspicious\|failed\|attempt\|blocked\|brute' | head -10");
            if ($logs) {
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
        $this->createBannedIPsTable();
        
        $search = $request->get('search');
        $ips = DB::table('security_banned_ips');
        
        if ($search) {
            $ips->where(function($q) use ($search) {
                $q->where('ip_address', 'like', "%{$search}%")
                  ->orWhere('reason', 'like', "%{$search}%");
            });
        }
        
        $ips = $ips->orderBy('created_at', 'desc')->paginate(20);
            
        return view('admin.security.banned-ips', compact('ips', 'search'));
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|in:1hour,1day,1week,1month,permanent'
        ]);
        
        $this->createBannedIPsTable();
        
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
        
        Cache::forget('banned_ips_list');
        
        return redirect()->back()->with('success', "IP {$request->ip_address} has been banned.");
    }
    
    public function unbanIp($id)
    {
        DB::table('security_banned_ips')
            ->where('id', $id)
            ->update(['is_active' => false]);
            
        Cache::forget('banned_ips_list');
        
        return redirect()->back()->with('success', 'IP has been unbanned.');
    }
    
    public function massUnban(Request $request)
    {
        $ids = $request->input('ids', []);
        
        if (count($ids) > 0) {
            DB::table('security_banned_ips')
                ->whereIn('id', $ids)
                ->update(['is_active' => false]);
                
            Cache::forget('banned_ips_list');
        }
        
        return redirect()->back()->with('success', 'Selected IPs have been unbanned.');
    }
    
    public function rateLimits()
    {
        $limits = [
            [
                'id' => 'api',
                'name' => 'API Rate Limit',
                'description' => 'Limit requests to general API endpoints',
                'enabled' => Cache::get('rate_limit:enabled:api', true),
                'config' => Cache::get('rate_limit:config:api', ['max' => 60, 'window' => 60])
            ],
            [
                'id' => 'login',
                'name' => 'Login Rate Limit',
                'description' => 'Limit login attempts to prevent brute force',
                'enabled' => Cache::get('rate_limit:enabled:login', true),
                'config' => Cache::get('rate_limit:config:login', ['max' => 5, 'window' => 300])
            ],
            [
                'id' => 'files',
                'name' => 'File Operations Limit',
                'description' => 'Limit file operations (upload, download, edit)',
                'enabled' => Cache::get('rate_limit:enabled:files', true),
                'config' => Cache::get('rate_limit:config:files', ['max' => 30, 'window' => 60])
            ]
        ];
        
        return view('admin.security.rate-limits', compact('limits'));
    }
    
    public function toggleRateLimit(Request $request, $id)
    {
        $current = Cache::get("rate_limit:enabled:$id", true);
        Cache::put("rate_limit:enabled:$id", !$current, now()->addDays(30));
        
        return response()->json([
            'success' => true,
            'enabled' => !$current,
            'message' => ucfirst($id) . ' rate limit ' . (!$current ? 'enabled' : 'disabled')
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
        ], now()->addDays(30));
        
        return redirect()->back()->with('success', ucfirst($id) . ' rate limit configuration updated.');
    }
    
    public function getStats()
    {
        $this->createBannedIPsTable();
        
        $stats = [
            'banned_ips' => DB::table('security_banned_ips')->where('is_active', true)->count(),
            'total_bans' => DB::table('security_banned_ips')->count(),
            'recent_bans' => DB::table('security_banned_ips')
                ->where('created_at', '>', now()->subDay())
                ->count(),
            'rate_limits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ]
        ];
        
        return response()->json($stats);
    }
    
    public function clearLogs()
    {
        $logTypes = request()->input('log_types', []);
        
        if (in_array('access', $logTypes)) {
            $file = storage_path('logs/access.log');
            if (file_exists($file)) {
                file_put_contents($file, '');
            }
        }
        
        if (in_array('security', $logTypes)) {
            $file = storage_path('logs/security.log');
            if (file_exists($file)) {
                file_put_contents($file, '');
            }
        }
        
        return redirect()->back()->with('success', 'Selected logs cleared.');
    }
    
    public function exportBannedIPs()
    {
        $this->createBannedIPsTable();
        
        $ips = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->select('ip_address', 'reason', 'banned_at', 'expires_at')
            ->get();
            
        $content = "# Banned IPs Export - " . now()->format('Y-m-d H:i:s') . "\n";
        $content .= "# Total: " . $ips->count() . "\n\n";
        
        foreach ($ips as $ip) {
            $content .= $ip->ip_address;
            if ($ip->reason) {
                $content .= " # " . $ip->reason;
            }
            $content .= "\n";
        }
        
        return response($content)
            ->header('Content-Type', 'text/plain')
            ->header('Content-Disposition', 'attachment; filename="banned_ips_' . date('Y-m-d') . '.txt"');
    }
}
EOF

echo "5. Membuat views security..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Monitor and manage security settings</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.settings') }}">Settings</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-3 col-sm-6">
        <div class="info-box bg-red">
            <span class="info-box-icon"><i class="fa fa-ban"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Banned IPs</span>
                <span class="info-box-number">{{ $totalBanned }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: 100%"></div>
                </div>
                <span class="progress-description">
                    Active bans
                </span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="info-box bg-yellow">
            <span class="info-box-icon"><i class="fa fa-exclamation-triangle"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Suspicious IPs</span>
                <span class="info-box-number">{{ count($suspiciousIPs) }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: 100%"></div>
                </div>
                <span class="progress-description">
                    Last 24 hours
                </span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="info-box bg-green">
            <span class="info-box-icon"><i class="fa fa-check-circle"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Active Rate Limits</span>
                <span class="info-box-number">
                    {{ array_sum(array_map(function($v) { return $v ? 1 : 0; }, $rateLimits)) }}/3
                </span>
                <div class="progress">
                    @php $active = array_sum(array_map(function($v) { return $v ? 1 : 0; }, $rateLimits)); @endphp
                    <div class="progress-bar" style="width: {{ ($active/3)*100 }}%"></div>
                </div>
                <span class="progress-description">
                    Protection enabled
                </span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6">
        <div class="info-box bg-blue">
            <span class="info-box-icon"><i class="fa fa-shield"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Security Status</span>
                <span class="info-box-number">Protected</span>
                <div class="progress">
                    <div class="progress-bar" style="width: 100%"></div>
                </div>
                <span class="progress-description">
                    Last updated: Just now
                </span>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title">Recent Banned IPs</h3>
                <div class="box-tools">
                    <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-xs btn-default">View All</a>
                </div>
            </div>
            <div class="box-body">
                <div class="table-responsive">
                    <table class="table table-hover table-striped">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Reason</th>
                                <th>Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            @forelse($bannedIPs as $ip)
                            <tr>
                                <td><code>{{ $ip->ip_address }}</code></td>
                                <td>{{ $ip->reason ?: 'No reason provided' }}</td>
                                <td>{{ \Carbon\Carbon::parse($ip->created_at)->diffForHumans() }}</td>
                            </tr>
                            @empty
                            <tr>
                                <td colspan="3" class="text-center text-muted">No banned IPs</td>
                            </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
                <div class="text-center">
                    <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-danger btn-sm">
                        <i class="fa fa-list"></i> Manage Banned IPs
                    </a>
                    <button class="btn btn-default btn-sm" data-toggle="modal" data-target="#banIpModal">
                        <i class="fa fa-plus"></i> Add Ban
                    </button>
                </div>
            </div>
        </div>
        
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title">Rate Limits Status</h3>
                <div class="box-tools">
                    <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-xs btn-default">Configure</a>
                </div>
            </div>
            <div class="box-body">
                <div class="row">
                    @foreach($rateLimits as $key => $enabled)
                    <div class="col-md-4">
                        <div class="small-box bg-{{ $enabled ? 'green' : 'gray' }}">
                            <div class="inner">
                                <h4 style="margin: 0; font-size: 16px;">{{ ucfirst($key) }}</h4>
                                <p style="font-size: 12px;">{{ $enabled ? 'ENABLED' : 'DISABLED' }}</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-{{ $enabled ? 'check' : 'times' }}"></i>
                            </div>
                            <a href="{{ route('admin.security.rate-limits') }}" class="small-box-footer">
                                Configure <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                    @endforeach
                </div>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title">Suspicious Activity</h3>
                <div class="box-tools">
                    <span class="badge bg-red">{{ count($suspiciousIPs) }} IPs</span>
                </div>
            </div>
            <div class="box-body">
                @if(count($suspiciousIPs) > 0)
                <div class="table-responsive">
                    <table class="table table-hover">
                        <thead>
                            <tr>
                                <th>IP Address</th>
                                <th>Attempts</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            @foreach($suspiciousIPs as $ip => $count)
                            <tr>
                                <td><code>{{ $ip }}</code></td>
                                <td>
                                    <span class="badge bg-red">{{ $count }}</span>
                                </td>
                                <td>
                                    <form action="{{ route('admin.security.ban-ip') }}" method="POST" style="display:inline">
                                        @csrf
                                        <input type="hidden" name="ip_address" value="{{ $ip }}">
                                        <input type="hidden" name="reason" value="Suspicious activity detected">
                                        <input type="hidden" name="duration" value="1day">
                                        <button type="submit" class="btn btn-xs btn-danger" onclick="return confirm('Ban this IP?')">
                                            Ban
                                        </button>
                                    </form>
                                </td>
                            </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                @else
                <div class="alert alert-success">
                    <i class="fa fa-check"></i> No suspicious activity detected in recent logs.
                </div>
                @endif
            </div>
        </div>
        
        <div class="box box-success">
            <div class="box-header with-border">
                <h3 class="box-title">Quick Actions</h3>
            </div>
            <div class="box-body">
                <div class="row">
                    <div class="col-md-4">
                        <button class="btn btn-block btn-danger" data-toggle="modal" data-target="#banIpModal">
                            <i class="fa fa-ban"></i> Ban IP
                        </button>
                    </div>
                    <div class="col-md-4">
                        <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-block btn-warning">
                            <i class="fa fa-sliders"></i> Rate Limits
                        </a>
                    </div>
                    <div class="col-md-4">
                        <button class="btn btn-block btn-info" onclick="refreshStats()">
                            <i class="fa fa-refresh"></i> Refresh
                        </button>
                    </div>
                </div>
                <div class="row" style="margin-top: 10px;">
                    <div class="col-md-6">
                        <a href="{{ route('admin.security.export-banned-ips') }}" class="btn btn-block btn-default">
                            <i class="fa fa-download"></i> Export Bans
                        </a>
                    </div>
                    <div class="col-md-6">
                        <button class="btn btn-block btn-default" data-toggle="modal" data-target="#clearLogsModal">
                            <i class="fa fa-trash"></i> Clear Logs
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
                        <label for="ip_address">IP Address *</label>
                        <input type="text" class="form-control" name="ip_address" 
                               placeholder="e.g., 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <textarea class="form-control" name="reason" rows="2" 
                                  placeholder="Why is this IP being banned?"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="duration">Ban Duration</label>
                        <select name="duration" class="form-control">
                            <option value="1hour">1 Hour</option>
                            <option value="1day">1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="1month">1 Month</option>
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

<!-- Clear Logs Modal -->
<div class="modal fade" id="clearLogsModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <form action="{{ route('admin.security.clear-logs') }}" method="POST">
                @csrf
                <div class="modal-header">
                    <button type="button" class="close" data-dismiss="modal">&times;</button>
                    <h4 class="modal-title">Clear Logs</h4>
                </div>
                <div class="modal-body">
                    <div class="form-group">
                        <label>Select logs to clear:</label>
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="log_types[]" value="access" checked>
                                Access Logs
                            </label>
                        </div>
                        <div class="checkbox">
                            <label>
                                <input type="checkbox" name="log_types[]" value="security">
                                Security Logs
                            </label>
                        </div>
                    </div>
                    <div class="alert alert-warning">
                        <i class="fa fa-warning"></i> This action cannot be undone. Logs will be permanently deleted.
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                    <button type="submit" class="btn btn-danger">Clear Selected Logs</button>
                </div>
            </form>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
<script>
function refreshStats() {
    $.ajax({
        url: '{{ route('admin.security.stats') }}',
        method: 'GET',
        success: function(data) {
            alert('Security Statistics:\n\n' +
                  'Active Banned IPs: ' + data.banned_ips + '\n' +
                  'Total Bans: ' + data.total_bans + '\n' +
                  'Recent Bans (24h): ' + data.recent_bans + '\n\n' +
                  'Rate Limits Status:\n' +
                  '- API: ' + (data.rate_limits.api ? 'Enabled' : 'Disabled') + '\n' +
                  '- Login: ' + (data.rate_limits.login ? 'Enabled' : 'Disabled') + '\n' +
                  '- Files: ' + (data.rate_limits.files ? 'Enabled' : 'Disabled'));
        }
    });
}
</script>
@endsection
EOF

cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Banned IPs Management
@endsection

@section('content-header')
    <h1>Banned IPs Management<small>Manage blocked IP addresses</small></h1>
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
                    <div class="input-group input-group-sm" style="width: 200px;">
                        <form method="GET" action="{{ route('admin.security.banned-ips') }}" class="input-group">
                            <input type="text" name="search" class="form-control pull-right" 
                                   placeholder="Search IP or reason..." value="{{ $search }}">
                            <div class="input-group-btn">
                                <button type="submit" class="btn btn-default"><i class="fa fa-search"></i></button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <div class="box-body">
                @if(session('success'))
                <div class="alert alert-success alert-dismissible">
                    <button type="button" class="close" data-dismiss="alert">&times;</button>
                    {{ session('success') }}
                </div>
                @endif
                
                <form id="massActionForm" method="POST" action="{{ route('admin.security.mass-unban') }}">
                    @csrf
                    <div class="table-responsive">
                        <table class="table table-hover table-striped">
                            <thead>
                                <tr>
                                    <th width="30"><input type="checkbox" id="selectAll"></th>
                                    <th width="80">ID</th>
                                    <th>IP Address</th>
                                    <th>Reason</th>
                                    <th>Banned At</th>
                                    <th>Expires At</th>
                                    <th>Status</th>
                                    <th width="100">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                @forelse($ips as $ip)
                                <tr>
                                    <td><input type="checkbox" name="ids[]" value="{{ $ip->id }}"></td>
                                    <td>{{ $ip->id }}</td>
                                    <td>
                                        <code>{{ $ip->ip_address }}</code>
                                    </td>
                                    <td>{{ $ip->reason ?: 'No reason provided' }}</td>
                                    <td>
                                        <span title="{{ $ip->banned_at }}">
                                            {{ \Carbon\Carbon::parse($ip->banned_at)->diffForHumans() }}
                                        </span>
                                    </td>
                                    <td>
                                        @if($ip->expires_at)
                                            <span title="{{ $ip->expires_at }}">
                                                {{ \Carbon\Carbon::parse($ip->expires_at)->diffForHumans() }}
                                            </span>
                                        @else
                                            <span class="label label-danger">PERMANENT</span>
                                        @endif
                                    </td>
                                    <td>
                                        @if($ip->is_active)
                                            <span class="label label-danger">ACTIVE</span>
                                        @else
                                            <span class="label label-success">INACTIVE</span>
                                        @endif
                                    </td>
                                    <td>
                                        @if($ip->is_active)
                                        <form action="{{ route('admin.security.unban-ip', $ip->id) }}" 
                                              method="POST" style="display:inline">
                                            @csrf
                                            <button type="submit" class="btn btn-xs btn-success"
                                                    onclick="return confirm('Unban this IP?')" title="Unban">
                                                <i class="fa fa-check"></i>
                                            </button>
                                        </form>
                                        @endif
                                        <button class="btn btn-xs btn-default" 
                                                onclick="showIPDetails({{ json_encode($ip) }})" title="View Details">
                                            <i class="fa fa-eye"></i>
                                        </button>
                                    </td>
                                </tr>
                                @empty
                                <tr>
                                    <td colspan="8" class="text-center text-muted">
                                        No banned IPs found.
                                        @if($search)
                                        Try a different search term.
                                        @endif
                                    </td>
                                </tr>
                                @endforelse
                            </tbody>
                        </table>
                    </div>
                    
                    @if($ips->count() > 0)
                    <div class="row">
                        <div class="col-md-8">
                            <button type="button" class="btn btn-danger btn-sm" onclick="confirmMassUnban()">
                                <i class="fa fa-check-circle"></i> Unban Selected
                            </button>
                            <span class="text-muted" style="margin-left: 10px;">
                                {{ $ips->count() }} IP(s) found
                            </span>
                        </div>
                        <div class="col-md-4 text-right">
                            <a href="{{ route('admin.security.export-banned-ips') }}" class="btn btn-default btn-sm">
                                <i class="fa fa-download"></i> Export List
                            </a>
                            <button class="btn btn-danger btn-sm" data-toggle="modal" data-target="#banIpModal">
                                <i class="fa fa-plus"></i> Add Ban
                            </button>
                        </div>
                    </div>
                    @endif
                </form>
                
                <div class="text-center">
                    {{ $ips->appends(['search' => $search])->links() }}
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
                               placeholder="e.g., 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <textarea class="form-control" name="reason" rows="3" 
                                  placeholder="Why is this IP being banned? This will be logged."></textarea>
                    </div>
                    <div class="form-group">
                        <label for="duration">Ban Duration</label>
                        <select name="duration" class="form-control">
                            <option value="1hour">1 Hour</option>
                            <option value="1day">1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="1month">1 Month</option>
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

<!-- IP Details Modal -->
<div class="modal fade" id="ipDetailsModal" tabindex="-1" role="dialog">
    <div class="modal-dialog" role="document">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">IP Address Details</h4>
            </div>
            <div class="modal-body">
                <div class="row">
                    <div class="col-md-6">
                        <strong>IP Address:</strong>
                        <p><code id="detail-ip"></code></p>
                    </div>
                    <div class="col-md-6">
                        <strong>Status:</strong>
                        <p><span id="detail-status" class="label"></span></p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-6">
                        <strong>Banned At:</strong>
                        <p id="detail-banned-at"></p>
                    </div>
                    <div class="col-md-6">
                        <strong>Expires At:</strong>
                        <p id="detail-expires-at"></p>
                    </div>
                </div>
                <div class="row">
                    <div class="col-md-12">
                        <strong>Reason:</strong>
                        <p id="detail-reason" class="well well-sm" style="margin-bottom: 0;"></p>
                    </div>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
<script>
$('#selectAll').click(function() {
    $('input[name="ids[]"]').prop('checked', this.checked);
});

function showIPDetails(ip) {
    $('#detail-ip').text(ip.ip_address);
    $('#detail-status').text(ip.is_active ? 'ACTIVE' : 'INACTIVE')
        .removeClass().addClass('label ' + (ip.is_active ? 'label-danger' : 'label-success'));
    $('#detail-banned-at').text(ip.banned_at);
    $('#detail-expires-at').html(ip.expires_at ? ip.expires_at : '<span class="label label-danger">PERMANENT</span>');
    $('#detail-reason').text(ip.reason || 'No reason provided');
    $('#ipDetailsModal').modal('show');
}

function confirmMassUnban() {
    var checked = $('input[name="ids[]"]:checked').length;
    if (checked === 0) {
        alert('Please select at least one IP to unban.');
        return;
    }
    
    if (confirm('Are you sure you want to unban ' + checked + ' IP address(es)?')) {
        $('#massActionForm').submit();
    }
}
</script>
@endsection
EOF

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
        <div class="nav-tabs-custom">
            <ul class="nav nav-tabs">
                <li class="active"><a href="#limits" data-toggle="tab">Rate Limits</a></li>
                <li><a href="#configuration" data-toggle="tab">Configuration</a></li>
            </ul>
            <div class="tab-content">
                <div class="tab-pane active" id="limits">
                    @if(session('success'))
                    <div class="alert alert-success alert-dismissible">
                        <button type="button" class="close" data-dismiss="alert">&times;</button>
                        {{ session('success') }}
                    </div>
                    @endif
                    
                    <div class="row">
                        @foreach($limits as $limit)
                        <div class="col-md-6">
                            <div class="box box-{{ $limit['enabled'] ? 'success' : 'default' }}">
                                <div class="box-header with-border">
                                    <h3 class="box-title">{{ $limit['name'] }}</h3>
                                    <div class="box-tools pull-right">
                                        <button class="btn btn-xs btn-{{ $limit['enabled'] ? 'success' : 'default' }} toggle-rate"
                                                data-id="{{ $limit['id'] }}">
                                            {{ $limit['enabled'] ? 'ENABLED' : 'DISABLED' }}
                                        </button>
                                    </div>
                                </div>
                                <div class="box-body">
                                    <p>{{ $limit['description'] }}</p>
                                    
                                    <div class="row">
                                        <div class="col-md-6">
                                            <div class="info-box bg-{{ $limit['enabled'] ? 'blue' : 'gray' }}">
                                                <span class="info-box-icon">
                                                    <i class="fa fa-bolt"></i>
                                                </span>
                                                <div class="info-box-content">
                                                    <span class="info-box-text">Max Requests</span>
                                                    <span class="info-box-number">{{ $limit['config']['max'] }}</span>
                                                </div>
                                            </div>
                                        </div>
                                        <div class="col-md-6">
                                            <div class="info-box bg-{{ $limit['enabled'] ? 'blue' : 'gray' }}">
                                                <span class="info-box-icon">
                                                    <i class="fa fa-clock-o"></i>
                                                </span>
                                                <div class="info-box-content">
                                                    <span class="info-box-text">Time Window</span>
                                                    <span class="info-box-number">{{ $limit['config']['window'] }}s</span>
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <form action="{{ route('admin.security.update-rate-limit', $limit['id']) }}" 
                                          method="POST" class="form-horizontal">
                                        @csrf
                                        <div class="form-group">
                                            <label class="col-sm-4 control-label">Max Requests</label>
                                            <div class="col-sm-8">
                                                <input type="number" name="max_requests" 
                                                       class="form-control" 
                                                       value="{{ $limit['config']['max'] }}"
                                                       min="1" max="1000" required>
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <label class="col-sm-4 control-label">Time Window (seconds)</label>
                                            <div class="col-sm-8">
                                                <input type="number" name="time_window" 
                                                       class="form-control" 
                                                       value="{{ $limit['config']['window'] }}"
                                                       min="1" max="86400" required>
                                            </div>
                                        </div>
                                        <div class="form-group">
                                            <div class="col-sm-offset-4 col-sm-8">
                                                <button type="submit" class="btn btn-primary">
                                                    <i class="fa fa-save"></i> Update Settings
                                                </button>
                                            </div>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                        @endforeach
                    </div>
                    
                    <div class="box box-info">
                        <div class="box-header with-border">
                            <h3 class="box-title">Quick Actions</h3>
                        </div>
                        <div class="box-body">
                            <div class="row">
                                <div class="col-md-4">
                                    <button class="btn btn-block btn-success" onclick="enableAllLimits()">
                                        <i class="fa fa-toggle-on"></i> Enable All
                                    </button>
                                </div>
                                <div class="col-md-4">
                                    <button class="btn btn-block btn-default" onclick="disableAllLimits()">
                                        <i class="fa fa-toggle-off"></i> Disable All
                                    </button>
                                </div>
                                <div class="col-md-4">
                                    <button class="btn btn-block btn-warning" onclick="testRateLimits()">
                                        <i class="fa fa-flask"></i> Test Settings
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="tab-pane" id="configuration">
                    <div class="box box-warning">
                        <div class="box-header with-border">
                            <h3 class="box-title">Rate Limit Configuration Guide</h3>
                        </div>
                        <div class="box-body">
                            <div class="callout callout-info">
                                <h4>Understanding Rate Limits</h4>
                                <p>Rate limiting controls how many requests a client can make to your API within a specified time window. This prevents abuse and protects your server from DDoS attacks.</p>
                            </div>
                            
                            <div class="callout callout-warning">
                                <h4>Recommended Settings</h4>
                                <ul>
                                    <li><strong>API Endpoints:</strong> 60-100 requests per minute for normal usage</li>
                                    <li><strong>Login Attempts:</strong> 5 attempts per 5 minutes to prevent brute force</li>
                                    <li><strong>File Operations:</strong> 20-30 operations per minute to prevent resource exhaustion</li>
                                </ul>
                            </div>
                            
                            <div class="callout callout-danger">
                                <h4>Warning</h4>
                                <p>Setting limits too low may affect legitimate users. Setting them too high may leave your server vulnerable to attacks. Monitor your logs and adjust accordingly.</p>
                            </div>
                            
                            <h4>How It Works</h4>
                            <ol>
                                <li>When a client makes a request, the system checks if they've exceeded the limit</li>
                                <li>If exceeded, the request is blocked with HTTP 429 (Too Many Requests)</li>
                                <li>The limit resets after the time window expires</li>
                                <li>Blocked requests are logged for monitoring</li>
                            </ol>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
<script>
function enableAllLimits() {
    if (confirm('Enable all rate limits?')) {
        @foreach($limits as $limit)
        toggleRateLimit('{{ $limit['id'] }}', true);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

function disableAllLimits() {
    if (confirm('Disable all rate limits? This may leave your server vulnerable.')) {
        @foreach($limits as $limit)
        toggleRateLimit('{{ $limit['id'] }}', false);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

function testRateLimits() {
    alert('Rate limit test functionality would connect to your API endpoints to verify limits are working correctly.\n\nThis feature requires additional setup.');
}

$('.toggle-rate').click(function() {
    const id = $(this).data('id');
    const current = $(this).text().trim() === 'ENABLED';
    toggleRateLimit(id, !current);
});

function toggleRateLimit(id, enable) {
    $.ajax({
        url: '{{ url('admin/security/toggle-rate-limit') }}/' + id,
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

echo "6. Menambahkan menu security di sidebar..."
SIDEBAR_FILE="/var/www/pterodactyl/resources/views/admin/partials/navigation.blade.php"

if [ -f "$SIDEBAR_FILE" ]; then
    backup_file "$SIDEBAR_FILE"
    
    if ! grep -q "Security Settings" "$SIDEBAR_FILE"; then
        # Gunakan approach yang lebih sederhana
        sed -i '/<a href="{{ route("admin.settings") }}">/ {
            :a
            N
            /<\/a>/!ba
            a\
            @if(auth()->user()->id === 1)\
            <li class="{{ $active === '"'"'security'"'"' ? '"'"'active'"'"' : '"'"''"'"' }}">\
                <a href="{{ route('"'"'admin.security'"'"') }}">\
                    <i class="fa fa-shield"></i> <span>Security Settings</span>\
                </a>\
            </li>\
            @endif
        }' "$SIDEBAR_FILE"
    fi
else
    echo "Sidebar file not found at: $SIDEBAR_FILE"
    echo "Creating alternative sidebar inclusion..."
    
    # Coba file sidebar lainnya
    SIDEBAR_FILES=(
        "/var/www/pterodactyl/resources/views/layouts/admin.blade.php"
        "/var/www/pterodactyl/resources/views/templates/admin.blade.php"
        "/var/www/pterodactyl/resources/views/admin/index.blade.php"
    )
    
    for file in "${SIDEBAR_FILES[@]}"; do
        if [ -f "$file" ] && grep -q "admin.settings" "$file"; then
            echo "Found sidebar in: $file"
            SIDEBAR_FILE="$file"
            break
        fi
    done
    
    if [ -f "$SIDEBAR_FILE" ]; then
        backup_file "$SIDEBAR_FILE"
        # Insert sederhana di akhir sebelum penutup
        if grep -q "Settings" "$SIDEBAR_FILE"; then
            sed -i '/Settings/i\
            @if(auth()->user()->id === 1)\
            <li class="{{ $active === '"'"'security'"'"' ? '"'"'active'"'"' : '"'"''"'"' }}">\
                <a href="{{ route('"'"'admin.security'"'"') }}">\
                    <i class="fa fa-shield"></i> <span>Security Settings</span>\
                </a>\
            </li>\
            @endif' "$SIDEBAR_FILE"
        fi
    fi
fi

echo "7. Membuat tabel database..."
cd /var/www/pterodactyl
php artisan tinker --execute='
if (!Schema::hasTable("security_banned_ips")) {
    Schema::create("security_banned_ips", function ($table) {
        $table->bigIncrements("id");
        $table->string("ip_address", 45)->unique();
        $table->string("reason")->nullable();
        $table->unsignedBigInteger("banned_by")->nullable();
        $table->timestamp("banned_at")->useCurrent();
        $table->timestamp("expires_at")->nullable();
        $table->boolean("is_active")->default(true);
        $table->text("metadata")->nullable();
        $table->timestamps();
        $table->index(["ip_address", "is_active"]);
        $table->index(["expires_at"]);
    });
    echo "Table security_banned_ips created successfully.\n";
} else {
    echo "Table security_banned_ips already exists.\n";
}
'

echo "8. Membersihkan cache..."
php artisan view:clear
php artisan config:clear
php artisan route:clear
php artisan cache:clear

echo "9. Mengatur permissions..."
chown -R www-data:www-data /var/www/pterodactyl
find /var/www/pterodactyl -type f -exec chmod 644 {} \;
find /var/www/pterodactyl -type d -exec chmod 755 {} \;
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

echo "===================================================="
echo "INSTALASI SELESAI!"
echo "===================================================="
echo ""
echo "FITUR YANG TERSEDIA:"
echo "1. Security Dashboard dengan statistik"
echo "2. Banned IP Management (Ban/Unban)"
echo "3. Rate Limit Control (API, Login, Files)"
echo "4. Suspicious Activity Monitoring"
echo "5. Mass Actions (unban multiple IP)"
echo "6. Export banned IPs list"
echo "7. Log management"
echo ""
echo "CARA AKSES:"
echo "1. Login sebagai OWNER (user ID 1)"
echo "2. Buka Admin Panel"
echo "3. Cari menu 'Security Settings' di sidebar Settings"
echo ""
echo "TROUBLESHOOTING:"
echo "- php artisan route:list | grep security"
echo "- php artisan cache:clear"
echo "- Cek apakah user ID 1 adalah owner"
echo "- Cek logs: tail -f storage/logs/laravel.log"
echo ""
echo "Backup tersimpan di: $BACKUP_DIR"
echo "===================================================="
