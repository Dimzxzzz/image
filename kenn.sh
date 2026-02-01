#!/bin/bash

echo "Memperbaiki permission cache dan instalasi security..."
echo "======================================================="

# 1. Fix permission cache directory
echo "1. Memperbaiki permission cache..."
CACHE_DIR="/var/www/pterodactyl/storage/framework/cache"
if [ -d "$CACHE_DIR" ]; then
    rm -rf "$CACHE_DIR/data"/*
    chown -R www-data:www-data "$CACHE_DIR"
    chmod -R 775 "$CACHE_DIR"
    echo "✅ Permission cache diperbaiki"
else
    mkdir -p "$CACHE_DIR/data"
    chown -R www-data:www-data "$CACHE_DIR"
    chmod -R 775 "$CACHE_DIR"
    echo "✅ Direktori cache dibuat"
fi

# 2. Fix semua permission storage
echo "2. Memperbaiki permission storage..."
STORAGE_DIR="/var/www/pterodactyl/storage"
chown -R www-data:www-data "$STORAGE_DIR"
chmod -R 775 "$STORAGE_DIR"
find "$STORAGE_DIR" -type f -exec chmod 664 {} \;
find "$STORAGE_DIR" -type d -exec chmod 775 {} \;
echo "✅ Permission storage diperbaiki"

# 3. Clear semua cache
echo "3. Membersihkan cache..."
cd /var/www/pterodactyl
sudo -u www-data php artisan view:clear
sudo -u www-data php artisan config:clear
sudo -u www-data php artisan route:clear
sudo -u www-data php artisan cache:clear
echo "✅ Cache dibersihkan"

# 4. Cek dan buat tabel security jika belum ada
echo "4. Membuat tabel security..."
cd /var/www/pterodactyl
sudo -u www-data php artisan tinker --execute='
if (!Schema::hasTable("security_banned_ips")) {
    try {
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
    } catch (\Exception $e) {
        echo "Error creating table: " . $e->getMessage() . "\n";
    }
} else {
    echo "Table security_banned_ips already exists.\n";
}
'

# 5. Buat file controller security (versi sederhana)
echo "5. Membuat controller security..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"

if [ ! -f "$CONTROLLER_FILE" ]; then
    cat > "$CONTROLLER_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

class SecurityController extends Controller
{
    public function index()
    {
        if (!Schema::hasTable('security_banned_ips')) {
            return view('admin.security.index', [
                'bannedIPs' => collect(),
                'rateLimits' => ['api' => true, 'login' => true, 'files' => true],
                'suspiciousIPs' => [],
                'totalBanned' => 0,
            ]);
        }
        
        $bannedIPs = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->orderBy('created_at', 'desc')
            ->limit(10)
            ->get();
        
        return view('admin.security.index', [
            'bannedIPs' => $bannedIPs,
            'rateLimits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ],
            'suspiciousIPs' => $this->getSuspiciousIPs(),
            'totalBanned' => DB::table('security_banned_ips')->where('is_active', true)->count(),
        ]);
    }
    
    private function getSuspiciousIPs()
    {
        $ips = [];
        $logFile = storage_path('logs/laravel.log');
        if (file_exists($logFile)) {
            $logs = @shell_exec("tail -50 $logFile 2>/dev/null | grep -i 'failed\|attempt' | head -5");
            if ($logs) {
                $lines = explode("\n", trim($logs));
                foreach ($lines as $line) {
                    if (preg_match('/(\d+\.\d+\.\d+\.\d+)/', $line, $matches)) {
                        $ip = $matches[1];
                        if (!isset($ips[$ip])) {
                            $ips[$ip] = 0;
                        }
                        $ips[$ip]++;
                    }
                }
            }
        }
        return $ips;
    }
    
    public function bannedIps(Request $request)
    {
        if (!Schema::hasTable('security_banned_ips')) {
            $ips = collect();
        } else {
            $search = $request->get('search');
            $query = DB::table('security_banned_ips');
            
            if ($search) {
                $query->where('ip_address', 'like', "%{$search}%")
                      ->orWhere('reason', 'like', "%{$search}%");
            }
            
            $ips = $query->orderBy('created_at', 'desc')->paginate(20);
        }
        
        return view('admin.security.banned-ips', [
            'ips' => $ips,
            'search' => $request->get('search')
        ]);
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|in:1hour,1day,1week,1month,permanent'
        ]);
        
        if (!Schema::hasTable('security_banned_ips')) {
            Schema::create('security_banned_ips', function ($table) {
                $table->bigIncrements('id');
                $table->string('ip_address', 45)->unique();
                $table->string('reason')->nullable();
                $table->unsignedBigInteger('banned_by')->nullable();
                $table->timestamp('banned_at')->useCurrent();
                $table->timestamp('expires_at')->nullable();
                $table->boolean('is_active')->default(true);
                $table->timestamps();
            });
        }
        
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
        
        return redirect()->back()->with('success', "IP {$request->ip_address} telah dibanned.");
    }
    
    public function unbanIp($id)
    {
        if (Schema::hasTable('security_banned_ips')) {
            DB::table('security_banned_ips')
                ->where('id', $id)
                ->update(['is_active' => false]);
        }
        
        return redirect()->back()->with('success', 'IP telah diunban.');
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
                'name' => 'File Operations Limit',
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
        
        return redirect()->back()->with('success', 'Rate limit configuration updated.');
    }
    
    public function getStats()
    {
        $bannedCount = Schema::hasTable('security_banned_ips') 
            ? DB::table('security_banned_ips')->where('is_active', true)->count() 
            : 0;
        
        return response()->json([
            'banned_ips' => $bannedCount,
            'rate_limits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ]
        ]);
    }
}
EOF
    echo "✅ Controller security dibuat"
else
    echo "⚠️  Controller sudah ada"
fi

# 6. Buat views directory dan file
echo "6. Membuat views security..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view sederhana
cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Security management</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.settings') }}">Settings</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-4">
        <div class="small-box bg-red">
            <div class="inner">
                <h3>{{ $totalBanned }}</h3>
                <p>Banned IPs</p>
            </div>
            <div class="icon">
                <i class="fa fa-ban"></i>
            </div>
            <a href="{{ route('admin.security.banned-ips') }}" class="small-box-footer">
                View All <i class="fa fa-arrow-circle-right"></i>
            </a>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="small-box bg-yellow">
            <div class="inner">
                <h3>{{ count($suspiciousIPs) }}</h3>
                <p>Suspicious IPs</p>
            </div>
            <div class="icon">
                <i class="fa fa-exclamation-triangle"></i>
            </div>
            <a href="{{ route('admin.security.banned-ips') }}" class="small-box-footer">
                View All <i class="fa fa-arrow-circle-right"></i>
            </a>
        </div>
    </div>
    
    <div class="col-md-4">
        <div class="small-box bg-green">
            <div class="inner">
                @php $active = array_sum(array_map(function($v) { return $v ? 1 : 0; }, $rateLimits)); @endphp
                <h3>{{ $active }}/3</h3>
                <p>Active Rate Limits</p>
            </div>
            <div class="icon">
                <i class="fa fa-shield"></i>
            </div>
            <a href="{{ route('admin.security.rate-limits') }}" class="small-box-footer">
                Configure <i class="fa fa-arrow-circle-right"></i>
            </a>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-6">
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title">Recent Banned IPs</h3>
            </div>
            <div class="box-body">
                <table class="table table-hover">
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
                            <td>{{ $ip->reason ?: '-' }}</td>
                            <td>{{ \Carbon\Carbon::parse($ip->created_at)->diffForHumans() }}</td>
                        </tr>
                        @empty
                        <tr>
                            <td colspan="3" class="text-center">No banned IPs</td>
                        </tr>
                        @endforelse
                    </tbody>
                </table>
                <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-danger btn-block">
                    Manage Banned IPs
                </a>
            </div>
        </div>
    </div>
    
    <div class="col-md-6">
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title">Rate Limits Status</h3>
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
                            <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-xs btn-default">
                                Configure
                            </a>
                        </td>
                    </tr>
                    @endforeach
                </table>
                <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">
                    Rate Limit Settings
                </a>
            </div>
        </div>
        
        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title">Quick Actions</h3>
            </div>
            <div class="box-body">
                <button class="btn btn-danger btn-block" data-toggle="modal" data-target="#banModal">
                    Ban IP Address
                </button>
                <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">
                    Rate Limits
                </a>
                <button onclick="refreshStats()" class="btn btn-info btn-block">
                    Refresh Stats
                </button>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="banModal" tabindex="-1">
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

@section('footer-scripts')
<script>
function refreshStats() {
    $.ajax({
        url: '{{ route('admin.security.stats') }}',
        method: 'GET',
        success: function(data) {
            alert('Banned IPs: ' + data.banned_ips + '\nAPI Limit: ' + (data.rate_limits.api ? 'Enabled' : 'Disabled'));
        }
    });
}
</script>
@endsection
EOF

# Banned IPs view
cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Banned IPs
@endsection

@section('content-header')
    <h1>Banned IPs<small>Manage banned IP addresses</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Banned IPs</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box">
            <div class="box-header with-border">
                <h3 class="box-title">Banned IP Addresses</h3>
                <div class="box-tools">
                    <div class="input-group" style="width: 200px;">
                        <form method="GET" class="input-group">
                            <input type="text" name="search" class="form-control" placeholder="Search..." value="{{ $search }}">
                            <div class="input-group-btn">
                                <button class="btn btn-default"><i class="fa fa-search"></i></button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
            <div class="box-body">
                @if(session('success'))
                <div class="alert alert-success">{{ session('success') }}</div>
                @endif
                
                <div class="table-responsive">
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
                            @forelse($ips as $ip)
                            <tr>
                                <td><code>{{ $ip->ip_address }}</code></td>
                                <td>{{ $ip->reason ?: '-' }}</td>
                                <td>{{ \Carbon\Carbon::parse($ip->banned_at)->format('Y-m-d H:i') }}</td>
                                <td>
                                    @if($ip->expires_at)
                                        {{ \Carbon\Carbon::parse($ip->expires_at)->diffForHumans() }}
                                    @else
                                        <span class="label label-danger">Permanent</span>
                                    @endif
                                </td>
                                <td>
                                    <span class="label label-{{ $ip->is_active ? 'danger' : 'success' }}">
                                        {{ $ip->is_active ? 'Active' : 'Inactive' }}
                                    </span>
                                </td>
                                <td>
                                    @if($ip->is_active)
                                    <form action="{{ route('admin.security.unban-ip', $ip->id) }}" method="POST" style="display:inline">
                                        @csrf
                                        <button type="submit" class="btn btn-xs btn-success" onclick="return confirm('Unban this IP?')">
                                            Unban
                                        </button>
                                    </form>
                                    @endif
                                </td>
                            </tr>
                            @empty
                            <tr>
                                <td colspan="6" class="text-center">No banned IPs found</td>
                            </tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
                
                @if($ips->count() > 0)
                <div class="text-center">
                    {{ $ips->appends(['search' => $search])->links() }}
                </div>
                @endif
                
                <div class="text-right">
                    <button class="btn btn-danger" data-toggle="modal" data-target="#banModal">
                        <i class="fa fa-ban"></i> Ban New IP
                    </button>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="modal fade" id="banModal" tabindex="-1">
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
                        <label>IP Address *</label>
                        <input type="text" name="ip_address" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label>Reason (Optional)</label>
                        <textarea name="reason" class="form-control" rows="2"></textarea>
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
    <h1>Rate Limits<small>Configure request limits</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Rate Limits</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box">
            <div class="box-header with-border">
                <h3 class="box-title">Rate Limit Settings</h3>
            </div>
            <div class="box-body">
                @if(session('success'))
                <div class="alert alert-success">{{ session('success') }}</div>
                @endif
                
                @foreach($limits as $limit)
                <div class="box box-{{ $limit['enabled'] ? 'success' : 'default' }}">
                    <div class="box-header">
                        <h3 class="box-title">{{ $limit['name'] }}</h3>
                        <div class="box-tools">
                            <button class="btn btn-xs btn-{{ $limit['enabled'] ? 'success' : 'default' }} toggle-limit" data-id="{{ $limit['id'] }}">
                                {{ $limit['enabled'] ? 'Enabled' : 'Disabled' }}
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
                                        <input type="number" name="max_requests" class="form-control" value="{{ $limit['config']['max'] }}" min="1" max="1000" required>
                                    </div>
                                </div>
                                <div class="col-md-6">
                                    <div class="form-group">
                                        <label>Time Window (seconds)</label>
                                        <input type="number" name="time_window" class="form-control" value="{{ $limit['config']['window'] }}" min="1" max="86400" required>
                                    </div>
                                </div>
                            </div>
                            <button type="submit" class="btn btn-primary">Save</button>
                        </form>
                    </div>
                </div>
                @endforeach
                
                <div class="box box-info">
                    <div class="box-header">
                        <h3 class="box-title">Quick Actions</h3>
                    </div>
                    <div class="box-body">
                        <button class="btn btn-success" onclick="enableAll()">Enable All</button>
                        <button class="btn btn-default" onclick="disableAll()">Disable All</button>
                    </div>
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
        toggleLimit('{{ $limit['id'] }}', true);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

function disableAll() {
    if (confirm('Disable all rate limits?')) {
        @foreach($limits as $limit)
        toggleLimit('{{ $limit['id'] }}', false);
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

$('.toggle-limit').click(function() {
    const id = $(this).data('id');
    const current = $(this).text().trim() === 'Enabled';
    toggleLimit(id, !current);
});

function toggleLimit(id, enable) {
    $.ajax({
        url: '{{ url('admin/security/toggle-rate-limit') }}/' + id,
        method: 'POST',
        data: {_token: '{{ csrf_token() }}'},
        success: function() {
            location.reload();
        }
    });
}
</script>
@endsection
EOF

# 7. Tambahkan routes secara manual jika perlu
echo "7. Menambahkan routes security..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

if [ -f "$ROUTES_FILE" ] && ! grep -q "Route::get('/security'" "$ROUTES_FILE"; then
    cat >> "$ROUTES_FILE" << 'EOF'

// Security Routes
Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {
    Route::get('/', 'SecurityController@index')->name('admin.security');
    Route::get('/banned-ips', 'SecurityController@bannedIps')->name('admin.security.banned-ips');
    Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban-ip');
    Route::post('/unban-ip/{id}', 'SecurityController@unbanIp')->name('admin.security.unban-ip');
    Route::get('/rate-limits', 'SecurityController@rateLimits')->name('admin.security.rate-limits');
    Route::post('/toggle-rate-limit/{id}', 'SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');
    Route::post('/update-rate-limit/{id}', 'SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');
    Route::get('/stats', 'SecurityController@getStats')->name('admin.security.stats');
});
EOF
    echo "✅ Routes ditambahkan"
fi

# 8. Buat middleware OwnerOnly
echo "8. Membuat middleware..."
MIDDLEWARE_FILE="/var/www/pterodactyl/app/Http/Middleware/OwnerOnly.php"
mkdir -p "$(dirname "$MIDDLEWARE_FILE")"

cat > "$MIDDLEWARE_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
        if (!$request->user() || $request->user()->id !== 1) {
            return redirect()->route('admin.index')->with('error', 'Access denied.');
        }
        
        return $next($request);
    }
}
EOF

# 9. Register middleware di Kernel
echo "9. Register middleware..."
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"
if [ -f "$KERNEL_FILE" ] && ! grep -q "'owner.only'" "$KERNEL_FILE"; then
    sed -i "/protected \$routeMiddleware = \[/a\ \ \ \ 'owner.only' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\OwnerOnly::class," "$KERNEL_FILE"
    echo "✅ Middleware registered"
fi

# 10. Fix permission akhir
echo "10. Final permission fix..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 755 /var/www/pterodactyl/bootstrap/cache
chmod -R 775 /var/www/pterodactyl/storage

# 11. Restart queue worker
echo "11. Restarting services..."
systemctl restart pteroq.service 2>/dev/null || true

echo "======================================================="
echo "PERBAIKAN SELESAI!"
echo "======================================================="
echo ""
echo "Security features sudah diinstal dengan fitur:"
echo "1. Security Dashboard"
echo "2. Banned IP Management"
echo "3. Rate Limit Control"
echo ""
echo "Akses: /admin/security"
echo "Hanya user ID 1 (owner) yang bisa akses"
echo ""
echo "Jika ada error:"
echo "1. Cek permission: ls -la /var/www/pterodactyl/storage"
echo "2. Clear cache: php artisan cache:clear"
echo "3. Cek logs: tail -f storage/logs/laravel.log"
echo "======================================================="
