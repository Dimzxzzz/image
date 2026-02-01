#!/bin/bash

echo "Perbaikan Error 500 dan Instalasi Security..."
echo "=============================================="

# 1. Cek error logs
echo "1. Mengecek error logs..."
tail -n 50 /var/www/pterodactyl/storage/logs/laravel.log 2>/dev/null | tail -20

# 2. Backup controller yang bermasalah
echo "2. Backup controller..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"
if [ -f "$CONTROLLER_FILE" ]; then
    cp "$CONTROLLER_FILE" "${CONTROLLER_FILE}.backup.$(date +%s)"
    echo "✅ Controller dibackup"
fi

# 3. Buat controller yang benar-benar sederhana
echo "3. Membuat controller yang benar..."
cat > "$CONTROLLER_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class SecurityController extends Controller
{
    public function index()
    {
        // Cek table exists
        $tableExists = false;
        try {
            $tableExists = DB::select("SHOW TABLES LIKE 'security_banned_ips'");
        } catch (\Exception $e) {
            // Table doesn't exist
        }
        
        $bannedIPs = collect();
        $totalBanned = 0;
        
        if ($tableExists) {
            $bannedIPs = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->orderBy('created_at', 'desc')
                ->limit(10)
                ->get();
                
            $totalBanned = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->count();
        }
        
        $rateLimits = [
            'api' => Cache::get('rate_limit:enabled:api', true),
            'login' => Cache::get('rate_limit:enabled:login', true),
            'files' => Cache::get('rate_limit:enabled:files', true),
        ];
        
        return view('admin.security.index', [
            'bannedIPs' => $bannedIPs,
            'rateLimits' => $rateLimits,
            'totalBanned' => $totalBanned,
        ]);
    }
    
    public function bannedIps(Request $request)
    {
        $search = $request->get('search', '');
        $ips = collect();
        
        try {
            $query = DB::table('security_banned_ips');
            
            if ($search) {
                $query->where('ip_address', 'like', "%{$search}%")
                      ->orWhere('reason', 'like', "%{$search}%");
            }
            
            $ips = $query->orderBy('created_at', 'desc')->paginate(20);
        } catch (\Exception $e) {
            // Table doesn't exist yet
        }
        
        return view('admin.security.banned-ips', [
            'ips' => $ips,
            'search' => $search
        ]);
    }
    
    public function banIp(Request $request)
    {
        $validated = $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|in:1hour,1day,1week,1month,permanent'
        ]);
        
        // Create table if not exists
        try {
            DB::statement("
                CREATE TABLE IF NOT EXISTS security_banned_ips (
                    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) UNIQUE NOT NULL,
                    reason VARCHAR(255) NULL,
                    banned_by BIGINT UNSIGNED NULL,
                    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            ");
        } catch (\Exception $e) {
            // Table might already exist
        }
        
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
                case '1month':
                    $expiresAt = now()->addMonth();
                    break;
            }
        }
        
        DB::table('security_banned_ips')->updateOrInsert(
            ['ip_address' => $request->ip_address],
            [
                'reason' => $request->reason,
                'banned_by' => auth()->id(),
                'expires_at' => $expiresAt,
                'is_active' => 1,
                'updated_at' => now()
            ]
        );
        
        return redirect()->route('admin.security.banned-ips')
            ->with('success', "IP {$request->ip_address} has been banned.");
    }
    
    public function unbanIp($id)
    {
        try {
            DB::table('security_banned_ips')
                ->where('id', $id)
                ->update(['is_active' => 0]);
                
            return redirect()->back()->with('success', 'IP has been unbanned.');
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Error: ' . $e->getMessage());
        }
    }
    
    public function rateLimits()
    {
        $limits = [
            [
                'id' => 'api',
                'name' => 'API Rate Limit',
                'description' => 'Limit requests to API endpoints',
                'enabled' => Cache::get('rate_limit:enabled:api', true),
                'max' => Cache::get('rate_limit:config:api_max', 60),
                'window' => Cache::get('rate_limit:config:api_window', 60)
            ],
            [
                'id' => 'login',
                'name' => 'Login Rate Limit',
                'description' => 'Limit login attempts',
                'enabled' => Cache::get('rate_limit:enabled:login', true),
                'max' => Cache::get('rate_limit:config:login_max', 5),
                'window' => Cache::get('rate_limit:config:login_window', 300)
            ],
            [
                'id' => 'files',
                'name' => 'File Operations',
                'description' => 'Limit file operations',
                'enabled' => Cache::get('rate_limit:enabled:files', true),
                'max' => Cache::get('rate_limit:config:files_max', 30),
                'window' => Cache::get('rate_limit:config:files_window', 60)
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
        $validated = $request->validate([
            'max_requests' => 'required|integer|min:1|max:1000',
            'time_window' => 'required|integer|min:1|max:86400'
        ]);
        
        Cache::put("rate_limit:config:{$id}_max", $request->max_requests);
        Cache::put("rate_limit:config:{$id}_window", $request->time_window);
        
        return redirect()->back()->with('success', 'Rate limit updated.');
    }
}
EOF
echo "✅ Controller dibuat"

# 4. Cari dan tambahkan sidebar menu
echo "4. Mencari file sidebar..."
# Cari semua file blade yang mungkin berisi navigation
FOUND_SIDEBAR=false
for file in $(find /var/www/pterodactyl/resources/views -name "*.blade.php" -type f); do
    if grep -q "admin.settings" "$file" && grep -q "<li.*active" "$file"; then
        echo "📁 Found possible sidebar: $file"
        SIDEBAR_FILE="$file"
        FOUND_SIDEBAR=true
        
        # Backup
        cp "$SIDEBAR_FILE" "${SIDEBAR_FILE}.backup"
        
        # Tambahkan menu security
        if ! grep -q "admin.security" "$file"; then
            # Cari pattern Settings dan tambahkan setelahnya
            sed -i '/route("admin.settings")/,/<\/a>/ {
                /<\/a>/a\
                @if(auth()->check() && auth()->user()->id === 1)\
                <li class="{{ $active == '\''security'\'' ? '\''active'\'' : '\'''\'' }}">\
                    <a href="{{ route('\''admin.security'\'') }}">\
                        <i class="fa fa-shield"></i> Security Settings\
                    </a>\
                </li>\
                @endif
            }' "$file"
            echo "✅ Menu ditambahkan ke: $file"
        fi
        break
    fi
done

if [ "$FOUND_SIDEBAR" = false ]; then
    echo "⚠️  Sidebar tidak ditemukan, buat manual inclusion"
    # Buat file include sederhana
    INCLUDE_FILE="/var/www/pterodactyl/resources/views/admin/security/menu.blade.php"
    mkdir -p "$(dirname "$INCLUDE_FILE")"
    cat > "$INCLUDE_FILE" << 'EOF'
@if(auth()->check() && auth()->user()->id === 1)
<li class="{{ $active == 'security' ? 'active' : '' }}">
    <a href="{{ route('admin.security') }}">
        <i class="fa fa-shield"></i> Security Settings
    </a>
</li>
@endif
EOF
    echo "✅ Created menu include at: $INCLUDE_FILE"
fi

# 5. Buat views yang benar
echo "5. Memperbaiki views..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view - SANGAT SEDERHANA
cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title', 'Security Settings')

@section('content-header')
    <h1>Security Settings</h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-md-12">
        <div class="box box-primary">
            <div class="box-header">
                <h3 class="box-title">Security Dashboard</h3>
            </div>
            <div class="box-body">
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
                                Manage <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="small-box bg-yellow">
                            <div class="inner">
                                @php
                                    $active = 0;
                                    foreach($rateLimits as $limit) {
                                        if($limit) $active++;
                                    }
                                @endphp
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
                    
                    <div class="col-md-4">
                        <div class="small-box bg-green">
                            <div class="inner">
                                <h3>Ready</h3>
                                <p>Security System</p>
                            </div>
                            <div class="icon">
                                <i class="fa fa-check"></i>
                            </div>
                            <a href="{{ route('admin.security.banned-ips') }}" class="small-box-footer">
                                Get Started <i class="fa fa-arrow-circle-right"></i>
                            </a>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-12">
                        <div class="box box-default">
                            <div class="box-header">
                                <h3 class="box-title">Quick Actions</h3>
                            </div>
                            <div class="box-body">
                                <div class="row">
                                    <div class="col-md-4">
                                        <a href="{{ route('admin.security.banned-ips') }}" class="btn btn-danger btn-block">
                                            <i class="fa fa-ban"></i> Manage Banned IPs
                                        </a>
                                    </div>
                                    <div class="col-md-4">
                                        <a href="{{ route('admin.security.rate-limits') }}" class="btn btn-warning btn-block">
                                            <i class="fa fa-tachometer"></i> Rate Limits
                                        </a>
                                    </div>
                                    <div class="col-md-4">
                                        <button class="btn btn-info btn-block" onclick="location.reload()">
                                            <i class="fa fa-refresh"></i> Refresh
                                        </button>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
EOF

# Banned IPs view
cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title', 'Banned IPs')

@section('content-header')
    <h1>Banned IP Addresses</h1>
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
            <div class="box-header">
                <h3 class="box-title">Banned IP List</h3>
                <div class="box-tools">
                    <form method="GET" class="form-inline">
                        <input type="text" name="search" class="form-control input-sm" placeholder="Search..." value="{{ request('search') }}">
                        <button type="submit" class="btn btn-sm btn-default"><i class="fa fa-search"></i></button>
                    </form>
                </div>
            </div>
            <div class="box-body">
                @if(session('success'))
                    <div class="alert alert-success">{{ session('success') }}</div>
                @endif
                @if(session('error'))
                    <div class="alert alert-danger">{{ session('error') }}</div>
                @endif
                
                <div class="text-right" style="margin-bottom: 10px;">
                    <button class="btn btn-danger" data-toggle="modal" data-target="#banModal">
                        <i class="fa fa-plus"></i> Ban New IP
                    </button>
                </div>
                
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
                                <td>{{ $ip->banned_at }}</td>
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
                
                @if($ips->hasPages())
                <div class="text-center">
                    {{ $ips->links() }}
                </div>
                @endif
            </div>
        </div>
    </div>
</div>

<!-- Ban Modal -->
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
                        <input type="text" name="ip_address" class="form-control" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>Reason (Optional)</label>
                        <input type="text" name="reason" class="form-control" placeholder="e.g., DDoS attempt">
                    </div>
                    <div class="form-group">
                        <label>Duration</label>
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

@section('title', 'Rate Limits')

@section('content-header')
    <h1>Rate Limit Settings</h1>
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
                <div class="box-tools pull-right">
                    <button class="btn btn-xs btn-{{ $limit['enabled'] ? 'success' : 'default' }} toggle-btn" data-id="{{ $limit['id'] }}">
                        {{ $limit['enabled'] ? 'Enabled' : 'Disabled' }}
                    </button>
                </div>
            </div>
            <div class="box-body">
                <p>{{ $limit['description'] }}</p>
                <form action="{{ route('admin.security.update-rate-limit', $limit['id']) }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label>Max Requests</label>
                        <input type="number" name="max_requests" class="form-control" value="{{ $limit['max'] }}" min="1" max="1000" required>
                    </div>
                    <div class="form-group">
                        <label>Time Window (seconds)</label>
                        <input type="number" name="time_window" class="form-control" value="{{ $limit['window'] }}" min="1" max="86400" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Save Settings</button>
                </form>
            </div>
        </div>
    </div>
    @endforeach
</div>

<div class="row">
    <div class="col-md-12">
        <div class="box box-info">
            <div class="box-header">
                <h3 class="box-title">Quick Actions</h3>
            </div>
            <div class="box-body">
                <button class="btn btn-success" onclick="enableAll()">Enable All</button>
                <button class="btn btn-default" onclick="disableAll()">Disable All</button>
                <a href="{{ route('admin.security') }}" class="btn btn-info">Back to Security</a>
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
        $.post('{{ route("admin.security.toggle-rate-limit", $limit["id"]) }}', {_token: '{{ csrf_token() }}'});
        @endforeach
        setTimeout(() => location.reload(), 500);
    }
}

function disableAll() {
    if (confirm('Disable all rate limits?')) {
        @foreach($limits as $limit)
        $.post('{{ route("admin.security.toggle-rate-limit", $limit["id"]) }}', {_token: '{{ csrf_token() }}'});
        @endforeach
        setTimeout(() => location.reload(), 500);
    }
}

$('.toggle-btn').click(function() {
    const id = $(this).data('id');
    $.post('/admin/security/toggle-rate-limit/' + id, {_token: '{{ csrf_token() }}'}, function() {
        location.reload();
    });
});
</script>
EOF
echo "✅ Views diperbaiki"

# 6. Fix permission dan clear cache
echo "6. Membersihkan cache dan permission..."
cd /var/www/pterodactyl

# Fix ownership
chown -R www-data:www-data /var/www/pterodactyl/storage
chown -R www-data:www-data /var/www/pterodactyl/bootstrap/cache

# Clear cache sebagai www-data
sudo -u www-data php artisan view:clear
sudo -u www-data php artisan config:clear
sudo -u www-data php artisan route:clear

# 7. Test jika controller bisa diakses
echo "7. Testing controller..."
php artisan tinker --execute='
try {
    $controller = new \Pterodactyl\Http\Controllers\Admin\SecurityController();
    echo "✅ Controller OK\n";
} catch (\Exception $e) {
    echo "❌ Controller Error: " . $e->getMessage() . "\n";
}
'

# 8. Cek routes
echo "8. Cek routes..."
php artisan route:list | grep -i security || echo "⚠️  Routes tidak ditemukan"

# 9. Buat middleware sederhana jika diperlukan
echo "9. Membuat middleware..."
MIDDLEWARE_FILE="/var/www/pterodactyl/app/Http/Middleware/CheckOwner.php"
mkdir -p "$(dirname "$MIDDLEWARE_FILE")"

cat > "$MIDDLEWARE_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class CheckOwner
{
    public function handle(Request $request, Closure $next)
    {
        // Hanya user ID 1 yang bisa akses
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Access denied. Owner only.');
        }
        
        return $next($request);
    }
}
EOF

# Register middleware di Kernel jika belum
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"
if [ -f "$KERNEL_FILE" ] && ! grep -q "CheckOwner" "$KERNEL_FILE"; then
    sed -i "/protected \$routeMiddleware = \[/a\ \ \ \ 'owner.only' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\CheckOwner::class," "$KERNEL_FILE"
    echo "✅ Middleware registered"
fi

# 10. Update routes untuk pakai middleware
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"
if [ -f "$ROUTES_FILE" ] && grep -q "'middleware' => 'owner.only'" "$ROUTES_FILE"; then
    echo "✅ Routes sudah pakai middleware"
else
    # Update routes untuk pakai middleware
    sed -i "s/Route::group(\['prefix' => 'security'\], function () {/Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {/" "$ROUTES_FILE"
    echo "✅ Routes updated dengan middleware"
fi

echo "=============================================="
echo "PERBAIKAN SELESAI!"
echo "=============================================="
echo ""
echo "Langkah selanjutnya:"
echo "1. Buka website panel Anda"
echo "2. Login sebagai user ID 1 (owner)"
echo "3. Coba akses: https://your-panel.com/admin/security"
echo ""
echo "Jika masih error 500:"
echo "1. Cek logs: tail -f /var/www/pterodactyl/storage/logs/laravel.log"
echo "2. Fix permission: chown -R www-data:www-data /var/www/pterodactyl"
echo "3. Clear cache: php artisan cache:clear"
echo ""
echo "Untuk debugging:"
echo "- php artisan route:list | grep security"
echo "- ls -la app/Http/Controllers/Admin/SecurityController.php"
echo "- Cek apakah tabel exists: SHOW TABLES LIKE 'security_banned_ips'"
echo "=============================================="
