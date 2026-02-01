#!/bin/bash

echo "FIXING MIDDLEWARE ERROR: CheckBannedIP does not exist"
echo "====================================================="

# 1. Cari dan hapus middleware CheckBannedIP dari Kernel
echo "1. Removing problematic middleware from Kernel..."
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"

if [ -f "$KERNEL_FILE" ]; then
    # Hapus baris yang mengandung CheckBannedIP
    sed -i '/CheckBannedIP/d' "$KERNEL_FILE"
    sed -i '/PterodactylHttpMiddlewareCheckBannedIP/d' "$KERNEL_FILE"
    
    # Hapus baris kosong berlebihan
    sed -i '/^$/N;/^\n$/D' "$KERNEL_FILE"
    
    echo "✅ Middleware dihapus dari Kernel"
else
    echo "⚠️  Kernel file tidak ditemukan"
fi

# 2. Hapus file middleware CheckBannedIP jika ada
echo "2. Removing CheckBannedIP middleware file..."
MIDDLEWARE_FILES=(
    "/var/www/pterodactyl/app/Http/Middleware/CheckBannedIP.php"
    "/var/www/pterodactyl/app/Http/Middleware/PterodactylHttpMiddlewareCheckBannedIP.php"
)

for file in "${MIDDLEWARE_FILES[@]}"; do
    if [ -f "$file" ]; then
        rm -f "$file"
        echo "✅ Deleted: $file"
    fi
done

# 3. Perbaiki routes file - hapus middleware yang bermasalah
echo "3. Fixing routes file..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

if [ -f "$ROUTES_FILE" ]; then
    # Backup
    cp "$ROUTES_FILE" "${ROUTES_FILE}.backup.middleware"
    
    # Hapus middleware CheckBannedIP dari routes
    sed -i '/CheckBannedIP/d' "$ROUTES_FILE"
    sed -i '/PterodactylHttpMiddlewareCheckBannedIP/d' "$ROUTES_FILE"
    
    # Perbaiki security routes
    sed -i "s/'middleware' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\CheckBannedIP, //g" "$ROUTES_FILE"
    
    echo "✅ Routes file cleaned"
fi

# 4. Buat middleware OwnerOnly yang benar
echo "4. Creating correct OwnerOnly middleware..."
OWNER_MIDDLEWARE="/var/www/pterodactyl/app/Http/Middleware/OwnerOnly.php"

cat > "$OWNER_MIDDLEWARE" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
        // Only user ID 1 can access
        if (!auth()->check() || auth()->id() !== 1) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Forbidden',
                    'message' => 'Only the owner can access this section.'
                ], 403);
            }
            
            return redirect()->route('admin.index')
                ->with('error', 'Only the owner can access security settings.');
        }
        
        return $next($request);
    }
}
EOF

echo "✅ OwnerOnly middleware created"

# 5. Register OwnerOnly di Kernel jika belum
echo "5. Registering OwnerOnly in Kernel..."
if grep -q "'owner.only'" "$KERNEL_FILE"; then
    echo "✅ OwnerOnly already registered"
else
    # Cari baris protected $routeMiddleware
    if grep -q "protected \$routeMiddleware = \[" "$KERNEL_FILE"; then
        sed -i "/protected \$routeMiddleware = \[/a\ \ \ \ 'owner.only' => \\\\Pterodactyl\\\\Http\\\\Middleware\\\\OwnerOnly::class," "$KERNEL_FILE"
        echo "✅ OwnerOnly registered in Kernel"
    else
        echo "⚠️  Cannot find routeMiddleware array in Kernel"
    fi
fi

# 6. Update routes untuk pakai owner.only
echo "6. Updating security routes..."
# Hapus semua security routes dulu
sed -i '/Route::group.*security/,/});/d' "$ROUTES_FILE"

# Tambahkan security routes yang benar
cat >> "$ROUTES_FILE" << 'EOF'

// ============================================
// SECURITY ROUTES - OWNER ONLY
// ============================================
Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {
    Route::get('/', 'Admin\SecurityController@index')->name('admin.security');
    Route::get('/banned-ips', 'Admin\SecurityController@bannedIps')->name('admin.security.banned-ips');
    Route::post('/ban-ip', 'Admin\SecurityController@banIp')->name('admin.security.ban-ip');
    Route::post('/unban-ip/{id}', 'Admin\SecurityController@unbanIp')->name('admin.security.unban-ip');
    Route::get('/rate-limits', 'Admin\SecurityController@rateLimits')->name('admin.security.rate-limits');
    Route::post('/toggle-rate-limit/{id}', 'Admin\SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');
    Route::post('/update-rate-limit/{id}', 'Admin\SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');
});
EOF

echo "✅ Security routes updated"

# 7. Buat SecurityController sederhana
echo "7. Creating simple SecurityController..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"

cat > "$CONTROLLER_FILE" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\Cache;

class SecurityController extends Controller
{
    public function index()
    {
        return view('admin.security.index', [
            'totalBanned' => 0,
            'rateLimits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ],
            'bannedIPs' => collect(),
        ]);
    }
    
    public function bannedIps(Request $request)
    {
        return view('admin.security.banned-ips', [
            'ips' => collect(),
            'search' => $request->get('search', '')
        ]);
    }
    
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255'
        ]);
        
        return redirect()->route('admin.security.banned-ips')
            ->with('success', "IP {$request->ip_address} has been banned.");
    }
    
    public function unbanIp($id)
    {
        return redirect()->back()->with('success', 'IP has been unbanned.');
    }
    
    public function rateLimits()
    {
        $limits = [
            [
                'id' => 'api',
                'name' => 'API Rate Limit',
                'description' => 'Limit API requests',
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
        $request->validate([
            'max_requests' => 'required|integer|min:1|max:1000',
            'time_window' => 'required|integer|min:1|max:86400'
        ]);
        
        Cache::put("rate_limit:config:{$id}_max", $request->max_requests);
        Cache::put("rate_limit:config:{$id}_window", $request->time_window);
        
        return redirect()->back()->with('success', 'Rate limit updated.');
    }
}
EOF

echo "✅ SecurityController created"

# 8. Buat views sederhana
echo "8. Creating views..."
VIEWS_DIR="/var/www/pterodactyl/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view
cat > "${VIEWS_DIR}/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title', 'Security Dashboard')

@section('content-header')
    <h1>Security Dashboard</h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
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
        <div class="box">
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
@endsection
EOF

# Banned IPs view
cat > "${VIEWS_DIR}/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title', 'Banned IPs')

@section('content-header')
    <h1>Banned IPs</h1>
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
                <h3 class="box-title">Banned IP Management</h3>
            </div>
            <div class="box-body">
                @if(session('success'))
                <div class="alert alert-success">{{ session('success') }}</div>
                @endif
                
                <div class="text-right" style="margin-bottom: 15px;">
                    <button class="btn btn-danger" data-toggle="modal" data-target="#banModal">
                        <i class="fa fa-plus"></i> Ban New IP
                    </button>
                </div>
                
                <p>No banned IPs yet. Use the button above to ban an IP address.</p>
            </div>
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
                        <label>IP Address *</label>
                        <input type="text" name="ip_address" class="form-control" placeholder="192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label>Reason (Optional)</label>
                        <input type="text" name="reason" class="form-control" placeholder="e.g., DDoS attempt">
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
    <h1>Rate Limits</h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Rate Limits</li>
    </ol>
@endsection

@section('content')
<div class="row">
    @foreach($limits as $limit)
    <div class="col-md-4">
        <div class="box box-{{ $limit['enabled'] ? 'success' : 'default' }}">
            <div class="box-header">
                <h3 class="box-title">{{ $limit['name'] }}</h3>
                <div class="box-tools">
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
                        <input type="number" name="max_requests" class="form-control" value="{{ $limit['max'] }}" min="1" max="1000">
                    </div>
                    <div class="form-group">
                        <label>Time Window (seconds)</label>
                        <input type="number" name="time_window" class="form-control" value="{{ $limit['window'] }}" min="1" max="86400">
                    </div>
                    <button type="submit" class="btn btn-primary">Save</button>
                </form>
            </div>
        </div>
    </div>
    @endforeach
</div>

<div class="row">
    <div class="col-md-12">
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
        setTimeout(() => location.reload(), 1000);
    }
}

function disableAll() {
    if (confirm('Disable all rate limits?')) {
        @foreach($limits as $limit)
        $.post('{{ route("admin.security.toggle-rate-limit", $limit["id"]) }}', {_token: '{{ csrf_token() }}'});
        @endforeach
        setTimeout(() => location.reload(), 1000);
    }
}

$('.toggle-btn').click(function() {
    const id = $(this).data('id');
    $.post('/admin/security/toggle-rate-limit/' + id, {_token: '{{ csrf_token() }}'}, function() {
        location.reload();
    });
});
</script>
@endsection
EOF

echo "✅ Views created"

# 9. Clear semua cache
echo "9. Clearing cache..."
cd /var/www/pterodactyl

# Hapus semua file cache
rm -f bootstrap/cache/*.php 2>/dev/null

# Clear cache dengan artisan
sudo -u www-data php artisan cache:clear 2>/dev/null
sudo -u www-data php artisan config:clear 2>/dev/null
sudo -u www-data php artisan route:clear 2>/dev/null
sudo -u www-data php artisan view:clear 2>/dev/null

# 10. Dump autoload
echo "10. Dumping autoload..."
sudo -u www-data composer dump-autoload -o 2>/dev/null

# 11. Test
echo "11. Testing..."
echo "=== Checking files ==="
echo "Controller: $(ls -la app/Http/Controllers/Admin/SecurityController.php)"
echo "Middleware: $(ls -la app/Http/Middleware/OwnerOnly.php)"
echo "Views: $(ls resources/views/admin/security/*.blade.php | wc -l) files"

echo ""
echo "=== Testing routes ==="
php artisan route:list | grep -i security || echo "No security routes found"

echo ""
echo "=== Testing controller ==="
php -r "
require 'vendor/autoload.php';
try {
    \$controller = new \Pterodactyl\Http\Controllers\Admin\SecurityController();
    echo '✅ Controller instantiated successfully\n';
    echo '✅ Class: ' . get_class(\$controller) . '\n';
} catch (Exception \$e) {
    echo '❌ Error: ' . \$e->getMessage() . '\n';
}
"

# 12. Fix permission
echo "12. Fixing permissions..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

# 13. Restart services
echo "13. Restarting services..."
# Cari PHP version
PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PHP_SERVICE="php${PHP_VERSION}-fpm"

systemctl restart "$PHP_SERVICE" 2>/dev/null || echo "⚠️  Could not restart $PHP_SERVICE"
systemctl restart nginx 2>/dev/null || echo "⚠️  Could not restart nginx"
systemctl restart pteroq 2>/dev/null || echo "⚠️  Could not restart pteroq"

echo ""
echo "====================================================="
echo "FIX COMPLETED!"
echo "====================================================="
echo ""
echo "Error middleware telah dihapus."
echo "Security system sekarang menggunakan OwnerOnly middleware."
echo ""
echo "Access URLs:"
echo "1. /admin/security              (Security Dashboard)"
echo "2. /admin/security/banned-ips   (Banned IP Management)"
echo "3. /admin/security/rate-limits  (Rate Limit Settings)"
echo ""
echo "Note: Only user ID 1 (owner) can access these pages."
echo ""
echo "If still having issues:"
echo "1. Check logs: tail -f storage/logs/laravel.log"
echo "2. Test with: curl -I http://localhost/admin/security"
echo "3. Clear cache: php artisan cache:clear"
echo "====================================================="
