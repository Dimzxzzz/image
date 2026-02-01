#!/bin/bash

echo "FINAL FIX: Class SecurityController does not exist"
echo "===================================================="

# 1. Periksa file controller
echo "1. Checking SecurityController..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"

if [ ! -f "$CONTROLLER_FILE" ]; then
    echo "❌ Controller tidak ditemukan!"
    exit 1
fi

# 2. Periksa namespace yang benar
echo "2. Memperbaiki namespace..."
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
        try {
            $bannedCount = DB::table('security_banned_ips')->where('is_active', 1)->count();
            $bannedIPs = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->orderBy('created_at', 'desc')
                ->limit(5)
                ->get();
        } catch (\Exception $e) {
            $bannedCount = 0;
            $bannedIPs = collect();
        }
        
        return view('admin.security.index', [
            'bannedIPs' => $bannedIPs,
            'rateLimits' => [
                'api' => Cache::get('rate_limit:enabled:api', true),
                'login' => Cache::get('rate_limit:enabled:login', true),
                'files' => Cache::get('rate_limit:enabled:files', true),
            ],
            'totalBanned' => $bannedCount,
        ]);
    }
    
    public function bannedIps(Request $request)
    {
        $search = $request->get('search', '');
        
        try {
            $query = DB::table('security_banned_ips');
            
            if ($search) {
                $query->where('ip_address', 'like', "%{$search}%")
                      ->orWhere('reason', 'like', "%{$search}%");
            }
            
            $ips = $query->orderBy('created_at', 'desc')->paginate(20);
        } catch (\Exception $e) {
            $ips = collect();
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
        
        try {
            DB::table('security_banned_ips')->updateOrInsert(
                ['ip_address' => $request->ip_address],
                [
                    'reason' => $request->reason,
                    'banned_by' => auth()->id(),
                    'expires_at' => $request->duration === 'permanent' ? null : now()->add(1, $request->duration),
                    'is_active' => 1,
                    'updated_at' => now()
                ]
            );
            
            return redirect()->route('admin.security.banned-ips')
                ->with('success', "IP {$request->ip_address} has been banned.");
        } catch (\Exception $e) {
            return redirect()->back()->with('error', 'Error: ' . $e->getMessage());
        }
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

echo "✅ Controller updated"

# 3. Periksa routes
echo "3. Checking routes..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

# Backup routes
cp "$ROUTES_FILE" "${ROUTES_FILE}.backup.final"

# Hapus semua security routes
sed -i '/security/d' "$ROUTES_FILE"
sed -i '/Security/d' "$ROUTES_FILE"

# Tambahkan routes yang benar
cat > /tmp/security_routes << 'EOF'

// ========================
// SECURITY ROUTES
// ========================
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

# Tambahkan ke file routes
cat /tmp/security_routes >> "$ROUTES_FILE"
rm -f /tmp/security_routes

echo "✅ Routes updated"

# 4. Fix autoload
echo "4. Fixing autoload..."
cd /var/www/pterodactyl

# Hapus vendor jika perlu
# rm -rf vendor  # JANGAN dihapus!

# Dump autoload
sudo -u www-data composer dump-autoload -o

# 5. Clear cache COMPLETE
echo "5. Clearing ALL cache..."
rm -rf bootstrap/cache/*
mkdir -p bootstrap/cache
chown -R www-data:www-data bootstrap/cache

# Clear laravel cache
sudo -u www-data php artisan cache:clear 2>/dev/null || true
sudo -u www-data php artisan config:clear
sudo -u www-data php artisan route:clear
sudo -u www-data php artisan view:clear

# 6. Test controller dengan php langsung
echo "6. Testing controller existence..."
cat > /tmp/test_controller.php << 'EOF'
<?php
require_once '/var/www/pterodactyl/vendor/autoload.php';

use Pterodactyl\Http\Controllers\Admin\SecurityController;

try {
    $reflection = new ReflectionClass(SecurityController::class);
    echo "✅ SecurityController class exists\n";
    echo "✅ Namespace: " . $reflection->getNamespaceName() . "\n";
    echo "✅ Methods: " . count($reflection->getMethods()) . "\n";
} catch (Exception $e) {
    echo "❌ Error: " . $e->getMessage() . "\n";
}
EOF

php /tmp/test_controller.php
rm -f /tmp/test_controller.php

# 7. Buat middleware sederhana
echo "7. Creating middleware..."
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
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Access denied. Owner only.');
        }
        
        return $next($request);
    }
}
EOF

echo "✅ Middleware created"

# 8. Test dengan artisan tinker tanpa psy-sh
echo "8. Testing with artisan..."
cat > /tmp/test_artisan.php << 'EOF'
<?php
define('LARAVEL_START', microtime(true));
require __DIR__.'/vendor/autoload.php';
$app = require_once __DIR__.'/bootstrap/app.php';
$kernel = $app->make(Illuminate\Contracts\Http\Kernel::class);
$response = $kernel->handle($request = Illuminate\Http\Request::capture());

// Test controller
try {
    $controller = $app->make(\Pterodactyl\Http\Controllers\Admin\SecurityController::class);
    echo "✅ Controller instantiated successfully\n";
} catch (Exception $e) {
    echo "❌ Controller error: " . $e->getMessage() . "\n";
}

// Test routes
$router = $app['router'];
$routes = $router->getRoutes()->getRoutes();
$securityRoutes = array_filter($routes, function($route) {
    return strpos($route->uri, 'security') !== false;
});
echo "✅ Found " . count($securityRoutes) . " security routes\n";

foreach ($securityRoutes as $route) {
    echo "  - " . $route->uri . " -> " . $route->action['uses'] . "\n";
}
EOF

cd /var/www/pterodactyl
php /tmp/test_artisan.php
rm -f /tmp/test_artisan.php

# 9. Fix permission
echo "9. Fixing permissions..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

# 10. Restart services
echo "10. Restarting services..."
# Cari PHP version
PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PHP_SERVICE="php${PHP_VERSION}-fpm"

systemctl restart "$PHP_SERVICE" 2>/dev/null || echo "⚠️  Could not restart $PHP_SERVICE"
systemctl restart nginx 2>/dev/null || echo "⚠️  Could not restart nginx"
systemctl restart pteroq 2>/dev/null || echo "⚠️  Could not restart pteroq"

# 11. Test akhir
echo "11. Final test..."
echo "=== Cek routes ==="
php artisan route:list | grep -i security || echo "No security routes found"

echo ""
echo "=== Cek controller ==="
ls -la app/Http/Controllers/Admin/SecurityController.php

echo ""
echo "=== Cek views ==="
ls -la resources/views/admin/security/

echo ""
echo "=== Cek middleware ==="
ls -la app/Http/Middleware/OwnerOnly.php

echo ""
echo "===================================================="
echo "FINAL FIX COMPLETE!"
echo "===================================================="
echo ""
echo "To access security panel:"
echo "1. Login as OWNER (user ID 1)"
echo "2. Visit: https://your-domain.com/admin/security"
echo ""
echo "If still having issues:"
echo "1. Check logs: tail -f storage/logs/laravel.log"
echo "2. Test manually: curl -I http://localhost/admin/security"
echo "3. Clear cache: php artisan cache:clear"
echo ""
echo "Features available:"
echo "- /admin/security (Dashboard)"
echo "- /admin/security/banned-ips (IP Ban Management)"
echo "- /admin/security/rate-limits (Rate Limit Settings)"
echo ""
echo "ONLY user ID 1 can access!"
echo "===================================================="
