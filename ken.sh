#!/bin/bash

echo "Memperbaiki duplicate route error..."
echo "===================================="

# 1. Cari semua route yang pakai admin.security
echo "1. Mencari duplicate routes..."
ROUTES_FILE="/var/www/pterodactyl/routes/admin.php"

if [ -f "$ROUTES_FILE" ]; then
    # Backup dulu
    cp "$ROUTES_FILE" "${ROUTES_FILE}.backup.$(date +%s)"
    
    # Hapus semua security routes yang duplicate
    sed -i '/\/\/ Security Routes/,/});/d' "$ROUTES_FILE"
    
    # Tambahkan routes yang benar
    cat >> "$ROUTES_FILE" << 'EOF'

// Security Routes - Owner Only
Route::group(['prefix' => 'security', 'middleware' => 'owner.only'], function () {
    Route::get('/', 'Admin\\SecurityController@index')->name('admin.security');
    Route::get('/banned-ips', 'Admin\\SecurityController@bannedIps')->name('admin.security.banned-ips');
    Route::post('/ban-ip', 'Admin\\SecurityController@banIp')->name('admin.security.ban-ip');
    Route::post('/unban-ip/{id}', 'Admin\\SecurityController@unbanIp')->name('admin.security.unban-ip');
    Route::get('/rate-limits', 'Admin\\SecurityController@rateLimits')->name('admin.security.rate-limits');
    Route::post('/toggle-rate-limit/{id}', 'Admin\\SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');
    Route::post('/update-rate-limit/{id}', 'Admin\\SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');
});
EOF
    
    echo "✅ Routes diperbaiki"
fi

# 2. Perbaiki namespace di controller
echo "2. Memperbaiki namespace controller..."
CONTROLLER_FILE="/var/www/pterodactyl/app/Http/Controllers/Admin/SecurityController.php"

# Backup controller
cp "$CONTROLLER_FILE" "${CONTROLLER_FILE}.backup"

# Buat controller yang benar dengan namespace lengkap
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
        $bannedCount = 0;
        $bannedIPs = collect();
        
        try {
            $bannedCount = DB::table('security_banned_ips')->where('is_active', 1)->count();
            $bannedIPs = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->orderBy('created_at', 'desc')
                ->limit(5)
                ->get();
        } catch (\Exception $e) {
            // Table doesn't exist yet
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
        $ips = collect();
        
        try {
            $query = DB::table('security_banned_ips');
            
            if ($search) {
                $query->where('ip_address', 'like', "%{$search}%")
                      ->orWhere('reason', 'like', "%{$search}%");
            }
            
            $ips = $query->orderBy('created_at', 'desc')->paginate(20);
        } catch (\Exception $e) {
            // Table doesn't exist
        }
        
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
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            ");
        } catch (\Exception $e) {
            // Table might already exist
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

echo "✅ Controller diperbarui"

# 3. Clear cache routes
echo "3. Membersihkan cache..."
cd /var/www/pterodactyl

# Hapus file cache routes
rm -f bootstrap/cache/routes*.php 2>/dev/null
rm -f bootstrap/cache/packages*.php 2>/dev/null
rm -f bootstrap/cache/config*.php 2>/dev/null

# Clear cache
sudo -u www-data php artisan route:clear
sudo -u www-data php artisan config:clear
sudo -u www-data php artisan view:clear

# 4. Cek routes
echo "4. Testing routes..."
php artisan route:list | grep -i security || echo "⚠️  Routes belum muncul, coba optimize"

# 5. Optimize dengan force
echo "5. Optimizing..."
sudo -u www-data php artisan optimize:clear
sudo -u www-data php artisan route:cache

# 6. Cek lagi
echo "6. Final check..."
php artisan route:list | grep -i security && echo "✅ Routes berhasil!" || echo "⚠️  Routes masih bermasalah"

# 7. Test akses controller
echo "7. Testing controller access..."
php artisan tinker --execute='
try {
    $reflection = new ReflectionClass(\Pterodactyl\Http\Controllers\Admin\SecurityController::class);
    echo "✅ Controller class exists\n";
    
    $methods = $reflection->getMethods();
    echo "✅ Controller has " . count($methods) . " methods\n";
    
    echo "✅ Testing DB connection...\n";
    try {
        DB::select("SELECT 1");
        echo "✅ DB connection OK\n";
    } catch (\Exception $e) {
        echo "⚠️  DB error: " . $e->getMessage() . "\n";
    }
} catch (\Exception $e) {
    echo "❌ Controller error: " . $e->getMessage() . "\n";
}
'

# 8. Buat tabel jika belum ada
echo "8. Membuat tabel security_banned_ips..."
DB_PASSWORD=$(grep DB_PASSWORD /var/www/pterodactyl/.env | cut -d '=' -f2)
if [ -n "$DB_PASSWORD" ]; then
    mysql -u pterodactyl -p"$DB_PASSWORD" panel << 'EOF'
CREATE TABLE IF NOT EXISTS security_banned_ips (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE NOT NULL,
    reason VARCHAR(255) NULL,
    banned_by BIGINT UNSIGNED NULL,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_ip_active (ip_address, is_active),
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
SHOW TABLES LIKE 'security_banned_ips';
EOF
else
    echo "⚠️  Tidak bisa mendapatkan DB password"
fi

# 9. Fix permission
echo "9. Fixing permissions..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

echo "===================================="
echo "PERBAIKAN SELESAI!"
echo "===================================="
echo ""
echo "Untuk test:"
echo "1. Login sebagai owner (user ID 1)"
echo "2. Buka: https://your-domain.com/admin/security"
echo ""
echo "Jika masih error:"
echo "1. Cek logs: tail -f storage/logs/laravel.log"
echo "2. Routes: php artisan route:list | grep security"
echo "3. Controller: ls -la app/Http/Controllers/Admin/SecurityController.php"
echo ""
echo "URL yang tersedia:"
echo "- /admin/security (Dashboard)"
echo "- /admin/security/banned-ips (Manage IP bans)"
echo "- /admin/security/rate-limits (Rate limit settings)"
echo "===================================="
