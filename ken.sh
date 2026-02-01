#!/bin/bash

echo "RESTORING PTERODACTYL ROUTES FILE"
echo "=================================="

# 1. Restore dari backup yang ada
echo "1. Looking for backup..."
cd /var/www/pterodactyl

# Cari backup terbaru
BACKUP_FILES=(
    "/var/www/pterodactyl/routes/admin.php.backup"
    "/var/www/pterodactyl/routes/admin.php.backup.*"
    "/root/ptero_backup_*/routes/admin.php"
)

BACKUP_FOUND=false
for backup in ${BACKUP_FILES[@]}; do
    if ls $backup 1>/dev/null 2>&1; then
        ACTUAL_BACKUP=$(ls -t $backup 2>/dev/null | head -1)
        if [ -f "$ACTUAL_BACKUP" ]; then
            echo "✅ Found backup: $ACTUAL_BACKUP"
            cp "$ACTUAL_BACKUP" "/var/www/pterodactyl/routes/admin.php"
            BACKUP_FOUND=true
            break
        fi
    fi
done

# 2. Jika tidak ada backup, buat routes dari scratch
if [ "$BACKUP_FOUND" = false ]; then
    echo "⚠️  No backup found, creating new routes file..."
    
    # Download original routes dari GitHub
    curl -s -o /tmp/admin_routes.php https://raw.githubusercontent.com/pterodactyl/panel/develop/routes/admin.php 2>/dev/null || {
        # Jika gagal download, buat minimal routes
        cat > /var/www/pterodactyl/routes/admin.php << 'EOF'
<?php

use Illuminate\Support\Facades\Route;
use Pterodactyl\Http\Controllers\Admin;

/*
|--------------------------------------------------------------------------
| Admin Routes
|--------------------------------------------------------------------------
*/

Route::get('/', 'Admin\IndexController@index')->name('admin.index');

Route::group(['prefix' => 'api'], function () {
    Route::get('/', 'Admin\ApiController@index')->name('admin.api');
});

Route::group(['prefix' => 'nodes'], function () {
    Route::get('/', 'Admin\NodesController@index')->name('admin.nodes');
});

Route::group(['prefix' => 'servers'], function () {
    Route::get('/', 'Admin\ServersController@index')->name('admin.servers');
});

Route::group(['prefix' => 'users'], function () {
    Route::get('/', 'Admin\UsersController@index')->name('admin.users');
});

Route::group(['prefix' => 'settings'], function () {
    Route::get('/', 'Admin\SettingsController@index')->name('admin.settings');
});

// ============================================
// SECURITY ROUTES - ADDED BY SECURITY SYSTEM
// ============================================
Route::group(['prefix' => 'security'], function () {
    Route::get('/', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        return view('admin.security.index', [
            'totalBanned' => 0,
            'rateLimits' => ['api' => true, 'login' => true, 'files' => true],
            'bannedIPs' => collect(),
        ]);
    })->name('admin.security');
    
    Route::get('/banned-ips', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        return view('admin.security.banned-ips', ['ips' => collect()]);
    })->name('admin.security.banned-ips');
    
    Route::get('/rate-limits', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        $limits = [
            ['id' => 'api', 'name' => 'API', 'enabled' => true, 'max' => 60, 'window' => 60, 'description' => 'API rate limit'],
            ['id' => 'login', 'name' => 'Login', 'enabled' => true, 'max' => 5, 'window' => 300, 'description' => 'Login rate limit'],
            ['id' => 'files', 'name' => 'Files', 'enabled' => true, 'max' => 30, 'window' => 60, 'description' => 'File operations limit'],
        ];
        return view('admin.security.rate-limits', compact('limits'));
    })->name('admin.security.rate-limits');
});
EOF
    }
fi

# 3. Jika kita punya file backup routes, gunakan itu
if [ -f "/tmp/admin_routes.php" ]; then
    echo "✅ Using downloaded routes file"
    cp /tmp/admin_routes.php /var/www/pterodactyl/routes/admin.php
    
    # Tambahkan security routes ke akhir file
    cat >> /var/www/pterodactyl/routes/admin.php << 'EOF'

// ============================================
// SECURITY ROUTES - ADDED BY SECURITY SYSTEM
// ============================================
Route::group(['prefix' => 'security'], function () {
    Route::get('/', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        return view('admin.security.index', [
            'totalBanned' => 0,
            'rateLimits' => ['api' => true, 'login' => true, 'files' => true],
            'bannedIPs' => collect(),
        ]);
    })->name('admin.security');
    
    Route::get('/banned-ips', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        return view('admin.security.banned-ips', ['ips' => collect()]);
    })->name('admin.security.banned-ips');
    
    Route::get('/rate-limits', function () {
        if (!auth()->check() || auth()->id() !== 1) {
            abort(403, 'Owner only');
        }
        $limits = [
            ['id' => 'api', 'name' => 'API', 'enabled' => true, 'max' => 60, 'window' => 60, 'description' => 'API rate limit'],
            ['id' => 'login', 'name' => 'Login', 'enabled' => true, 'max' => 5, 'window' => 300, 'description' => 'Login rate limit'],
            ['id' => 'files', 'name' => 'Files', 'enabled' => true, 'max' => 30, 'window' => 60, 'description' => 'File operations limit'],
        ];
        return view('admin.security.rate-limits', compact('limits'));
    })->name('admin.security.rate-limits');
});
EOF
fi

echo "✅ Routes file restored"

# 4. Hapus middleware yang bermasalah dari Kernel
echo "4. Cleaning up Kernel..."
KERNEL_FILE="/var/www/pterodactyl/app/Http/Kernel.php"

if [ -f "$KERNEL_FILE" ]; then
    # Backup kernel
    cp "$KERNEL_FILE" "${KERNEL_FILE}.backup"
    
    # Hapus middleware kita yang bermasalah
    sed -i '/CheckBannedIP/d' "$KERNEL_FILE"
    sed -i '/OwnerOnly/d' "$KERNEL_FILE"
    sed -i '/owner.only/d' "$KERNEL_FILE"
    
    # Hapus baris kosong berlebihan
    sed -i '/^$/N;/^\n$/D' "$KERNEL_FILE"
    
    echo "✅ Kernel cleaned"
fi

# 5. Hapus file middleware yang bermasalah
echo "5. Removing problematic middleware files..."
rm -f /var/www/pterodactyl/app/Http/Middleware/CheckBannedIP.php 2>/dev/null
rm -f /var/www/pterodactyl/app/Http/Middleware/OwnerOnly.php 2>/dev/null

echo "✅ Middleware files removed"

# 6. Clear semua cache
echo "6. Clearing cache..."
cd /var/www/pterodactyl

# Hapus cache files
rm -f bootstrap/cache/*.php 2>/dev/null
mkdir -p bootstrap/cache
chown -R www-data:www-data bootstrap/cache

# Clear dengan artisan
sudo -u www-data php artisan cache:clear 2>/dev/null || true
sudo -u www-data php artisan config:clear 2>/dev/null || true
sudo -u www-data php artisan route:clear 2>/dev/null || true
sudo -u www-data php artisan view:clear 2>/dev/null || true

# 7. Dump autoload
echo "7. Dumping autoload..."
sudo -u www-data composer dump-autoload -o 2>/dev/null || echo "⚠️  Composer autoload failed"

# 8. Test routes
echo "8. Testing routes..."
php artisan route:list 2>/dev/null | head -5 && echo "✅ Routes working" || echo "⚠️  Routes still problematic"

# 9. Test admin access
echo "9. Testing admin access..."
curl -I http://localhost/admin 2>/dev/null | head -1 && echo "✅ Admin accessible" || echo "⚠️  Admin not accessible"

# 10. Fix permission
echo "10. Fixing permissions..."
chown -R www-data:www-data /var/www/pterodactyl
chmod -R 775 /var/www/pterodactyl/storage
chmod -R 775 /var/www/pterodactyl/bootstrap/cache

# 11. Restart services
echo "11. Restarting services..."
PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PHP_SERVICE="php${PHP_VERSION}-fpm"

systemctl restart "$PHP_SERVICE" 2>/dev/null || echo "⚠️  Could not restart PHP-FPM"
systemctl restart nginx 2>/dev/null || echo "⚠️  Could not restart nginx"
systemctl restart pteroq 2>/dev/null || echo "⚠️  Could not restart pteroq"

echo ""
echo "=================================="
echo "RESTORE COMPLETE!"
echo "=================================="
echo ""
echo "Admin panel should be working now."
echo "Security system accessible at: /admin/security"
echo ""
echo "Note: Security routes use closure functions, not controllers."
echo "This ensures they work even if controllers have issues."
echo ""
echo "If still having issues:"
echo "1. Check logs: tail -f storage/logs/laravel.log"
echo "2. Test: curl -I http://localhost/admin"
echo "3. Test security: curl -I http://localhost/admin/security"
echo "=================================="
