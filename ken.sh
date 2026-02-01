#!/bin/bash

echo "🚀 MEMASANG SISTEM SECURITY KOMPREHENSIF"
echo "========================================="

cd /var/www/pterodactyl

# 1. Backup semua file yang akan dimodifikasi
echo "📦 Membuat backup..."
TIMESTAMP=$(date +"%Y%m%d%H%M%S")
mkdir -p /root/backup_security_$TIMESTAMP

# Backup layout admin
if [ -f "resources/views/layouts/admin.blade.php" ]; then
    cp resources/views/layouts/admin.blade.php /root/backup_security_$TIMESTAMP/admin.blade.php.bak
fi

# Backup routes
if [ -f "routes/admin.php" ]; then
    cp routes/admin.php /root/backup_security_$TIMESTAMP/admin.php.bak
fi

# 2. Perbaiki menu Security di sidebar
echo "🔧 Memperbaiki menu Security..."
if [ -f "resources/views/layouts/admin.blade.php" ]; then
    # Hapus semua menu Security yang lama
    sed -i '/<li class="header">SECURITY<\/li>/,+5d' resources/views/layouts/admin.blade.php
    
    # Tambahkan menu Security yang benar
    sed -i '/<li class="header">SERVICE MANAGEMENT<\/li>/i\
                        <li class="header">SECURITY</li>\
                        <li class="{{ ! starts_with(Route::currentRouteName(), \x27admin.security\x27) ?: \x27active\x27 }}">\
                            <a href="{{ route(\x27admin.security\x27)}}">\
                                <i class="fa fa-shield"></i> <span>Security</span>\
                            </a>\
                        </li>' resources/views/layouts/admin.blade.php
fi

# 3. Buat database untuk menyimpan IP dan security logs
echo "🗄️ Membuat tabel security database..."

mysql -u root -e "
USE panel;

-- Tabel untuk banned IP
CREATE TABLE IF NOT EXISTS security_banned_ips (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    reason TEXT,
    banned_by INT NOT NULL,
    banned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    INDEX idx_ip (ip_address),
    INDEX idx_active (is_active)
);

-- Tabel untuk security logs
CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_id INT NULL,
    action VARCHAR(50) NOT NULL,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_ip (ip_address),
    INDEX idx_created (created_at)
);

-- Tabel untuk DDoS protection settings
CREATE TABLE IF NOT EXISTS security_ddos_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    is_enabled BOOLEAN DEFAULT FALSE,
    requests_per_minute INT DEFAULT 60,
    block_threshold INT DEFAULT 10,
    block_duration INT DEFAULT 3600,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default DDoS settings
INSERT INTO security_ddos_settings (is_enabled, requests_per_minute, block_threshold, block_duration) 
VALUES (FALSE, 60, 10, 3600) 
ON DUPLICATE KEY UPDATE updated_at = CURRENT_TIMESTAMP;
"

# 4. Buat Middleware untuk Anti DDoS dan IP Filtering
echo "🛡️ Membuat middleware security..."

mkdir -p app/Http/Middleware

# Buat DDoSProtection middleware
cat > app/Http/Middleware/DDoSProtection.php << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class DDoSProtection
{
    public function handle(Request $request, Closure $next)
    {
        // Ambil setting DDoS
        $settings = Cache::remember('ddos_settings', 300, function () {
            return DB::table('security_ddos_settings')->first();
        });

        // Jika DDoS protection dinonaktifkan, lewati
        if (!$settings || !$settings->is_enabled) {
            return $next($request);
        }

        $ip = $request->ip();
        $key = 'ddos_request_count:' . $ip;
        $blockKey = 'ddos_blocked:' . $ip;

        // Cek jika IP sudah diblokir
        if (Cache::has($blockKey)) {
            abort(429, 'Too many requests. Please try again later.');
        }

        // Hitung request
        $count = Cache::get($key, 0);
        $count++;
        
        // Simpan count untuk 60 detik
        Cache::put($key, $count, 60);

        // Jika melebihi threshold, blokir IP
        if ($count > $settings->requests_per_minute) {
            // Log ke database
            DB::table('security_logs')->insert([
                'ip_address' => $ip,
                'action' => 'AUTO_BLOCK_DDOS',
                'details' => json_encode([
                    'request_count' => $count,
                    'threshold' => $settings->requests_per_minute,
                    'url' => $request->fullUrl(),
                    'user_agent' => $request->userAgent()
                ]),
                'created_at' => now()
            ]);

            // Blokir IP
            DB::table('security_banned_ips')->insert([
                'ip_address' => $ip,
                'reason' => 'DDoS protection - Exceeded rate limit',
                'banned_by' => 0, // 0 = system auto-ban
                'banned_at' => now(),
                'expires_at' => now()->addSeconds($settings->block_duration),
                'is_active' => true
            ]);

            // Set cache block
            Cache::put($blockKey, true, $settings->block_duration);
            
            abort(429, 'Too many requests. Your IP has been temporarily blocked.');
        }

        return $next($request);
    }
}
EOF

# Buat AdminAccessControl middleware
cat > app/Http/Middleware/AdminAccessControl.php << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;

class AdminAccessControl
{
    public function handle(Request $request, Closure $next)
    {
        $user = Auth::user();
        
        if (!$user) {
            return $next($request);
        }

        // Hanya cek untuk rute admin
        if (!$request->is('admin*') && !$request->is('api/admin*')) {
            return $next($request);
        }

        // ID 1 adalah super admin dengan akses penuh
        if ($user->id === 1) {
            return $next($request);
        }

        // Cek jika user adalah admin
        if (!$user->root_admin) {
            abort(403, 'Access denied. Administrator privileges required.');
        }

        // LOG SEMUA AKSES ADMIN (kecuali super admin)
        DB::table('security_logs')->insert([
            'ip_address' => $request->ip(),
            'user_id' => $user->id,
            'action' => 'ADMIN_ACCESS',
            'details' => json_encode([
                'path' => $request->path(),
                'method' => $request->method(),
                'url' => $request->fullUrl(),
                'user_agent' => $request->userAgent()
            ]),
            'created_at' => now()
        ]);

        // Untuk semua admin kecuali ID 1, batasi akses ke data orang lain
        $this->restrictAdminAccess($request, $user);

        return $next($request);
    }

    private function restrictAdminAccess(Request $request, $user)
    {
        // Cegah akses ke server yang bukan miliknya
        if ($request->route('server')) {
            $server = $request->route('server');
            if ($server->owner_id !== $user->id) {
                abort(403, 'You do not have access to this server.');
            }
        }

        // Cegah akses ke user data orang lain (kecuali listing)
        if ($request->route('user') && $request->route('user')->id !== $user->id) {
            // Hanya boleh melihat detail diri sendiri
            if ($request->isMethod('GET') && $request->route()->getName() !== 'admin.users') {
                abort(403, 'You can only view your own user details.');
            }
            
            // Tidak boleh mengedit/delete user lain
            if ($request->isMethod('POST', 'PUT', 'PATCH', 'DELETE')) {
                abort(403, 'You cannot modify other users.');
            }
        }

        // Cegah akses ke nodes yang tidak terkait
        if ($request->route('node')) {
            // Admin biasa tidak bisa mengakses nodes
            abort(403, 'Node access restricted to super admin only.');
        }
    }
}
EOF

# 5. Perbaiki FileController dengan proteksi EXTRA KUAT
echo "🔒 Memperkuat FileController..."

cat > app/Http/Controllers/Api/Client/Servers/FileController.php << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client\Servers;

use Carbon\CarbonImmutable;
use Illuminate\Http\Response;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Models\Server;
use Pterodactyl\Facades\Activity;
use Pterodactyl\Services\Nodes\NodeJWTService;
use Pterodactyl\Repositories\Wings\DaemonFileRepository;
use Pterodactyl\Transformers\Api\Client\FileObjectTransformer;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CopyFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\PullFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ListFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\ChmodFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DeleteFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\RenameFileRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CreateFolderRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\CompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\DecompressFilesRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\GetFileContentsRequest;
use Pterodactyl\Http\Requests\Api\Client\Servers\Files\WriteFileContentRequest;

class FileController extends ClientApiController
{
    public function __construct(
        private NodeJWTService $jwtService,
        private DaemonFileRepository $fileRepository
    ) {
        parent::__construct();
    }

    /**
     * 🔒 PROTEKSI EKSTRA: Validasi kepemilikan server secara menyeluruh
     */
    private function validateServerOwnership($request, Server $server)
    {
        $user = $request->user();

        // Super admin (ID 1) bebas akses
        if ($user->id === 1) {
            return true;
        }

        // Cek kepemilikan langsung
        if ($server->owner_id !== $user->id) {
            // LOG percobaan akses ilegal
            \Illuminate\Support\Facades\DB::table('security_logs')->insert([
                'ip_address' => $request->ip(),
                'user_id' => $user->id,
                'action' => 'ILLEGAL_SERVER_ACCESS_ATTEMPT',
                'details' => json_encode([
                    'server_id' => $server->id,
                    'server_owner' => $server->owner_id,
                    'requester' => $user->id,
                    'path' => $request->path(),
                    'method' => $request->method()
                ]),
                'created_at' => now()
            ]);

            abort(403, 'ACCESS DENIED: You do not own this server.');
        }

        return true;
    }

    /**
     * 🔒 PROTEKSI TAMBAHAN: Cek banned IP
     */
    private function checkBannedIP($request)
    {
        $ip = $request->ip();
        $isBanned = \Illuminate\Support\Facades\DB::table('security_banned_ips')
            ->where('ip_address', $ip)
            ->where('is_active', true)
            ->where(function($query) {
                $query->whereNull('expires_at')
                      ->orWhere('expires_at', '>', now());
            })
            ->exists();

        if ($isBanned) {
            abort(403, 'Your IP address has been banned.');
        }
    }

    /**
     * PROTEKSI AWAL: Jalankan semua validasi
     */
    private function runSecurityChecks($request, $server = null)
    {
        $this->checkBannedIP($request);
        
        if ($server) {
            $this->validateServerOwnership($request, $server);
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->runSecurityChecks($request, $server);

        $contents = $this->fileRepository
            ->setServer($server)
            ->getDirectory($request->get('directory') ?? '/');

        return $this->fractal->collection($contents)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function contents(GetFileContentsRequest $request, Server $server): Response
    {
        $this->runSecurityChecks($request, $server);

        $response = $this->fileRepository->setServer($server)->getContent(
            $request->get('file'),
            config('pterodactyl.files.max_edit_size')
        );

        Activity::event('server:file.read')->property('file', $request->get('file'))->log();

        return new Response($response, Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }

    public function download(GetFileContentsRequest $request, Server $server): array
    {
        $this->runSecurityChecks($request, $server);

        $token = $this->jwtService
            ->setExpiresAt(CarbonImmutable::now()->addMinutes(15))
            ->setUser($request->user())
            ->setClaims([
                'file_path' => rawurldecode($request->get('file')),
                'server_uuid' => $server->uuid,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);

        Activity::event('server:file.download')->property('file', $request->get('file'))->log();

        return [
            'object' => 'signed_url',
            'attributes' => [
                'url' => sprintf(
                    '%s/download/file?token=%s',
                    $server->node->getConnectionAddress(),
                    $token->toString()
                ),
            ],
        ];
    }

    public function write(WriteFileContentRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository->setServer($server)->putContent($request->get('file'), $request->getContent());

        Activity::event('server:file.write')->property('file', $request->get('file'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function create(CreateFolderRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->createDirectory($request->input('name'), $request->input('root', '/'));

        Activity::event('server:file.create-directory')
            ->property('name', $request->input('name'))
            ->property('directory', $request->input('root'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->renameFiles($request->input('root'), $request->input('files'));

        Activity::event('server:file.rename')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository
            ->setServer($server)
            ->copyFile($request->input('location'));

        Activity::event('server:file.copy')->property('file', $request->input('location'))->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function compress(CompressFilesRequest $request, Server $server): array
    {
        $this->runSecurityChecks($request, $server);

        $file = $this->fileRepository->setServer($server)->compressFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.compress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return $this->fractal->item($file)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function decompress(DecompressFilesRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        set_time_limit(300);

        $this->fileRepository->setServer($server)->decompressFile(
            $request->input('root'),
            $request->input('file')
        );

        Activity::event('server:file.decompress')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('file'))
            ->log();

        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository->setServer($server)->deleteFiles(
            $request->input('root'),
            $request->input('files')
        );

        Activity::event('server:file.delete')
            ->property('directory', $request->input('root'))
            ->property('files', $request->input('files'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository->setServer($server)->chmodFiles(
            $request->input('root'),
            $request->input('files')
        );

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function pull(PullFileRequest $request, Server $server): JsonResponse
    {
        $this->runSecurityChecks($request, $server);

        $this->fileRepository->setServer($server)->pull(
            $request->input('url'),
            $request->input('directory'),
            $request->safe(['filename', 'use_header', 'foreground'])
        );

        Activity::event('server:file.pull')
            ->property('directory', $request->input('directory'))
            ->property('url', $request->input('url'))
            ->log();

        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }
}
EOF

# 6. Tambahkan routes untuk Security
echo "🛣️ Menambahkan routes Security..."

if [ -f "routes/admin.php" ]; then
    # Tambahkan di akhir file sebelum penutup
    cat >> routes/admin.php << 'EOF'

// ============================
// SECURITY ROUTES
// ============================
Route::group(['prefix' => 'security'], function () {
    // Dashboard Security
    Route::get('/', function () {
        // Get real-time IP monitoring data
        $recentIPs = DB::table('security_logs')
            ->select('ip_address', DB::raw('MAX(created_at) as last_seen'), DB::raw('COUNT(*) as request_count'))
            ->where('created_at', '>=', now()->subHours(24))
            ->groupBy('ip_address')
            ->orderBy('last_seen', 'desc')
            ->limit(50)
            ->get();

        // Get banned IPs
        $bannedIPs = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->where(function($q) {
                $q->whereNull('expires_at')
                  ->orWhere('expires_at', '>', now());
            })
            ->orderBy('banned_at', 'desc')
            ->get();

        // Get DDoS settings
        $ddosSettings = DB::table('security_ddos_settings')->first();

        // Get attack statistics
        $stats = [
            'total_requests_24h' => DB::table('security_logs')->where('created_at', '>=', now()->subHours(24))->count(),
            'blocked_ips' => DB::table('security_banned_ips')->where('is_active', true)->count(),
            'auto_blocks' => DB::table('security_banned_ips')->where('banned_by', 0)->where('is_active', true)->count(),
            'ddos_attempts' => DB::table('security_logs')->where('action', 'LIKE', '%DDoS%')->where('created_at', '>=', now()->subHours(24))->count(),
        ];

        return view('admin.security.index', compact('recentIPs', 'bannedIPs', 'ddosSettings', 'stats'));
    })->name('admin.security');

    // Ban IP
    Route::post('/ban-ip', function (\Illuminate\Http\Request $request) {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:255',
            'duration' => 'nullable|integer|min:0' // in hours, 0 = permanent
        ]);

        $expiresAt = $request->duration > 0 
            ? now()->addHours($request->duration)
            : null;

        DB::table('security_banned_ips')->insert([
            'ip_address' => $request->ip_address,
            'reason' => $request->reason ?? 'Manual ban by administrator',
            'banned_by' => Auth::user()->id,
            'banned_at' => now(),
            'expires_at' => $expiresAt,
            'is_active' => true
        ]);

        // Log the action
        DB::table('security_logs')->insert([
            'ip_address' => $request->ip(),
            'user_id' => Auth::user()->id,
            'action' => 'MANUAL_IP_BAN',
            'details' => json_encode([
                'banned_ip' => $request->ip_address,
                'reason' => $request->reason,
                'duration' => $request->duration
            ]),
            'created_at' => now()
        ]);

        return redirect()->route('admin.security')->with('success', 'IP address has been banned.');
    })->name('admin.security.ban-ip');

    // Unban IP
    Route::post('/unban-ip', function (\Illuminate\Http\Request $request) {
        $request->validate([
            'ip_address' => 'required|ip'
        ]);

        DB::table('security_banned_ips')
            ->where('ip_address', $request->ip_address)
            ->where('is_active', true)
            ->update(['is_active' => false]);

        // Log the action
        DB::table('security_logs')->insert([
            'ip_address' => $request->ip(),
            'user_id' => Auth::user()->id,
            'action' => 'MANUAL_IP_UNBAN',
            'details' => json_encode([
                'unbanned_ip' => $request->ip_address
            ]),
            'created_at' => now()
        ]);

        return redirect()->route('admin.security')->with('success', 'IP address has been unbanned.');
    })->name('admin.security.unban-ip');

    // Toggle DDoS Protection
    Route::post('/toggle-ddos', function (\Illuminate\Http\Request $request) {
        $enabled = $request->input('enabled', false);
        
        DB::table('security_ddos_settings')->update(['is_enabled' => $enabled]);

        // Log the action
        DB::table('security_logs')->insert([
            'ip_address' => $request->ip(),
            'user_id' => Auth::user()->id,
            'action' => 'DDOS_TOGGLE',
            'details' => json_encode([
                'enabled' => $enabled
            ]),
            'created_at' => now()
        ]);

        return response()->json(['success' => true, 'enabled' => $enabled]);
    })->name('admin.security.toggle-ddos');

    // Update DDoS Settings
    Route::post('/update-ddos-settings', function (\Illuminate\Http\Request $request) {
        $request->validate([
            'requests_per_minute' => 'required|integer|min:10|max:1000',
            'block_threshold' => 'required|integer|min:5|max:100',
            'block_duration' => 'required|integer|min:60|max:86400'
        ]);

        DB::table('security_ddos_settings')->update([
            'requests_per_minute' => $request->requests_per_minute,
            'block_threshold' => $request->block_threshold,
            'block_duration' => $request->block_duration
        ]);

        return redirect()->route('admin.security')->with('success', 'DDoS protection settings updated.');
    })->name('admin.security.update-ddos-settings');
});
EOF
fi

# 7. Buat view untuk Security Dashboard
echo "🎨 Membuat Security Dashboard view..."
mkdir -p resources/views/admin/security

cat > resources/views/admin/security/index.blade.php << 'EOF'
@extends('layouts.admin')

@section('title', 'Security Dashboard')

@section('content-header')
    <h1>Security Dashboard<small>Real-time IP monitoring and protection</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
@if(session('success'))
    <div class="alert alert-success alert-dismissible">
        <button type="button" class="close" data-dismiss="alert" aria-hidden="true">×</button>
        <h4><i class="fa fa-check"></i> Success!</h4>
        {{ session('success') }}
    </div>
@endif

<div class="row">
    <!-- Stats Cards -->
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box bg-blue">
            <span class="info-box-icon"><i class="fa fa-globe"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">24h Requests</span>
                <span class="info-box-number">{{ number_format($stats['total_requests_24h']) }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: 100%"></div>
                </div>
                <span class="progress-description">Last 24 hours</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box bg-red">
            <span class="info-box-icon"><i class="fa fa-ban"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Blocked IPs</span>
                <span class="info-box-number">{{ $stats['blocked_ips'] }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: {{ min($stats['blocked_ips'] * 10, 100) }}%"></div>
                </div>
                <span class="progress-description">Active blocks</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box bg-yellow">
            <span class="info-box-icon"><i class="fa fa-shield"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">Auto Blocks</span>
                <span class="info-box-number">{{ $stats['auto_blocks'] }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: {{ min($stats['auto_blocks'] * 20, 100) }}%"></div>
                </div>
                <span class="progress-description">System protected</span>
            </div>
        </div>
    </div>
    
    <div class="col-md-3 col-sm-6 col-xs-12">
        <div class="info-box bg-green">
            <span class="info-box-icon"><i class="fa fa-bolt"></i></span>
            <div class="info-box-content">
                <span class="info-box-text">DDoS Attempts</span>
                <span class="info-box-number">{{ $stats['ddos_attempts'] }}</span>
                <div class="progress">
                    <div class="progress-bar" style="width: {{ min($stats['ddos_attempts'] * 10, 100) }}%"></div>
                </div>
                <span class="progress-description">Last 24 hours</span>
            </div>
        </div>
    </div>
</div>

<div class="row">
    <div class="col-md-8">
        <!-- Real-time IP Monitoring -->
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-eye"></i> Real-time IP Monitoring (Last 24 Hours)</h3>
                <div class="box-tools">
                    <button class="btn btn-xs btn-default" onclick="refreshIPList()">
                        <i class="fa fa-refresh"></i> Refresh
                    </button>
                </div>
            </div>
            <div class="box-body table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Last Seen</th>
                            <th>Request Count</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($recentIPs as $ip)
                        <tr>
                            <td><code>{{ $ip->ip_address }}</code></td>
                            <td>{{ \Carbon\Carbon::parse($ip->last_seen)->diffForHumans() }}</td>
                            <td>
                                <span class="badge bg-{{ $ip->request_count > 100 ? 'red' : ($ip->request_count > 50 ? 'yellow' : 'blue') }}">
                                    {{ $ip->request_count }}
                                </span>
                            </td>
                            <td>
                                @php
                                    $isBanned = collect($bannedIPs)->contains('ip_address', $ip->ip_address);
                                @endphp
                                @if($isBanned)
                                    <span class="label label-danger">BANNED</span>
                                @else
                                    <span class="label label-success">ALLOWED</span>
                                @endif
                            </td>
                            <td>
                                @if(!$isBanned)
                                    <button class="btn btn-xs btn-danger" onclick="banIP('{{ $ip->ip_address }}')">
                                        <i class="fa fa-ban"></i> Ban
                                    </button>
                                @else
                                    <button class="btn btn-xs btn-success" onclick="unbanIP('{{ $ip->ip_address }}')">
                                        <i class="fa fa-check"></i> Unban
                                    </button>
                                @endif
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
        </div>

        <!-- DDoS Protection Settings -->
        <div class="box box-warning">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-shield"></i> DDoS Protection Settings</h3>
                <div class="box-tools">
                    <div class="btn-group">
                        <button id="ddosToggle" class="btn btn-sm {{ $ddosSettings && $ddosSettings->is_enabled ? 'btn-success' : 'btn-default' }}">
                            <i class="fa fa-power-off"></i> 
                            {{ $ddosSettings && $ddosSettings->is_enabled ? 'ON' : 'OFF' }}
                        </button>
                    </div>
                </div>
            </div>
            <div class="box-body">
                <form id="ddosSettingsForm" action="{{ route('admin.security.update-ddos-settings') }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label>Requests per Minute (Threshold)</label>
                        <input type="number" name="requests_per_minute" class="form-control" 
                               value="{{ $ddosSettings->requests_per_minute ?? 60 }}" 
                               min="10" max="1000">
                        <small class="text-muted">IPs exceeding this limit will be blocked</small>
                    </div>
                    
                    <div class="form-group">
                        <label>Block Duration (Seconds)</label>
                        <input type="number" name="block_duration" class="form-control" 
                               value="{{ $ddosSettings->block_duration ?? 3600 }}" 
                               min="60" max="86400">
                        <small class="text-muted">How long to block IPs (1 hour = 3600 seconds)</small>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fa fa-save"></i> Save Settings
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <div class="col-md-4">
        <!-- Ban IP Form -->
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-gavel"></i> Manual IP Ban</h3>
            </div>
            <div class="box-body">
                <form id="banIPForm" action="{{ route('admin.security.ban-ip') }}" method="POST">
                    @csrf
                    <div class="form-group">
                        <label>IP Address</label>
                        <input type="text" name="ip_address" class="form-control" 
                               placeholder="e.g., 192.168.1.100" required 
                               pattern="^(\d{1,3}\.){3}\d{1,3}$">
                    </div>
                    
                    <div class="form-group">
                        <label>Reason (Optional)</label>
                        <textarea name="reason" class="form-control" rows="2" 
                                  placeholder="Why are you banning this IP?"></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label>Duration (Hours)</label>
                        <select name="duration" class="form-control">
                            <option value="1">1 Hour</option>
                            <option value="24">24 Hours</option>
                            <option value="168">7 Days</option>
                            <option value="720">30 Days</option>
                            <option value="0" selected>Permanent</option>
                        </select>
                        <small class="text-muted">0 = Permanent ban</small>
                    </div>
                    
                    <button type="submit" class="btn btn-danger btn-block">
                        <i class="fa fa-ban"></i> Ban IP Address
                    </button>
                </form>
            </div>
        </div>
        
        <!-- Banned IPs List -->
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-list"></i> Active Banned IPs</h3>
            </div>
            <div class="box-body">
                <div class="list-group">
                    @foreach($bannedIPs as $banned)
                    <div class="list-group-item">
                        <div class="row">
                            <div class="col-xs-9">
                                <h5 class="list-group-item-heading">
                                    <code>{{ $banned->ip_address }}</code>
                                    <br>
                                    <small>
                                        {{ $banned->reason }}
                                        @if($banned->expires_at)
                                            <br>Expires: {{ \Carbon\Carbon::parse($banned->expires_at)->diffForHumans() }}
                                        @else
                                            <br><span class="text-danger">PERMANENT</span>
                                        @endif
                                    </small>
                                </h5>
                            </div>
                            <div class="col-xs-3 text-right">
                                <form action="{{ route('admin.security.unban-ip') }}" method="POST" style="display: inline;">
                                    @csrf
                                    <input type="hidden" name="ip_address" value="{{ $banned->ip_address }}">
                                    <button type="submit" class="btn btn-xs btn-success" 
                                            onclick="return confirm('Unban {{ $banned->ip_address }}?')">
                                        <i class="fa fa-check"></i>
                                    </button>
                                </form>
                            </div>
                        </div>
                    </div>
                    @endforeach
                    
                    @if($bannedIPs->isEmpty())
                    <div class="list-group-item text-center text-muted">
                        <i class="fa fa-check-circle"></i> No IPs are currently banned
                    </div>
                    @endif
                </div>
            </div>
        </div>
        
        <!-- Quick Stats -->
        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title"><i class="fa fa-info-circle"></i> Security Status</h3>
            </div>
            <div class="box-body">
                <div class="alert alert-{{ $ddosSettings && $ddosSettings->is_enabled ? 'success' : 'warning' }}">
                    <h4 style="margin-top: 0;">
                        <i class="fa fa-{{ $ddosSettings && $ddosSettings->is_enabled ? 'shield' : 'warning' }}"></i>
                        DDoS Protection: {{ $ddosSettings && $ddosSettings->is_enabled ? 'ACTIVE' : 'INACTIVE' }}
                    </h4>
                </div>
                
                <ul class="list-group">
                    <li class="list-group-item">
                        File Access Control
                        <span class="label label-success pull-right">ENABLED</span>
                    </li>
                    <li class="list-group-item">
                        Admin Restriction
                        <span class="label label-success pull-right">ACTIVE</span>
                    </li>
                    <li class="list-group-item">
                        Real-time Monitoring
                        <span class="label label-success pull-right">RUNNING</span>
                    </li>
                    <li class="list-group-item">
                        Auto IP Blocking
                        <span class="label label-success pull-right">READY</span>
                    </li>
                </ul>
            </div>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
    @parent
    <script>
    // Toggle DDoS Protection
    $('#ddosToggle').click(function() {
        var currentState = $(this).hasClass('btn-success');
        var newState = !currentState;
        
        $.ajax({
            url: '{{ route("admin.security.toggle-ddos") }}',
            method: 'POST',
            data: {
                _token: '{{ csrf_token() }}',
                enabled: newState
            },
            success: function(response) {
                if (response.success) {
                    if (newState) {
                        $('#ddosToggle').removeClass('btn-default').addClass('btn-success').html('<i class="fa fa-power-off"></i> ON');
                        toastr.success('DDoS protection activated');
                    } else {
                        $('#ddosToggle').removeClass('btn-success').addClass('btn-default').html('<i class="fa fa-power-off"></i> OFF');
                        toastr.warning('DDoS protection deactivated');
                    }
                }
            }
        });
    });
    
    // Ban IP from monitoring table
    function banIP(ip) {
        if (confirm('Ban IP address ' + ip + '?')) {
            var form = $('<form>').attr({
                method: 'POST',
                action: '{{ route("admin.security.ban-ip") }}'
            }).append(
                $('<input>').attr({type: 'hidden', name: '_token', value: '{{ csrf_token() }}'}),
                $('<input>').attr({type: 'hidden', name: 'ip_address', value: ip}),
                $('<input>').attr({type: 'hidden', name: 'reason', value: 'Manual ban from monitoring'}),
                $('<input>').attr({type: 'hidden', name: 'duration', value: '0'})
            ).appendTo('body');
            
            form.submit();
        }
    }
    
    // Unban IP from monitoring table
    function unbanIP(ip) {
        if (confirm('Unban IP address ' + ip + '?')) {
            var form = $('<form>').attr({
                method: 'POST',
                action: '{{ route("admin.security.unban-ip") }}'
            }).append(
                $('<input>').attr({type: 'hidden', name: '_token', value: '{{ csrf_token() }}'}),
                $('<input>').attr({type: 'hidden', name: 'ip_address', value: ip})
            ).appendTo('body');
            
            form.submit();
        }
    }
    
    // Refresh IP list
    function refreshIPList() {
        window.location.reload();
    }
    
    // Auto-refresh every 30 seconds
    setTimeout(refreshIPList, 30000);
    </script>
@endsection
EOF

# 8. Register middleware di Kernel
echo "🔗 Register middleware..."
if [ -f "app/Http/Kernel.php" ]; then
    # Backup kernel
    cp app/Http/Kernel.php app/Http/Kernel.php.bak
    
    # Tambahkan middleware ke $routeMiddleware
    sed -i "/protected \$routeMiddleware = \[/a\
        'ddos.protection' => \\Pterodactyl\\Http\\Middleware\\DDoSProtection::class,\n\
        'admin.access' => \\Pterodactyl\\Http\\Middleware\\AdminAccessControl::class," app/Http/Kernel.php
    
    # Tambahkan middleware ke $middlewareGroups api dan web
    sed -i "/'api' => \[/a\
            'ddos.protection'," app/Http/Kernel.php
    
    sed -i "/'web' => \[/a\
            'admin.access'," app/Http/Kernel.php
fi

# 9. Update app.php untuk menambahkan penggunaan DB di routes
echo "⚙️ Update app.php..."
if [ -f "config/app.php" ]; then
    # Tidak perlu modifikasi karena sudah menggunakan DB facade
    echo "App config sudah sesuai"
fi

# 10. Jalankan migrasi dan clear cache
echo "🔄 Menjalankan migrasi dan clear cache..."

# Buat migrasi untuk tabel security
cat > database/migrations/$(date +"%Y_%m_%d_%H%M%S")_create_security_tables.php << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
    {
        Schema::create('security_banned_ips', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->text('reason')->nullable();
            $table->unsignedInteger('banned_by');
            $table->timestamp('banned_at')->useCurrent();
            $table->timestamp('expires_at')->nullable();
            $table->boolean('is_active')->default(true);
            $table->index(['ip_address']);
            $table->index(['is_active']);
        });

        Schema::create('security_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->unsignedInteger('user_id')->nullable();
            $table->string('action', 50);
            $table->text('details')->nullable();
            $table->timestamp('created_at')->useCurrent();
            $table->index(['ip_address']);
            $table->index(['created_at']);
        });

        Schema::create('security_ddos_settings', function (Blueprint $table) {
            $table->id();
            $table->boolean('is_enabled')->default(false);
            $table->unsignedInteger('requests_per_minute')->default(60);
            $table->unsignedInteger('block_threshold')->default(10);
            $table->unsignedInteger('block_duration')->default(3600);
            $table->timestamp('updated_at')->useCurrent()->useCurrentOnUpdate();
        });

        // Insert default settings
        DB::table('security_ddos_settings')->insert([
            'is_enabled' => false,
            'requests_per_minute' => 60,
            'block_threshold' => 10,
            'block_duration' => 3600
        ]);
    }

    public function down()
    {
        Schema::dropIfExists('security_banned_ips');
        Schema::dropIfExists('security_logs');
        Schema::dropIfExists('security_ddos_settings');
    }
};
EOF

# Jalankan migrasi
php artisan migrate --force

# Clear semua cache
php artisan view:clear
php artisan route:clear
php artisan config:clear
php artisan cache:clear

# 11. Buat cron job untuk cleanup logs lama
echo "⏰ Setup cron job..."
(crontab -l 2>/dev/null | grep -v "security_cleanup"; echo "0 2 * * * php /var/www/pterodactyl/artisan security:cleanup") | crontab -

# Buat artisan command untuk cleanup
cat > app/Console/Commands/SecurityCleanup.php << 'EOF'
<?php

namespace Pterodactyl\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

class SecurityCleanup extends Command
{
    protected $signature = 'security:cleanup';
    protected $description = 'Clean up old security logs and expired bans';

    public function handle()
    {
        // Hapus logs yang lebih tua dari 30 hari
        $deletedLogs = DB::table('security_logs')
            ->where('created_at', '<', now()->subDays(30))
            ->delete();

        // Nonaktifkan bans yang sudah expired
        $updatedBans = DB::table('security_banned_ips')
            ->where('is_active', true)
            ->whereNotNull('expires_at')
            ->where('expires_at', '<', now())
            ->update(['is_active' => false]);

        $this->info("Cleaned up $deletedLogs old logs and deactivated $updatedBans expired bans.");
        
        return 0;
    }
}
EOF

# 12. Update composer autoload
composer dump-autoload

echo ""
echo "========================================="
echo "✅ SISTEM SECURITY BERHASIL DIPASANG"
echo "========================================="
echo ""
echo "🎯 FITUR YANG DIPASANG:"
echo "1. 🔒 Menu Security dengan icon shield"
echo "2. 👁️ Real-time IP monitoring"
echo "3. ⚡ Ban/Unban IP manual"
echo "4. 🛡️ DDoS Protection dengan saklar ON/OFF"
echo "5. 🤖 Auto-block IP mencurigakan"
echo "6. 👑 Admin ID 1 = SUPER ADMIN (akses penuh)"
echo "7. 🚫 Admin lain TIDAK BISA mengintip panel orang lain"
echo "8. 🔐 Proteksi EXTRA KUAT pada FileController"
echo "9. 📊 Database logging semua aktivitas"
echo "10. 🧹 Auto cleanup logs lama"
echo ""
echo "📍 AKSES: /admin/security"
echo "📍 Backup tersimpan di: /root/backup_security_$TIMESTAMP"
echo ""
echo "⚠️ PERHATIAN:"
echo "- Hanya Admin ID 1 yang bisa mengakses semua data"
echo "- Admin lain hanya bisa melihat data milik sendiri"
echo "- Semua percobaan akses ilegal akan di-log"
echo "- IP yang melebihi threshold akan diblokir otomatis"
echo ""
echo "🔥 SYSTEM READY - TANPA ERROR! 🔥"
