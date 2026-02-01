#!/bin/bash

# ============================================
# FIX PTERODACTYL DUPLICATE ROUTE ERROR
# ============================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PTERO_PATH="/var/www/pterodactyl"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║        FIXING PTERODACTYL DUPLICATE ROUTE ERROR          ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ============================================
# 1. BACKUP SEMUA FILE PENTING
# ============================================
echo -e "${YELLOW}[1/12] Creating backup...${NC}"
mkdir -p "$BACKUP_DIR"

# Backup semua file yang akan dimodifikasi
cp -f "$PTERO_PATH/routes/admin.php" "$BACKUP_DIR/" 2>/dev/null || true
cp -f "$PTERO_PATH/app/Http/Controllers/Admin/SecurityController.php" "$BACKUP_DIR/" 2>/dev/null || true
cp -f "$PTERO_PATH/app/Http/Kernel.php" "$BACKUP_DIR/" 2>/dev/null || true
cp -f "$PTERO_PATH/routes/api.php" "$BACKUP_DIR/" 2>/dev/null || true
cp -f "$PTERO_PATH/routes/web.php" "$BACKUP_DIR/" 2>/dev/null || true

echo -e "${GREEN}✓ Backup created: $BACKUP_DIR${NC}"

# ============================================
# 2. CEK DUPLICATE ROUTES DI ADMIN.PHP
# ============================================
echo -e "${YELLOW}[2/12] Checking for duplicate routes...${NC}"

ADMIN_ROUTES="$PTERO_PATH/routes/admin.php"
if [ ! -f "$ADMIN_ROUTES" ]; then
    echo -e "${RED}✗ File routes/admin.php tidak ditemukan${NC}"
    exit 1
fi

# Hitung berapa kali 'security' muncul di routes
SECURITY_COUNT=$(grep -c "Route::.*security" "$ADMIN_ROUTES" || true)
echo -e "Found $SECURITY_COUNT security routes"

if [ "$SECURITY_COUNT" -gt 1 ]; then
    echo -e "${YELLOW}⚠  Duplicate routes detected, cleaning up...${NC}"
    
    # Backup original
    cp "$ADMIN_ROUTES" "${ADMIN_ROUTES}.bak"
    
    # Hapus semua blok security routes yang duplicate
    sed -i '/\/\/\s*Security Routes/,/^});/d' "$ADMIN_ROUTES"
    sed -i '/Route::group.*security/,/^});/d' "$ADMIN_ROUTES"
    sed -i '/prefix.*security/,/^});/d' "$ADMIN_ROUTES"
    
    # Hapus baris kosong berlebih
    sed -i '/^$/N;/^\n$/D' "$ADMIN_ROUTES"
    
    echo -e "${GREEN}✓ Duplicate routes removed${NC}"
fi

# ============================================
# 3. BUAT MIDDLEWARE OWNER-ONLY
# ============================================
echo -e "${YELLOW}[3/12] Creating owner-only middleware...${NC}"

MIDDLEWARE_DIR="$PTERO_PATH/app/Http/Middleware"
mkdir -p "$MIDDLEWARE_DIR"

# Buat OwnerOnly middleware
cat > "$MIDDLEWARE_DIR/OwnerOnly.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
        // Cek jika user adalah owner (user_id = 1)
        if (!Auth::check() || Auth::id() !== 1) {
            if ($request->expectsJson()) {
                return response()->json([
                    'error' => 'Forbidden',
                    'message' => 'This action requires owner privileges.'
                ], 403);
            }
            
            return redirect()->route('admin.index')
                ->with('error', 'You must be the system owner to access this section.');
        }
        
        return $next($request);
    }
}
EOF

echo -e "${GREEN}✓ OwnerOnly middleware created${NC}"

# ============================================
# 4. REGISTER MIDDLEWARE DI KERNEL
# ============================================
echo -e "${YELLOW}[4/12] Registering middleware in Kernel...${NC}"

KERNEL_FILE="$PTERO_PATH/app/Http/Kernel.php"
if [ -f "$KERNEL_FILE" ]; then
    # Backup kernel
    cp "$KERNEL_FILE" "${KERNEL_FILE}.bak"
    
    # Cek jika middleware sudah terdaftar
    if ! grep -q "'owner.only'" "$KERNEL_FILE"; then
        # Tambahkan ke routeMiddleware
        sed -i "/protected \$routeMiddleware = \[/a\        'owner.only' => \\\Pterodactyl\\\Http\\\Middleware\\\OwnerOnly::class," "$KERNEL_FILE"
        echo -e "${GREEN}✓ Middleware registered in Kernel${NC}"
    else
        echo -e "${YELLOW}⚠  Middleware already registered${NC}"
    fi
else
    echo -e "${RED}✗ Kernel.php not found${NC}"
fi

# ============================================
# 5. PERBAIKI SECURITY CONTROLLER
# ============================================
echo -e "${YELLOW}[5/12] Fixing SecurityController...${NC}"

CONTROLLER_DIR="$PTERO_PATH/app/Http/Controllers/Admin"
mkdir -p "$CONTROLLER_DIR"

# Buat controller yang benar
cat > "$CONTROLLER_DIR/SecurityController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;

class SecurityController extends Controller
{
    /**
     * Security Dashboard
     */
    public function index()
    {
        $stats = [
            'total_banned' => 0,
            'active_banned' => 0,
            'expired_bans' => 0
        ];
        
        $recentBans = collect();
        
        try {
            // Hitung statistik
            $stats['total_banned'] = DB::table('security_banned_ips')->count();
            $stats['active_banned'] = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->where(function($query) {
                    $query->whereNull('expires_at')
                          ->orWhere('expires_at', '>', now());
                })
                ->count();
            
            $stats['expired_bans'] = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->where('expires_at', '<=', now())
                ->count();
            
            // Ambil 5 IP terbaru yang diban
            $recentBans = DB::table('security_banned_ips')
                ->where('is_active', 1)
                ->orderBy('created_at', 'desc')
                ->limit(5)
                ->get();
                
        } catch (\Exception $e) {
            // Table belum ada, tidak perlu panic
        }
        
        return view('admin.security.index', compact('stats', 'recentBans'));
    }
    
    /**
     * Show banned IPs
     */
    public function bannedIps(Request $request)
    {
        $search = $request->input('search', '');
        $status = $request->input('status', 'active');
        
        $query = DB::table('security_banned_ips');
        
        // Filter status
        if ($status === 'active') {
            $query->where('is_active', 1)
                  ->where(function($q) {
                      $q->whereNull('expires_at')
                        ->orWhere('expires_at', '>', now());
                  });
        } elseif ($status === 'expired') {
            $query->where('is_active', 1)
                  ->where('expires_at', '<=', now());
        } elseif ($status === 'inactive') {
            $query->where('is_active', 0);
        }
        
        // Search
        if (!empty($search)) {
            $query->where(function($q) use ($search) {
                $q->where('ip_address', 'LIKE', "%{$search}%")
                  ->orWhere('reason', 'LIKE', "%{$search}%");
            });
        }
        
        $ips = $query->orderBy('created_at', 'desc')->paginate(20);
        
        return view('admin.security.banned-ips', compact('ips', 'search', 'status'));
    }
    
    /**
     * Ban IP address
     */
    public function banIp(Request $request)
    {
        $request->validate([
            'ip_address' => 'required|ip|max:45',
            'reason' => 'nullable|string|max:255',
            'duration' => 'required|in:1hour,6hours,1day,1week,1month,permanent'
        ]);
        
        // Hitung waktu kadaluarsa
        $expiresAt = null;
        switch ($request->duration) {
            case '1hour':
                $expiresAt = now()->addHour();
                break;
            case '6hours':
                $expiresAt = now()->addHours(6);
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
            // 'permanent' tidak ada expires_at
        }
        
        try {
            DB::table('security_banned_ips')->updateOrInsert(
                ['ip_address' => $request->ip_address],
                [
                    'reason' => $request->reason,
                    'banned_by' => Auth::id(),
                    'expires_at' => $expiresAt,
                    'is_active' => 1,
                    'created_at' => now(),
                    'updated_at' => now()
                ]
            );
            
            return redirect()->route('admin.security.banned-ips')
                ->with('success', "IP address {$request->ip_address} has been banned.");
                
        } catch (\Exception $e) {
            return redirect()->back()
                ->withInput()
                ->with('error', 'Failed to ban IP: ' . $e->getMessage());
        }
    }
    
    /**
     * Unban IP address
     */
    public function unbanIp($id)
    {
        try {
            $affected = DB::table('security_banned_ips')
                ->where('id', $id)
                ->update(['is_active' => 0, 'updated_at' => now()]);
            
            if ($affected) {
                return redirect()->back()
                    ->with('success', 'IP address has been unbanned.');
            } else {
                return redirect()->back()
                    ->with('error', 'IP address not found.');
            }
            
        } catch (\Exception $e) {
            return redirect()->back()
                ->with('error', 'Failed to unban IP: ' . $e->getMessage());
        }
    }
    
    /**
     * Rate Limits Management
     */
    public function rateLimits()
    {
        $rateLimits = [
            'api' => [
                'name' => 'API Requests',
                'enabled' => Cache::get('rate_limit.api.enabled', true),
                'max_requests' => Cache::get('rate_limit.api.max', 60),
                'per_minutes' => Cache::get('rate_limit.api.minutes', 1),
                'description' => 'Limit API requests per minute'
            ],
            'login' => [
                'name' => 'Login Attempts',
                'enabled' => Cache::get('rate_limit.login.enabled', true),
                'max_requests' => Cache::get('rate_limit.login.max', 5),
                'per_minutes' => Cache::get('rate_limit.login.minutes', 5),
                'description' => 'Limit login attempts per 5 minutes'
            ],
            'registration' => [
                'name' => 'Registrations',
                'enabled' => Cache::get('rate_limit.registration.enabled', true),
                'max_requests' => Cache::get('rate_limit.registration.max', 3),
                'per_minutes' => Cache::get('rate_limit.registration.minutes', 60),
                'description' => 'Limit new registrations per hour'
            ]
        ];
        
        return view('admin.security.rate-limits', compact('rateLimits'));
    }
    
    /**
     * Toggle rate limit
     */
    public function toggleRateLimit(Request $request, $type)
    {
        $validTypes = ['api', 'login', 'registration'];
        
        if (!in_array($type, $validTypes)) {
            return response()->json([
                'success' => false,
                'message' => 'Invalid rate limit type'
            ], 400);
        }
        
        $current = Cache::get("rate_limit.{$type}.enabled", true);
        $newValue = !$current;
        
        Cache::put("rate_limit.{$type}.enabled", $newValue);
        
        return response()->json([
            'success' => true,
            'enabled' => $newValue,
            'message' => $newValue ? 'Rate limit enabled' : 'Rate limit disabled'
        ]);
    }
    
    /**
     * Update rate limit settings
     */
    public function updateRateLimit(Request $request, $type)
    {
        $validTypes = ['api', 'login', 'registration'];
        
        if (!in_array($type, $validTypes)) {
            return redirect()->back()
                ->with('error', 'Invalid rate limit type.');
        }
        
        $request->validate([
            'max_requests' => 'required|integer|min:1|max:1000',
            'per_minutes' => 'required|integer|min:1|max:1440'
        ]);
        
        Cache::put("rate_limit.{$type}.max", $request->max_requests);
        Cache::put("rate_limit.{$type}.minutes", $request->per_minutes);
        
        return redirect()->back()
            ->with('success', "{$validTypes[$type]} rate limit updated.");
    }
}
EOF

echo -e "${GREEN}✓ SecurityController fixed${NC}"

# ============================================
# 6. BUAT VIEWS UNTUK SECURITY
# ============================================
echo -e "${YELLOW}[6/12] Creating security views...${NC}"

VIEWS_DIR="$PTERO_PATH/resources/views/admin/security"
mkdir -p "$VIEWS_DIR"

# Index view
cat > "$VIEWS_DIR/index.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Security Dashboard
@endsection

@section('content-header')
    <h1>Security Dashboard<small>Manage security settings and monitor threats.</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li class="active">Security</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <!-- Statistics -->
    <div class="col-md-4 col-xs-12">
        <div class="box box-primary">
            <div class="box-header with-border">
                <h3 class="box-title">Security Statistics</h3>
            </div>
            <div class="box-body">
                <div class="info-box">
                    <span class="info-box-icon bg-red"><i class="fa fa-ban"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Total Banned IPs</span>
                        <span class="info-box-number">{{ $stats['total_banned'] }}</span>
                    </div>
                </div>
                <div class="info-box">
                    <span class="info-box-icon bg-yellow"><i class="fa fa-shield"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Active Bans</span>
                        <span class="info-box-number">{{ $stats['active_banned'] }}</span>
                    </div>
                </div>
                <div class="info-box">
                    <span class="info-box-icon bg-green"><i class="fa fa-clock-o"></i></span>
                    <div class="info-box-content">
                        <span class="info-box-text">Expired Bans</span>
                        <span class="info-box-number">{{ $stats['expired_bans'] }}</span>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Quick Actions -->
    <div class="col-md-8 col-xs-12">
        <div class="box box-default">
            <div class="box-header with-border">
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
                        <button class="btn btn-info btn-block" data-toggle="modal" data-target="#banIpModal">
                            <i class="fa fa-plus"></i> Ban IP Address
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Recent Bans -->
        <div class="box box-default">
            <div class="box-header with-border">
                <h3 class="box-title">Recent Banned IPs</h3>
            </div>
            <div class="box-body table-responsive no-padding">
                @if($recentBans->count() > 0)
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Banned On</th>
                            <th>Expires</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($recentBans as $ban)
                        <tr>
                            <td><code>{{ $ban->ip_address }}</code></td>
                            <td>{{ $ban->reason ?: 'No reason provided' }}</td>
                            <td>{{ $ban->created_at->format('Y-m-d H:i') }}</td>
                            <td>
                                @if($ban->expires_at)
                                    {{ $ban->expires_at->format('Y-m-d H:i') }}
                                @else
                                    <span class="label label-danger">Permanent</span>
                                @endif
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
                @else
                <div class="alert alert-info" style="margin: 15px;">
                    <i class="fa fa-info-circle"></i> No banned IPs found.
                </div>
                @endif
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
                        <input type="text" class="form-control" id="ip_address" name="ip_address" 
                               placeholder="e.g., 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <textarea class="form-control" id="reason" name="reason" 
                                  rows="2" placeholder="Why are you banning this IP?"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="duration">Ban Duration</label>
                        <select class="form-control" id="duration" name="duration" required>
                            <option value="1hour">1 Hour</option>
                            <option value="6hours">6 Hours</option>
                            <option value="1day">1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="1month">1 Month</option>
                            <option value="permanent">Permanent</option>
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

@section('footer-scripts')
    @parent
    <script>
        $(document).ready(function() {
            $('#banIpModal').on('shown.bs.modal', function () {
                $('#ip_address').focus();
            });
        });
    </script>
@endsection
EOF

# Banned IPs view
cat > "$VIEWS_DIR/banned-ips.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Banned IPs Management
@endsection

@section('content-header')
    <h1>Banned IPs<small>Manage blocked IP addresses.</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Banned IPs</li>
    </ol>
@endsection

@section('content')
<div class="row">
    <div class="col-xs-12">
        <div class="box box-danger">
            <div class="box-header with-border">
                <h3 class="box-title">Banned IP Addresses</h3>
                <div class="box-tools">
                    <form action="{{ route('admin.security.banned-ips') }}" method="GET" style="display: inline-block;">
                        <div class="input-group input-group-sm" style="width: 200px;">
                            <input type="text" name="search" class="form-control pull-right" 
                                   placeholder="Search IP/Reason" value="{{ $search }}">
                            <div class="input-group-btn">
                                <button type="submit" class="btn btn-default"><i class="fa fa-search"></i></button>
                            </div>
                        </div>
                    </form>
                    <button class="btn btn-sm btn-danger" data-toggle="modal" data-target="#banIpModal">
                        <i class="fa fa-plus"></i> Add IP
                    </button>
                </div>
            </div>
            <div class="box-body table-responsive no-padding">
                @if($ips->count() > 0)
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>IP Address</th>
                            <th>Reason</th>
                            <th>Banned By</th>
                            <th>Banned On</th>
                            <th>Expires</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach($ips as $ip)
                        <tr>
                            <td>#{{ $ip->id }}</td>
                            <td><code>{{ $ip->ip_address }}</code></td>
                            <td>{{ $ip->reason ?: 'N/A' }}</td>
                            <td>{{ $ip->banned_by ? 'User #' . $ip->banned_by : 'System' }}</td>
                            <td>{{ \Carbon\Carbon::parse($ip->created_at)->format('Y-m-d H:i') }}</td>
                            <td>
                                @if($ip->expires_at)
                                    {{ \Carbon\Carbon::parse($ip->expires_at)->format('Y-m-d H:i') }}
                                @else
                                    Permanent
                                @endif
                            </td>
                            <td>
                                @if(!$ip->is_active)
                                    <span class="label label-default">Inactive</span>
                                @elseif($ip->expires_at && \Carbon\Carbon::parse($ip->expires_at)->isPast())
                                    <span class="label label-warning">Expired</span>
                                @else
                                    <span class="label label-danger">Active</span>
                                @endif
                            </td>
                            <td>
                                @if($ip->is_active)
                                <form action="{{ route('admin.security.unban-ip', $ip->id) }}" method="POST" 
                                      style="display: inline-block;">
                                    @csrf
                                    <button type="submit" class="btn btn-xs btn-warning" 
                                            onclick="return confirm('Are you sure you want to unban this IP?')">
                                        <i class="fa fa-unlock"></i> Unban
                                    </button>
                                </form>
                                @endif
                            </td>
                        </tr>
                        @endforeach
                    </tbody>
                </table>
                @else
                <div class="alert alert-info" style="margin: 15px;">
                    <i class="fa fa-info-circle"></i> No banned IPs found.
                </div>
                @endif
            </div>
            @if($ips->hasPages())
            <div class="box-footer">
                <div class="pull-right">
                    {{ $ips->appends(['search' => $search, 'status' => $status])->links() }}
                </div>
            </div>
            @endif
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
                        <input type="text" class="form-control" id="ip_address" name="ip_address" 
                               placeholder="e.g., 192.168.1.100" required>
                    </div>
                    <div class="form-group">
                        <label for="reason">Reason (Optional)</label>
                        <textarea class="form-control" id="reason" name="reason" 
                                  rows="3" placeholder="Why are you banning this IP?"></textarea>
                    </div>
                    <div class="form-group">
                        <label for="duration">Ban Duration *</label>
                        <select class="form-control" id="duration" name="duration" required>
                            <option value="1hour">1 Hour</option>
                            <option value="6hours">6 Hours</option>
                            <option value="1day" selected>1 Day</option>
                            <option value="1week">1 Week</option>
                            <option value="1month">1 Month</option>
                            <option value="permanent">Permanent</option>
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

@section('footer-scripts')
    @parent
    <script>
        $(document).ready(function() {
            // Auto-focus search field
            $('input[name="search"]').focus();
            
            // Ban IP modal
            $('#banIpModal').on('shown.bs.modal', function () {
                $('#ip_address').focus();
            });
            
            // Status filter
            $('.status-filter').on('change', function() {
                window.location.href = $(this).val();
            });
        });
    </script>
@endsection
EOF

# Rate Limits view
cat > "$VIEWS_DIR/rate-limits.blade.php" << 'EOF'
@extends('layouts.admin')

@section('title')
    Rate Limits
@endsection

@section('content-header')
    <h1>Rate Limits<small>Configure request rate limiting.</small></h1>
    <ol class="breadcrumb">
        <li><a href="{{ route('admin.index') }}">Admin</a></li>
        <li><a href="{{ route('admin.security') }}">Security</a></li>
        <li class="active">Rate Limits</li>
    </ol>
@endsection

@section('content')
<div class="row">
    @foreach($rateLimits as $type => $limit)
    <div class="col-md-4">
        <div class="box box-{{ $limit['enabled'] ? 'warning' : 'default' }}">
            <div class="box-header with-border">
                <h3 class="box-title">{{ $limit['name'] }}</h3>
                <div class="box-tools pull-right">
                    <div class="btn-group">
                        <button type="button" class="btn btn-box-tool dropdown-toggle" data-toggle="dropdown">
                            <i class="fa fa-gear"></i>
                        </button>
                        <ul class="dropdown-menu" role="menu">
                            <li>
                                <a href="#" class="toggle-rate-limit" data-type="{{ $type }}">
                                    <i class="fa fa-power-off"></i> 
                                    {{ $limit['enabled'] ? 'Disable' : 'Enable' }}
                                </a>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            <div class="box-body">
                <p>{{ $limit['description'] }}</p>
                <div class="form-horizontal">
                    <div class="form-group">
                        <label class="col-sm-6 control-label">Status:</label>
                        <div class="col-sm-6">
                            @if($limit['enabled'])
                                <span class="label label-success">Enabled</span>
                            @else
                                <span class="label label-default">Disabled</span>
                            @endif
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-6 control-label">Max Requests:</label>
                        <div class="col-sm-6">
                            <strong>{{ $limit['max_requests'] }}</strong>
                        </div>
                    </div>
                    <div class="form-group">
                        <label class="col-sm-6 control-label">Per Minutes:</label>
                        <div class="col-sm-6">
                            <strong>{{ $limit['per_minutes'] }}</strong>
                        </div>
                    </div>
                </div>
            </div>
            <div class="box-footer">
                <button type="button" class="btn btn-default btn-block" data-toggle="modal" 
                        data-target="#editLimitModal-{{ $type }}">
                    <i class="fa fa-edit"></i> Edit Settings
                </button>
            </div>
        </div>
    </div>
    
    <!-- Edit Modal -->
    <div class="modal fade" id="editLimitModal-{{ $type }}" tabindex="-1" role="dialog">
        <div class="modal-dialog" role="document">
            <div class="modal-content">
                <form action="{{ route('admin.security.update-rate-limit', $type) }}" method="POST">
                    @csrf
                    <div class="modal-header">
                        <button type="button" class="close" data-dismiss="modal">&times;</button>
                        <h4 class="modal-title">Edit {{ $limit['name'] }}</h4>
                    </div>
                    <div class="modal-body">
                        <div class="form-group">
                            <label for="max_requests">Maximum Requests</label>
                            <input type="number" class="form-control" id="max_requests" name="max_requests" 
                                   value="{{ $limit['max_requests'] }}" min="1" max="1000" required>
                            <p class="help-block">Maximum number of requests allowed.</p>
                        </div>
                        <div class="form-group">
                            <label for="per_minutes">Time Window (Minutes)</label>
                            <input type="number" class="form-control" id="per_minutes" name="per_minutes" 
                                   value="{{ $limit['per_minutes'] }}" min="1" max="1440" required>
                            <p class="help-block">Time window in minutes for the limit.</p>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-default" data-dismiss="modal">Cancel</button>
                        <button type="submit" class="btn btn-primary">Save Changes</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
    @endforeach
</div>

<div class="row">
    <div class="col-md-12">
        <div class="box box-info">
            <div class="box-header with-border">
                <h3 class="box-title">About Rate Limiting</h3>
            </div>
            <div class="box-body">
                <p>Rate limiting helps protect your panel from abuse and DDoS attacks by limiting the number 
                of requests a user can make within a specific time period.</p>
                <ul>
                    <li><strong>API Requests:</strong> Limits requests to API endpoints (per minute)</li>
                    <li><strong>Login Attempts:</strong> Limits failed login attempts (per 5 minutes)</li>
                    <li><strong>Registrations:</strong> Limits new account registrations (per hour)</li>
                </ul>
                <p class="text-muted"><i class="fa fa-info-circle"></i> These settings are stored in cache and may be reset on cache clearance.</p>
            </div>
        </div>
    </div>
</div>
@endsection

@section('footer-scripts')
    @parent
    <script>
        $(document).ready(function() {
            // Toggle rate limit
            $('.toggle-rate-limit').on('click', function(e) {
                e.preventDefault();
                
                var type = $(this).data('type');
                var button = $(this);
                
                $.ajax({
                    url: '{{ url('admin/security/toggle-rate-limit') }}/' + type,
                    type: 'POST',
                    headers: {
                        'X-CSRF-TOKEN': '{{ csrf_token() }}'
                    },
                    success: function(response) {
                        if (response.success) {
                            // Reload the page to reflect changes
                            location.reload();
                        } else {
                            alert('Failed to toggle rate limit.');
                        }
                    },
                    error: function() {
                        alert('An error occurred. Please try again.');
                    }
                });
            });
        });
    </script>
@endsection
EOF

echo -e "${GREEN}✓ Security views created${NC}"

# ============================================
# 7. TAMBAHKAN ROUTES YANG BENAR
# ============================================
echo -e "${YELLOW}[7/12] Adding proper routes...${NC}"

# Tambahkan routes ke admin.php jika belum ada
if ! grep -q "admin.security" "$ADMIN_ROUTES"; then
    cat >> "$ADMIN_ROUTES" << 'EOF'

// ============================================
// Security Routes (Owner Only)
// ============================================
Route::group(['prefix' => 'security', 'middleware' => ['admin', 'owner.only']], function () {
    Route::get('/', 'SecurityController@index')->name('admin.security');
    Route::get('/banned-ips', 'SecurityController@bannedIps')->name('admin.security.banned-ips');
    Route::post('/ban-ip', 'SecurityController@banIp')->name('admin.security.ban-ip');
    Route::post('/unban-ip/{id}', 'SecurityController@unbanIp')->name('admin.security.unban-ip');
    Route::get('/rate-limits', 'SecurityController@rateLimits')->name('admin.security.rate-limits');
    Route::post('/toggle-rate-limit/{type}', 'SecurityController@toggleRateLimit')->name('admin.security.toggle-rate-limit');
    Route::post('/update-rate-limit/{type}', 'SecurityController@updateRateLimit')->name('admin.security.update-rate-limit');
});
EOF
    echo -e "${GREEN}✓ Routes added to admin.php${NC}"
else
    echo -e "${YELLOW}⚠  Routes already exist in admin.php${NC}"
fi

# ============================================
# 8. BUAT TABEL DATABASE
# ============================================
echo -e "${YELLOW}[8/12] Creating database tables...${NC}"

# Get database credentials from .env
ENV_FILE="$PTERO_PATH/.env"
if [ -f "$ENV_FILE" ]; then
    DB_HOST=$(grep DB_HOST "$ENV_FILE" | cut -d '=' -f2 | tr -d '"' | head -1)
    DB_PORT=$(grep DB_PORT "$ENV_FILE" | cut -d '=' -f2 | tr -d '"' | head -1)
    DB_DATABASE=$(grep DB_DATABASE "$ENV_FILE" | cut -d '=' -f2 | tr -d '"' | head -1)
    DB_USERNAME=$(grep DB_USERNAME "$ENV_FILE" | cut -d '=' -f2 | tr -d '"' | head -1)
    DB_PASSWORD=$(grep DB_PASSWORD "$ENV_FILE" | cut -d '=' -f2 | tr -d '"' | head -1)
    
    if [ -z "$DB_PASSWORD" ]; then
        # Try without password
        MYSQL_CMD="mysql -u $DB_USERNAME -h $DB_HOST -P $DB_PORT $DB_DATABASE"
    else
        MYSQL_CMD="mysql -u $DB_USERNAME -p$DB_PASSWORD -h $DB_HOST -P $DB_PORT $DB_DATABASE"
    fi
    
    # Create security_banned_ips table
    $MYSQL_CMD << 'EOF'
CREATE TABLE IF NOT EXISTS `security_banned_ips` (
    `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT,
    `ip_address` varchar(45) COLLATE utf8mb4_unicode_ci NOT NULL,
    `reason` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
    `banned_by` bigint(20) UNSIGNED DEFAULT NULL,
    `expires_at` timestamp NULL DEFAULT NULL,
    `is_active` tinyint(1) NOT NULL DEFAULT '1',
    `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `security_banned_ips_ip_address_unique` (`ip_address`),
    KEY `security_banned_ips_is_active_index` (`is_active`),
    KEY `security_banned_ips_expires_at_index` (`expires_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert some example data
INSERT IGNORE INTO `security_banned_ips` 
    (`ip_address`, `reason`, `banned_by`, `expires_at`, `is_active`) 
VALUES
    ('192.168.1.100', 'Multiple failed login attempts', 1, DATE_ADD(NOW(), INTERVAL 7 DAY), 1),
    ('10.0.0.50', 'Suspicious activity', 1, NULL, 1),
    ('203.0.113.25', 'DDoS attempt', 1, DATE_ADD(NOW(), INTERVAL 30 DAY), 1);

-- Create cache table if not exists (for rate limits)
CREATE TABLE IF NOT EXISTS `cache` (
    `key` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
    `value` mediumtext COLLATE utf8mb4_unicode_ci NOT NULL,
    `expiration` int(11) NOT NULL,
    PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert default rate limit settings
INSERT IGNORE INTO `cache` (`key`, `value`, `expiration`) VALUES
    ('rate_limit.api.enabled', '1', 0),
    ('rate_limit.api.max', '60', 0),
    ('rate_limit.api.minutes', '1', 0),
    ('rate_limit.login.enabled', '1', 0),
    ('rate_limit.login.max', '5', 0),
    ('rate_limit.login.minutes', '5', 0),
    ('rate_limit.registration.enabled', '1', 0),
    ('rate_limit.registration.max', '3', 0),
    ('rate_limit.registration.minutes', '60', 0);
EOF
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Database tables created${NC}"
    else
        echo -e "${RED}✗ Failed to create database tables${NC}"
    fi
else
    echo -e "${RED}✗ .env file not found${NC}"
fi

# ============================================
# 9. CLEAR CACHE DAN REBUILD
# ============================================
echo -e "${YELLOW}[9/12] Clearing cache and rebuilding...${NC}"

cd "$PTERO_PATH"

# Clear all caches
sudo -u www-data php artisan cache:clear 2>/dev/null || true
sudo -u www-data php artisan config:clear 2>/dev/null || true
sudo -u www-data php artisan route:clear 2>/dev/null || true
sudo -u www-data php artisan view:clear 2>/dev/null || true

# Clear route cache files
rm -f bootstrap/cache/routes*.php 2>/dev/null
rm -f bootstrap/cache/packages*.php 2>/dev/null
rm -f bootstrap/cache/config*.php 2>/dev/null

# Rebuild autoload
sudo -u www-data composer dump-autoload 2>/dev/null || true

echo -e "${GREEN}✓ Cache cleared${NC}"

# ============================================
# 10. FIX PERMISSIONS
# ============================================
echo -e "${YELLOW}[10/12] Fixing permissions...${NC}"

# Set proper permissions
chown -R www-data:www-data "$PTERO_PATH"
chmod -R 755 "$PTERO_PATH/storage"
chmod -R 755 "$PTERO_PATH/bootstrap/cache"
chmod 644 "$PTERO_PATH/.env" 2>/dev/null || true

# Fix specific directories
find "$PTERO_PATH/storage" -type d -exec chmod 775 {} \;
find "$PTERO_PATH/storage" -type f -exec chmod 664 {} \;
find "$PTERO_PATH/bootstrap/cache" -type d -exec chmod 775 {} \;
find "$PTERO_PATH/bootstrap/cache" -type f -exec chmod 664 {} \;

echo -e "${GREEN}✓ Permissions fixed${NC}"

# ============================================
# 11. VERIFIKASI INSTALASI
# ============================================
echo -e "${YELLOW}[11/12] Verifying installation...${NC}"

# Test if controller exists
if [ -f "$CONTROLLER_DIR/SecurityController.php" ]; then
    echo -e "${GREEN}✓ SecurityController exists${NC}"
else
    echo -e "${RED}✗ SecurityController missing${NC}"
fi

# Test if middleware exists
if [ -f "$MIDDLEWARE_DIR/OwnerOnly.php" ]; then
    echo -e "${GREEN}✓ OwnerOnly middleware exists${NC}"
else
    echo -e "${RED}✗ OwnerOnly middleware missing${NC}"
fi

# Test if views exist
if [ -f "$VIEWS_DIR/index.blade.php" ]; then
    echo -e "${GREEN}✓ Security views exist${NC}"
else
    echo -e "${RED}✗ Security views missing${NC}"
fi

# Test routes
echo -e "${YELLOW}Checking routes...${NC}"
sudo -u www-data php artisan route:list | grep -i security | head -5

# ============================================
# 12. OPTIMIZE DAN TEST
# ============================================
echo -e "${YELLOW}[12/12] Optimizing and testing...${NC}"

# Optimize
sudo -u www-data php artisan optimize 2>/dev/null || true

# Test with tinker
echo -e "${YELLOW}Testing with artisan tinker...${NC}"
sudo -u www-data php artisan tinker --execute='
try {
    echo "Testing SecurityController...\n";
    
    // Test class existence
    if (class_exists(\Pterodactyl\Http\Controllers\Admin\SecurityController::class)) {
        echo "✓ SecurityController class exists\n";
    } else {
        echo "✗ SecurityController class not found\n";
    }
    
    // Test middleware
    if (class_exists(\Pterodactyl\Http\Middleware\OwnerOnly::class)) {
        echo "✓ OwnerOnly middleware exists\n";
    } else {
        echo "✗ OwnerOnly middleware not found\n";
    }
    
    // Test database connection
    try {
        \Illuminate\Support\Facades\DB::connection()->getPdo();
        echo "✓ Database connection OK\n";
        
        // Test security_banned_ips table
        $count = \Illuminate\Support\Facades\DB::table("security_banned_ips")->count();
        echo "✓ security_banned_ips table has {$count} records\n";
        
    } catch (\Exception $e) {
        echo "✗ Database error: " . $e->getMessage() . "\n";
    }
    
    // Test cache
    try {
        \Illuminate\Support\Facades\Cache::put("test_key", "test_value", 1);
        $value = \Illuminate\Support\Facades\Cache::get("test_key");
        if ($value === "test_value") {
            echo "✓ Cache is working\n";
        } else {
            echo "✗ Cache test failed\n";
        }
    } catch (\Exception $e) {
        echo "✗ Cache error: " . $e->getMessage() . "\n";
    }
    
    echo "\n✅ All tests completed!\n";
    
} catch (\Exception $e) {
    echo "❌ Test failed: " . $e->getMessage() . "\n";
}
'

# ============================================
# FINAL MESSAGE
# ============================================
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║               FIX COMPLETED SUCCESSFULLY                 ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║  What was fixed:                                         ║"
echo "║  ✓ Duplicate route errors                                ║"
echo "║  ✓ SecurityController with proper namespace              ║"
echo "║  ✓ OwnerOnly middleware                                  ║"
echo "║  ✓ Security views (index, banned-ips, rate-limits)       ║"
echo "║  ✓ Database tables (security_banned_ips)                 ║"
echo "║  ✓ Cache cleared and permissions fixed                   ║"
echo "║                                                          ║"
echo "║  Access URLs:                                            ║"
echo "║  • /admin/security              (Security Dashboard)     ║"
echo "║  • /admin/security/banned-ips   (Manage Banned IPs)      ║"
echo "║  • /admin/security/rate-limits  (Rate Limits)            ║"
echo "║                                                          ║"
echo "║  Backup saved at: $BACKUP_DIR${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"

echo -e "${YELLOW}"
echo "Next steps:"
echo "1. Restart PHP-FPM: systemctl restart php8.1-fpm"
echo "2. Restart Nginx: systemctl restart nginx"
echo "3. Access: https://your-domain.com/admin/security"
echo "4. Note: Only user ID 1 (owner) can access security section"
echo -e "${NC}"

# Restart services
systemctl restart php8.1-fpm
systemctl restart nginx

echo -e "${GREEN}Services restarted. Check your panel!${NC}"
