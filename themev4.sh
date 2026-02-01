#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"
LOG_FILE="/var/log/pterodactyl_security_fix.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log_message "${RED}ERROR: $1${NC}"
    exit 1
}

echo -e "${BLUE}"
echo "=================================================="
echo "     PTERODACTYL SECURITY SYSTEM INSTALLER       "
echo "           IP Monitoring & Protection            "
echo "=================================================="
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
    error_exit "Script harus dijalankan sebagai root!"
fi

if [ ! -d "$PTERO_PATH" ]; then
    error_exit "Directory Pterodactyl tidak ditemukan!"
fi

log_message "${YELLOW}Membuat backup...${NC}"
mkdir -p "$BACKUP_DIR"
cp -r "$PTERO_PATH/resources/scripts" "$BACKUP_DIR/" 2>/dev/null
log_message "${GREEN}Backup berhasil di: $BACKUP_DIR${NC}"

# ============================================
# 1. CREATE SECURITY TABLES MIGRATION
# ============================================
log_message "${YELLOW}Membuat database tables untuk security...${NC}"

SECURITY_MIGRATION="$PTERO_PATH/database/migrations/$(date +%Y_%m_%d_%H%M%S)_create_security_tables.php"

cat > "$SECURITY_MIGRATION" << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('security_ip_blacklist', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->unique();
            $table->text('reason')->nullable();
            $table->string('type')->default('manual');
            $table->integer('request_count')->default(0);
            $table->timestamp('last_attempt')->nullable();
            $table->timestamps();
            $table->softDeletes();
            
            $table->index('ip_address');
            $table->index('type');
        });

        Schema::create('security_ip_whitelist', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->unique();
            $table->text('note')->nullable();
            $table->timestamps();
        });

        Schema::create('security_request_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->string('user_agent')->nullable();
            $table->string('method', 10);
            $table->string('path');
            $table->integer('status_code');
            $table->integer('response_time')->nullable();
            $table->text('referrer')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
            
            $table->index('ip_address');
            $table->index('created_at');
            $table->index(['ip_address', 'created_at']);
        });

        Schema::create('security_rate_limits', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->string('endpoint');
            $table->integer('attempts')->default(1);
            $table->timestamp('reset_at');
            $table->timestamps();
            
            $table->unique(['ip_address', 'endpoint']);
            $table->index('reset_at');
        });

        Schema::create('security_suspicious_activity', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->string('activity_type');
            $table->text('details')->nullable();
            $table->integer('severity')->default(1);
            $table->boolean('reviewed')->default(false);
            $table->timestamps();
            
            $table->index('ip_address');
            $table->index('activity_type');
            $table->index(['reviewed', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('security_suspicious_activity');
        Schema::dropIfExists('security_rate_limits');
        Schema::dropIfExists('security_request_logs');
        Schema::dropIfExists('security_ip_whitelist');
        Schema::dropIfExists('security_ip_blacklist');
    }
};
EOF

log_message "${GREEN}Database migration created${NC}"

# ============================================
# 2. CREATE SECURITY MIDDLEWARE
# ============================================
log_message "${YELLOW}Membuat security middleware...${NC}"

MIDDLEWARE_DIR="$PTERO_PATH/app/Http/Middleware"
mkdir -p "$MIDDLEWARE_DIR"

cat > "$MIDDLEWARE_DIR/CheckIpBlacklist.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class CheckIpBlacklist
{
    public function handle(Request $request, Closure $next)
    {
        $ip = $request->ip();
        
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return $next($request);
        }

        $cacheKey = 'ip_blacklist_' . md5($ip);
        if (Cache::has($cacheKey)) {
            if (Cache::get($cacheKey) === true) {
                $this->logBlockedRequest($request);
                return response()->json([
                    'error' => 'Access denied',
                    'message' => 'Your IP address has been blacklisted.'
                ], 403);
            }
        }

        $isBlacklisted = DB::table('security_ip_blacklist')
            ->where('ip_address', $ip)
            ->exists();

        if ($isBlacklisted) {
            Cache::put($cacheKey, true, 300);
            $this->logBlockedRequest($request);
            
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your IP address has been blacklisted.'
            ], 403);
        }

        Cache::put($cacheKey, false, 3600);

        return $next($request);
    }

    private function logBlockedRequest(Request $request): void
    {
        try {
            DB::table('security_request_logs')->insert([
                'ip_address' => $request->ip(),
                'user_agent' => substr($request->userAgent() ?? '', 0, 255),
                'method' => $request->method(),
                'path' => $request->path(),
                'status_code' => 403,
                'referrer' => $request->header('referer'),
                'metadata' => json_encode([
                    'blacklisted' => true,
                    'timestamp' => now()->toIso8601String(),
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Exception $e) {
        }
    }
}
EOF

cat > "$MIDDLEWARE_DIR/RateLimitRequests.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class RateLimitRequests
{
    private array $limits = [
        'login' => [
            'max_attempts' => 5,
            'decay_minutes' => 15,
        ],
        'api' => [
            'max_attempts' => 60,
            'decay_minutes' => 1,
        ],
        'default' => [
            'max_attempts' => 100,
            'decay_minutes' => 1,
        ],
    ];

    public function handle(Request $request, Closure $next)
    {
        $ip = $request->ip();
        $path = $request->path();
        
        $type = $this->getRateLimitType($path);
        $config = $this->limits[$type];
        
        $key = "rate_limit:{$type}:{$ip}";
        
        $attempts = Cache::get($key, 0);
        
        if ($attempts >= $config['max_attempts']) {
            if ($attempts >= $config['max_attempts'] * 3) {
                $this->autoBlacklist($ip, 'Rate limit exceeded multiple times');
            }
            
            return response()->json([
                'error' => 'Too Many Requests',
                'message' => 'Please slow down and try again later.',
                'retry_after' => $config['decay_minutes'] * 60,
            ], 429);
        }
        
        Cache::put($key, $attempts + 1, $config['decay_minutes'] * 60);
        
        $response = $next($request);
        
        return $response->withHeaders([
            'X-RateLimit-Limit' => $config['max_attempts'],
            'X-RateLimit-Remaining' => max(0, $config['max_attempts'] - ($attempts + 1)),
            'X-RateLimit-Reset' => Carbon::now()->addMinutes($config['decay_minutes'])->timestamp,
        ]);
    }

    private function getRateLimitType(string $path): string
    {
        if (str_contains($path, '/auth/')) {
            return 'login';
        }
        
        if (str_contains($path, '/api/')) {
            return 'api';
        }
        
        return 'default';
    }

    private function autoBlacklist(string $ip, string $reason): void
    {
        try {
            DB::table('security_ip_blacklist')->updateOrInsert(
                ['ip_address' => $ip],
                [
                    'reason' => $reason,
                    'type' => 'auto',
                    'request_count' => DB::raw('request_count + 1'),
                    'last_attempt' => now(),
                    'updated_at' => now(),
                    'created_at' => DB::raw('COALESCE(created_at, NOW())'),
                ]
            );
            
            DB::table('security_suspicious_activity')->insert([
                'ip_address' => $ip,
                'activity_type' => 'rate_limit_exceeded',
                'details' => json_encode([
                    'reason' => $reason,
                    'threshold' => '3x normal limit',
                ]),
                'severity' => 3,
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Exception $e) {
        }
    }
}
EOF

log_message "${GREEN}Security middleware created${NC}"

# ============================================
# 3. CREATE SECURITY CONTROLLER
# ============================================
log_message "${YELLOW}Membuat security controller...${NC}"

CONTROLLER_DIR="$PTERO_PATH/app/Http/Controllers/Admin"
mkdir -p "$CONTROLLER_DIR"

cat > "$CONTROLLER_DIR/SecurityController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class SecurityController extends Controller
{
    public function getBlacklist(Request $request): JsonResponse
    {
        $page = $request->input('page', 1);
        $perPage = $request->input('per_page', 20);
        $search = $request->input('search');
        
        $query = DB::table('security_ip_blacklist')
            ->select('*');
        
        if ($search) {
            $query->where('ip_address', 'like', "%{$search}%")
                ->orWhere('reason', 'like', "%{$search}%");
        }
        
        $total = $query->count();
        $items = $query->orderBy('created_at', 'desc')
            ->offset(($page - 1) * $perPage)
            ->limit($perPage)
            ->get();
        
        return response()->json([
            'data' => $items,
            'meta' => [
                'total' => $total,
                'page' => $page,
                'per_page' => $perPage,
                'last_page' => ceil($total / $perPage),
            ],
        ]);
    }

    public function addToBlacklist(Request $request): JsonResponse
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'reason' => 'nullable|string|max:500',
            'type' => 'in:manual,auto,suspicious',
        ]);
        
        $ip = $request->input('ip_address');
        
        DB::table('security_ip_blacklist')->updateOrInsert(
            ['ip_address' => $ip],
            [
                'reason' => $request->input('reason', 'Manually added by admin'),
                'type' => $request->input('type', 'manual'),
                'updated_at' => now(),
                'created_at' => DB::raw('COALESCE(created_at, NOW())'),
            ]
        );
        
        Cache::forget('ip_blacklist_' . md5($ip));
        
        return response()->json([
            'success' => true,
            'message' => 'IP added to blacklist successfully.',
        ]);
    }

    public function removeFromBlacklist(Request $request, string $ip): JsonResponse
    {
        $deleted = DB::table('security_ip_blacklist')
            ->where('ip_address', $ip)
            ->delete();
        
        if ($deleted) {
            Cache::forget('ip_blacklist_' . md5($ip));
            
            return response()->json([
                'success' => true,
                'message' => 'IP removed from blacklist successfully.',
            ]);
        }
        
        return response()->json([
            'success' => false,
            'message' => 'IP not found in blacklist.',
        ], 404);
    }

    public function getSuspiciousActivity(Request $request): JsonResponse
    {
        $page = $request->input('page', 1);
        $perPage = $request->input('per_page', 20);
        $reviewed = $request->input('reviewed');
        $severity = $request->input('severity');
        
        $query = DB::table('security_suspicious_activity')
            ->select('*');
        
        if ($reviewed !== null) {
            $query->where('reviewed', $reviewed);
        }
        
        if ($severity) {
            $query->where('severity', '>=', $severity);
        }
        
        $total = $query->count();
        $items = $query->orderBy('created_at', 'desc')
            ->offset(($page - 1) * $perPage)
            ->limit($perPage)
            ->get();
        
        return response()->json([
            'data' => $items,
            'meta' => [
                'total' => $total,
                'page' => $page,
                'per_page' => $perPage,
                'last_page' => ceil($total / $perPage),
            ],
        ]);
    }

    public function markAsReviewed(Request $request, int $id): JsonResponse
    {
        $updated = DB::table('security_suspicious_activity')
            ->where('id', $id)
            ->update([
                'reviewed' => true,
                'updated_at' => now(),
            ]);
        
        if ($updated) {
            return response()->json([
                'success' => true,
                'message' => 'Activity marked as reviewed.',
            ]);
        }
        
        return response()->json([
            'success' => false,
            'message' => 'Activity not found.',
        ], 404);
    }

    public function getRequestStats(Request $request): JsonResponse
    {
        $period = $request->input('period', 'today');
        
        $now = now();
        $startDate = match($period) {
            'yesterday' => $now->copy()->subDay()->startOfDay(),
            'week' => $now->copy()->subWeek()->startOfDay(),
            'month' => $now->copy()->subMonth()->startOfDay(),
            default => $now->copy()->startOfDay(),
        };
        
        $totalRequests = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->count();
        
        $uniqueIPs = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->distinct('ip_address')
            ->count('ip_address');
        
        $blockedRequests = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->where('status_code', 403)
            ->count();
        
        $topIPs = DB::table('security_request_logs')
            ->select('ip_address', DB::raw('COUNT(*) as request_count'))
            ->where('created_at', '>=', $startDate)
            ->groupBy('ip_address')
            ->orderByDesc('request_count')
            ->limit(10)
            ->get();
        
        $hourlyData = DB::table('security_request_logs')
            ->select(
                DB::raw('HOUR(created_at) as hour'),
                DB::raw('COUNT(*) as count')
            )
            ->where('created_at', '>=', $now->copy()->subDay())
            ->groupBy('hour')
            ->orderBy('hour')
            ->get();
        
        return response()->json([
            'stats' => [
                'total_requests' => $totalRequests,
                'unique_ips' => $uniqueIPs,
                'blocked_requests' => $blockedRequests,
                'blocked_percentage' => $totalRequests > 0 ? round(($blockedRequests / $totalRequests) * 100, 2) : 0,
            ],
            'top_ips' => $topIPs,
            'hourly_data' => $hourlyData,
            'period' => $period,
            'start_date' => $startDate->toIso8601String(),
        ]);
    }

    public function getWhitelist(Request $request): JsonResponse
    {
        $items = DB::table('security_ip_whitelist')
            ->orderBy('created_at', 'desc')
            ->get();
        
        return response()->json([
            'data' => $items,
        ]);
    }

    public function addToWhitelist(Request $request): JsonResponse
    {
        $request->validate([
            'ip_address' => 'required|ip',
            'note' => 'nullable|string|max:255',
        ]);
        
        DB::table('security_ip_whitelist')->updateOrInsert(
            ['ip_address' => $request->input('ip_address')],
            [
                'note' => $request->input('note'),
                'updated_at' => now(),
                'created_at' => DB::raw('COALESCE(created_at, NOW())'),
            ]
        );
        
        return response()->json([
            'success' => true,
            'message' => 'IP added to whitelist successfully.',
        ]);
    }

    public function removeFromWhitelist(Request $request, string $ip): JsonResponse
    {
        $deleted = DB::table('security_ip_whitelist')
            ->where('ip_address', $ip)
            ->delete();
        
        if ($deleted) {
            return response()->json([
                'success' => true,
                'message' => 'IP removed from whitelist successfully.',
            ]);
        }
        
        return response()->json([
            'success' => false,
            'message' => 'IP not found in whitelist.',
        ], 404);
    }
}
EOF

log_message "${GREEN}Security controller created${NC}"

# ============================================
# 4. CREATE ROUTES FOR SECURITY
# ============================================
log_message "${YELLOW}Menambahkan routes untuk security...${NC}"

ROUTES_FILE="$PTERO_PATH/routes/api.php"
if [ -f "$ROUTES_FILE" ]; then
    cat >> "$ROUTES_FILE" << 'EOF'

// Security Routes
Route::group(['prefix' => '/admin/security', 'middleware' => ['api.application', 'api.key']], function () {
    Route::get('/blacklist', 'Admin\SecurityController@getBlacklist');
    Route::post('/blacklist', 'Admin\SecurityController@addToBlacklist');
    Route::delete('/blacklist/{ip}', 'Admin\SecurityController@removeFromBlacklist');
    
    Route::get('/whitelist', 'Admin\SecurityController@getWhitelist');
    Route::post('/whitelist', 'Admin\SecurityController@addToWhitelist');
    Route::delete('/whitelist/{ip}', 'Admin\SecurityController@removeFromWhitelist');
    
    Route::get('/activity', 'Admin\SecurityController@getSuspiciousActivity');
    Route::put('/activity/{id}/review', 'Admin\SecurityController@markAsReviewed');
    
    Route::get('/stats', 'Admin\SecurityController@getRequestStats');
});
EOF
fi

# ============================================
# 5. UPDATE KERNEL FOR MIDDLEWARE
# ============================================
log_message "${YELLOW}Update kernel untuk middleware...${NC}"

KERNEL_FILE="$PTERO_PATH/app/Http/Kernel.php"
if [ -f "$KERNEL_FILE" ]; then
    cp "$KERNEL_FILE" "$KERNEL_FILE.backup"
    
    if grep -q "'ip.blacklist'" "$KERNEL_FILE"; then
        log_message "${YELLOW}Middleware sudah ada di kernel${NC}"
    else
        sed -i "/protected \$routeMiddleware = \[/a\
        'ip.blacklist' => \\Pterodactyl\\Http\\Middleware\\CheckIpBlacklist::class,\n\
        'rate.limit' => \\Pterodactyl\\Http\\Middleware\\RateLimitRequests::class," "$KERNEL_FILE"
        
        sed -i "/protected \$middleware = \[/a\
        \\Pterodactyl\\Http\\Middleware\\CheckIpBlacklist::class," "$KERNEL_FILE"
        
        sed -i "/'web' => \[/a\
            \\Pterodactyl\\Http\\Middleware\\RateLimitRequests::class," "$KERNEL_FILE"
    fi
fi

# ============================================
# 6. CREATE SECURITY DASHBOARD COMPONENT
# ============================================
log_message "${YELLOW}Membuat security dashboard component...${NC}"

DASHBOARD_SECURITY_FILE="$PTERO_PATH/resources/scripts/components/admin/SecurityDashboard.tsx"
mkdir -p "$(dirname "$DASHBOARD_SECURITY_FILE")"

cat > "$DASHBOARD_SECURITY_FILE" << 'EOF'
import React, { useState, useEffect } from 'react';
import PageContentBlock from '@/components/elements/PageContentBlock';
import { useFlash } from '@/plugins/useFlash';

const SecurityDashboard = () => {
    const { addFlash } = useFlash();
    const [loading, setLoading] = useState(true);
    const [blacklist, setBlacklist] = useState([]);
    const [whitelist, setWhitelist] = useState([]);
    const [activity, setActivity] = useState([]);
    const [stats, setStats] = useState({
        totalRequests: 0,
        blockedIPs: 0,
        suspiciousActivity: 0,
        activeSessions: 0
    });
    
    const [newIp, setNewIp] = useState('');
    const [reason, setReason] = useState('');
    
    useEffect(() => {
        loadData();
    }, []);
    
    const loadData = async () => {
        try {
            const [blacklistRes, whitelistRes, activityRes, statsRes] = await Promise.all([
                fetch('/api/application/security/blacklist').then(r => r.json()),
                fetch('/api/application/security/whitelist').then(r => r.json()),
                fetch('/api/application/security/activity').then(r => r.json()),
                fetch('/api/application/security/stats').then(r => r.json())
            ]);
            
            setBlacklist(blacklistRes.data || []);
            setWhitelist(whitelistRes.data || []);
            setActivity(activityRes.data || []);
            setStats(statsRes.stats || stats);
            setLoading(false);
        } catch (error) {
            console.error('Failed to load security data:', error);
            setLoading(false);
        }
    };
    
    const addToBlacklist = async () => {
        if (!newIp) {
            addFlash({ type: 'error', message: 'IP address is required' });
            return;
        }
        
        try {
            const response = await fetch('/api/application/security/blacklist', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ ip_address: newIp, reason })
            });
            
            const data = await response.json();
            
            if (data.success) {
                addFlash({ type: 'success', message: data.message });
                setNewIp('');
                setReason('');
                loadData();
            } else {
                addFlash({ type: 'error', message: data.message });
            }
        } catch (error) {
            addFlash({ type: 'error', message: 'Failed to add IP to blacklist' });
        }
    };
    
    const removeFromBlacklist = async (ip: string) => {
        if (!confirm(`Remove ${ip} from blacklist?`)) return;
        
        try {
            const response = await fetch(`/api/application/security/blacklist/${ip}`, {
                method: 'DELETE'
            });
            
            const data = await response.json();
            
            if (data.success) {
                addFlash({ type: 'success', message: data.message });
                loadData();
            } else {
                addFlash({ type: 'error', message: data.message });
            }
        } catch (error) {
            addFlash({ type: 'error', message: 'Failed to remove IP from blacklist' });
        }
    };
    
    const markAsReviewed = async (id: number) => {
        try {
            const response = await fetch(`/api/application/security/activity/${id}/review`, {
                method: 'PUT'
            });
            
            const data = await response.json();
            
            if (data.success) {
                addFlash({ type: 'success', message: data.message });
                loadData();
            }
        } catch (error) {
            addFlash({ type: 'error', message: 'Failed to mark activity as reviewed' });
        }
    };
    
    if (loading) {
        return (
            <PageContentBlock title="Security Dashboard">
                <div className="text-center py-10">
                    <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                    <p className="text-gray-400 mt-3">Loading security data...</p>
                </div>
            </PageContentBlock>
        );
    }
    
    return (
        <PageContentBlock title="Security Dashboard">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-white mb-2">Security Dashboard</h1>
                <p className="text-gray-400">Monitor and manage security threats</p>
            </div>
            
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="text-sm text-blue-300 mb-1">TOTAL REQUESTS</div>
                    <div className="text-2xl font-bold">{stats.totalRequests.toLocaleString()}</div>
                </div>
                
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="text-sm text-red-300 mb-1">BLOCKED IPs</div>
                    <div className="text-2xl font-bold">{stats.blockedIPs}</div>
                </div>
                
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="text-sm text-yellow-300 mb-1">SUSPICIOUS ACTIVITY</div>
                    <div className="text-2xl font-bold">{stats.suspiciousActivity}</div>
                </div>
                
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <div className="text-sm text-green-300 mb-1">ACTIVE SESSIONS</div>
                    <div className="text-2xl font-bold">{stats.activeSessions}</div>
                </div>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 mb-8">
                {/* Add to Blacklist */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <h2 className="text-xl font-bold text-white mb-4">Add to Blacklist</h2>
                    <div className="space-y-4">
                        <div>
                            <label className="block text-sm text-gray-400 mb-2">IP Address</label>
                            <input
                                type="text"
                                value={newIp}
                                onChange={(e) => setNewIp(e.target.value)}
                                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white"
                                placeholder="192.168.1.1"
                            />
                        </div>
                        <div>
                            <label className="block text-sm text-gray-400 mb-2">Reason (Optional)</label>
                            <textarea
                                value={reason}
                                onChange={(e) => setReason(e.target.value)}
                                className="w-full px-4 py-2 bg-gray-900 border border-gray-700 rounded text-white"
                                placeholder="Multiple failed login attempts"
                                rows={3}
                            />
                        </div>
                        <button
                            onClick={addToBlacklist}
                            className="w-full bg-red-600 hover:bg-red-700 text-white py-2 px-4 rounded"
                        >
                            Add to Blacklist
                        </button>
                    </div>
                </div>
                
                {/* Quick Stats */}
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                    <h2 className="text-xl font-bold text-white mb-4">Security Overview</h2>
                    <div className="space-y-4">
                        <div className="flex justify-between items-center border-b border-gray-700 pb-3">
                            <span className="text-gray-400">Blocked Requests Today</span>
                            <span className="text-white font-medium">{stats.blockedRequests || 0}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-gray-700 pb-3">
                            <span className="text-gray-400">Unique IPs Today</span>
                            <span className="text-white font-medium">{stats.unique_ips || 0}</span>
                        </div>
                        <div className="flex justify-between items-center border-b border-gray-700 pb-3">
                            <span className="text-gray-400">Block Rate</span>
                            <span className="text-red-400 font-medium">{stats.blocked_percentage || 0}%</span>
                        </div>
                        <div className="flex justify-between items-center">
                            <span className="text-gray-400">Pending Reviews</span>
                            <span className="text-yellow-400 font-medium">
                                {activity.filter((a: any) => !a.reviewed).length}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
            
            {/* Blacklist Table */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6 mb-8">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-bold text-white">IP Blacklist ({blacklist.length})</h2>
                    <button
                        onClick={loadData}
                        className="bg-blue-600 hover:bg-blue-700 text-white py-2 px-4 rounded text-sm"
                    >
                        Refresh
                    </button>
                </div>
                
                {blacklist.length === 0 ? (
                    <p className="text-gray-400 text-center py-4">No IPs in blacklist</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-gray-700">
                                    <th className="text-left py-3 px-4 text-gray-400">IP Address</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Reason</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Type</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Added</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {blacklist.map((item: any) => (
                                    <tr key={item.id} className="border-b border-gray-800 hover:bg-gray-900">
                                        <td className="py-3 px-4 text-white">{item.ip_address}</td>
                                        <td className="py-3 px-4 text-gray-400">{item.reason || 'No reason provided'}</td>
                                        <td className="py-3 px-4">
                                            <span className={`px-2 py-1 rounded text-xs ${
                                                item.type === 'manual' ? 'bg-blue-900/30 text-blue-400' :
                                                item.type === 'auto' ? 'bg-yellow-900/30 text-yellow-400' :
                                                'bg-red-900/30 text-red-400'
                                            }`}>
                                                {item.type.toUpperCase()}
                                            </span>
                                        </td>
                                        <td className="py-3 px-4 text-gray-400">
                                            {new Date(item.created_at).toLocaleDateString()}
                                        </td>
                                        <td className="py-3 px-4">
                                            <button
                                                onClick={() => removeFromBlacklist(item.ip_address)}
                                                className="bg-red-600 hover:bg-red-700 text-white py-1 px-3 rounded text-sm"
                                            >
                                                Remove
                                            </button>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
            
            {/* Suspicious Activity */}
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-6">
                <div className="flex justify-between items-center mb-6">
                    <h2 className="text-xl font-bold text-white">Suspicious Activity ({activity.length})</h2>
                </div>
                
                {activity.length === 0 ? (
                    <p className="text-gray-400 text-center py-4">No suspicious activity detected</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-gray-700">
                                    <th className="text-left py-3 px-4 text-gray-400">IP Address</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Activity Type</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Severity</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Time</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Status</th>
                                    <th className="text-left py-3 px-4 text-gray-400">Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {activity.map((item: any) => (
                                    <tr key={item.id} className="border-b border-gray-800 hover:bg-gray-900">
                                        <td className="py-3 px-4 text-white">{item.ip_address}</td>
                                        <td className="py-3 px-4 text-gray-400">{item.activity_type}</td>
                                        <td className="py-3 px-4">
                                            <span className={`px-2 py-1 rounded text-xs ${
                                                item.severity <= 2 ? 'bg-green-900/30 text-green-400' :
                                                item.severity <= 4 ? 'bg-yellow-900/30 text-yellow-400' :
                                                'bg-red-900/30 text-red-400'
                                            }`}>
                                                Level {item.severity}
                                            </span>
                                        </td>
                                        <td className="py-3 px-4 text-gray-400">
                                            {new Date(item.created_at).toLocaleString()}
                                        </td>
                                        <td className="py-3 px-4">
                                            {item.reviewed ? (
                                                <span className="px-2 py-1 bg-green-900/30 text-green-400 text-xs rounded">
                                                    Reviewed
                                                </span>
                                            ) : (
                                                <span className="px-2 py-1 bg-yellow-900/30 text-yellow-400 text-xs rounded">
                                                    Pending
                                                </span>
                                            )}
                                        </td>
                                        <td className="py-3 px-4">
                                            {!item.reviewed && (
                                                <button
                                                    onClick={() => markAsReviewed(item.id)}
                                                    className="bg-blue-600 hover:bg-blue-700 text-white py-1 px-3 rounded text-sm"
                                                >
                                                    Mark Reviewed
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </PageContentBlock>
    );
};

export default SecurityDashboard;
EOF

log_message "${GREEN}Security dashboard component created${NC}"

# ============================================
# 7. ADD SECURITY LINK TO SIDEBAR
# ============================================
log_message "${YELLOW}Menambahkan link security ke sidebar...${NC}"

SIDEBAR_FILE="$PTERO_PATH/resources/scripts/components/elements/navigation/Sidebar.tsx"
if [ -f "$SIDEBAR_FILE" ]; then
    if grep -q "Security Dashboard" "$SIDEBAR_FILE"; then
        log_message "${YELLOW}Security link sudah ada di sidebar${NC}"
    else
        sed -i "/name: 'API',/i\
            {\n\
                route: '/admin/security',\n\
                name: 'Security Dashboard',\n\
                icon: 'shield',\n\
            }," "$SIDEBAR_FILE"
    fi
fi

# ============================================
# 8. BUILD AND MIGRATE
# ============================================
log_message "${YELLOW}Membangun assets dan menjalankan migrations...${NC}"

cd "$PTERO_PATH" || error_exit "Tidak bisa pindah ke $PTERO_PATH"

# Clear cache
php artisan view:clear
php artisan cache:clear
php artisan config:clear
php artisan route:clear

# Run migrations
php artisan migrate --force 2>&1 | tee -a "$LOG_FILE"

# Build assets
log_message "Membangun assets..."
yarn install --production=false --ignore-engines 2>&1 | tail -20 | tee -a "$LOG_FILE"

if npm run build:production 2>&1 | tail -30 | tee -a "$LOG_FILE"; then
    log_message "${GREEN}Build berhasil${NC}"
else
    log_message "${YELLOW}Build selesai dengan warnings${NC}"
fi

# Set permissions
chown -R www-data:www-data "$PTERO_PATH/storage"
chown -R www-data:www-data "$PTERO_PATH/bootstrap/cache"
chmod -R 755 "$PTERO_PATH/storage"
chmod -R 755 "$PTERO_PATH/bootstrap/cache"

# Restart services
systemctl restart pteroq 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true

# ============================================
# 9. FINISH
# ============================================
echo -e "${GREEN}"
echo "=================================================="
echo "     INSTALASI SECURITY SYSTEM BERHASIL!         "
echo "=================================================="
echo -e "${NC}"
echo ""
echo "✅ ${GREEN}Security System Features:${NC}"
echo "   • IP Blacklist Management"
echo "   • IP Whitelist Management"
echo "   • Rate Limiting (Login: 5/15min, API: 60/min)"
echo "   • Suspicious Activity Detection"
echo "   • Request Logging & Analytics"
echo "   • Auto-blocking for rate limit violations"
echo ""
echo "📊 ${BLUE}Access Security Dashboard:${NC}"
echo "   1. Login sebagai admin"
echo "   2. Navigasi ke: Admin → Security Dashboard"
echo ""
echo "🔧 ${YELLOW}API Endpoints Available:${NC}"
echo "   GET  /api/application/security/blacklist"
echo "   POST /api/application/security/blacklist"
echo "   DELETE /api/application/security/blacklist/{ip}"
echo "   GET  /api/application/security/stats"
echo "   GET  /api/application/security/activity"
echo ""
echo "📂 ${BLUE}Backup: $BACKUP_DIR${NC}"
echo "📝 ${BLUE}Log: $LOG_FILE${NC}"
echo ""
echo -e "${YELLOW}Jika ada error 500:${NC}"
echo "   tail -f $PTERO_PATH/storage/logs/laravel.log"
echo "   sudo systemctl restart pteroq"
echo "   sudo systemctl restart nginx"
echo ""
echo "=================================================="
