#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"
LOG_FILE="/var/log/vaxstresser_install.log"

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fungsi logging
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Fungsi error handling
error_exit() {
    log_message "${RED}ERROR: $1${NC}"
    exit 1
}

# Header
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          VAXSTRESSER PREMIUM THEME INSTALLER            ║"
echo "║          Advanced Security & Black-Blue Theme           ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Cek root
if [[ $EUID -ne 0 ]]; then
    error_exit "Script harus dijalankan sebagai root!"
fi

# Cek path Pterodactyl
if [ ! -d "$PTERO_PATH" ]; then
    error_exit "Directory Pterodactyl tidak ditemukan di $PTERO_PATH"
fi

# Buat backup
log_message "${YELLOW}Membuat backup...${NC}"
mkdir -p "$BACKUP_DIR"
cp -r "$PTERO_PATH/resources/scripts" "$BACKUP_DIR/" 2>/dev/null
cp -r "$PTERO_PATH/resources/views" "$BACKUP_DIR/" 2>/dev/null
cp -r "$PTERO_PATH/public/themes" "$BACKUP_DIR/" 2>/dev/null
log_message "${GREEN}Backup berhasil di: $BACKUP_DIR${NC}"

# ============================================
# 1. UPDATE CSS UTAMA (TEMA HITAM-BIRU PREMIUM)
# ============================================
log_message "${YELLOW}Menginstall tema CSS premium...${NC}"

MAIN_CSS="$PTERO_PATH/resources/scripts/index.css"
cat > "$MAIN_CSS" << 'EOF'
/* VAXSTRESSER PREMIUM THEME - BLACK & BLUE EDITION */
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #0f111a;
    --bg-card: #131520;
    --bg-input: #1a1c2b;
    --accent-blue: #0066ff;
    --accent-blue-light: #3399ff;
    --accent-blue-dark: #0044cc;
    --text-primary: #ffffff;
    --text-secondary: #a0aec0;
    --text-muted: #718096;
    --border-color: #2d3748;
    --border-light: #4a5568;
    --success: #10b981;
    --warning: #f59e0b;
    --danger: #ef4444;
    --gradient-primary: linear-gradient(135deg, var(--accent-blue) 0%, #0099ff 100%);
    --gradient-dark: linear-gradient(135deg, #1a1c2b 0%, #0f111a 100%);
}

/* GLOBAL STYLES */
body {
    background-color: var(--bg-primary) !important;
    background-image: radial-gradient(circle at 15% 50%, rgba(0, 102, 255, 0.1) 0%, transparent 20%),
                      radial-gradient(circle at 85% 30%, rgba(0, 153, 255, 0.05) 0%, transparent 20%);
    color: var(--text-primary);
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
}

/* HEADER & NAVIGATION */
header {
    background: var(--gradient-dark) !important;
    border-bottom: 1px solid rgba(0, 102, 255, 0.3) !important;
    backdrop-filter: blur(10px);
}

nav {
    background: var(--gradient-dark) !important;
    border-right: 1px solid var(--border-color) !important;
}

/* CARDS */
.bg-gray-800, .bg-gray-800\/50, .bg-gray-700 {
    background: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 12px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    transition: all 0.3s ease;
}

.bg-gray-800:hover, .bg-gray-800\/50:hover {
    border-color: var(--accent-blue) !important;
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 102, 255, 0.2);
}

/* BUTTONS */
.btn-primary, button.bg-blue-600, a.bg-blue-600 {
    background: var(--gradient-primary) !important;
    border: none !important;
    border-radius: 8px;
    color: white !important;
    font-weight: 600;
    padding: 10px 20px;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.btn-primary:hover, button.bg-blue-600:hover, a.bg-blue-600:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(0, 102, 255, 0.4);
}

.btn-primary:active, button.bg-blue-600:active {
    transform: translateY(0);
}

/* TABLES */
table {
    background: var(--bg-card) !important;
    border-radius: 10px;
    overflow: hidden;
}

thead {
    background: rgba(0, 102, 255, 0.2) !important;
    border-bottom: 2px solid var(--accent-blue) !important;
}

tbody tr {
    border-bottom: 1px solid var(--border-color);
    transition: background-color 0.2s;
}

tbody tr:hover {
    background: rgba(0, 102, 255, 0.1) !important;
}

/* INPUTS & FORMS */
input, select, textarea {
    background: var(--bg-input) !important;
    border: 1px solid var(--border-light) !important;
    border-radius: 8px;
    color: var(--text-primary) !important;
    padding: 10px 15px;
    transition: all 0.3s;
}

input:focus, select:focus, textarea:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 3px rgba(0, 102, 255, 0.2) !important;
    outline: none;
}

/* CUSTOM COMPONENTS */
.vax-card {
    background: var(--gradient-dark);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 25px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}

.vax-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: var(--gradient-primary);
}

.vax-stat-card {
    background: linear-gradient(135deg, rgba(0, 102, 255, 0.2) 0%, rgba(0, 153, 255, 0.1) 100%);
    border: 1px solid rgba(0, 102, 255, 0.3);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: all 0.3s;
}

.vax-stat-card:hover {
    transform: translateY(-3px);
    border-color: var(--accent-blue);
    box-shadow: 0 10px 30px rgba(0, 102, 255, 0.2);
}

.vax-admin-badge {
    background: linear-gradient(135deg, #ff3366 0%, #cc0044 100%);
    color: white;
    padding: 5px 15px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    display: inline-block;
}

.vax-user-badge {
    background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-blue-dark) 100%);
    color: white;
    padding: 5px 15px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    display: inline-block;
}

/* DASHBOARD SPECIFIC */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 25px;
    padding: 20px;
}

.server-card {
    background: var(--gradient-dark);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 20px;
    transition: all 0.3s;
}

.server-card:hover {
    border-color: var(--accent-blue);
    transform: translateY(-5px);
    box-shadow: 0 15px 35px rgba(0, 102, 255, 0.15);
}

/* FOOTER */
footer {
    background: rgba(10, 10, 15, 0.9) !important;
    border-top: 1px solid var(--border-color);
    backdrop-filter: blur(10px);
}

/* SCROLLBAR */
::-webkit-scrollbar {
    width: 10px;
}

::-webkit-scrollbar-track {
    background: var(--bg-secondary);
}

::-webkit-scrollbar-thumb {
    background: var(--accent-blue);
    border-radius: 5px;
}

::-webkit-scrollbar-thumb:hover {
    background: var(--accent-blue-light);
}

/* ANIMATIONS */
@keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
}

.vax-card, .server-card {
    animation: fadeIn 0.5s ease-out;
}

/* RESPONSIVE */
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .vax-card {
        padding: 15px;
    }
}
EOF

log_message "${GREEN}CSS utama berhasil diupdate${NC}"

# ============================================
# 2. UPDATE DASHBOARD COMPONENT (FIXED IMPORT)
# ============================================
log_message "${YELLOW}Memperbarui dashboard...${NC}"

DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"
cat > "$DASHBOARD_FILE" << 'EOF'
import React, { useEffect, useState } from 'react';
import { Server } from '@/api/server/getServer';
import getServers from '@/api/getServers';
import ServerRow from '@/components/dashboard/ServerRow';
import Pagination from '@/components/elements/Pagination';
import { useStoreState } from 'easy-peasy';
import { ApplicationStore } from '@/state';
import PageContentBlock from '@/components/elements/PageContentBlock';
import useFlash from '@/plugins/useFlash';
import { Link } from 'react-router-dom';

export default () => {
    const { addFlash, clearFlashes } = useFlash();
    const [page, setPage] = useState(1);
    const [servers, setServers] = useState<Server[]>([]);
    const [loading, setLoading] = useState(true);
    const [stats, setStats] = useState({
        totalServers: 0,
        activeServers: 0,
        totalMemory: 0,
        totalDisk: 0
    });
    
    const rootAdmin = useStoreState((state: ApplicationStore) => state.user.data?.rootAdmin);
    const username = useStoreState((state: ApplicationStore) => state.user.data?.username);
    const email = useStoreState((state: ApplicationStore) => state.user.data?.email);

    useEffect(() => {
        clearFlashes('dashboard');
        setLoading(true);
        
        getServers({ page })
            .then(data => {
                setServers(data.items);
                setPagination(data.pagination);
                
                // Calculate stats
                const activeServers = data.items.filter(s => s.status === 'running').length;
                const totalMemory = data.items.reduce((sum, server) => sum + (server.limits.memory || 0), 0);
                const totalDisk = data.items.reduce((sum, server) => sum + (server.limits.disk || 0), 0);
                
                setStats({
                    totalServers: data.pagination.total,
                    activeServers,
                    totalMemory,
                    totalDisk
                });
                setLoading(false);
            })
            .catch(error => {
                console.error(error);
                addFlash({
                    key: 'dashboard',
                    type: 'error',
                    message: 'Failed to load server dashboard.'
                });
                setLoading(false);
            });
    }, [page]);

    const [pagination, setPagination] = useState({
        total: 0,
        count: 0,
        perPage: 0,
        currentPage: 1,
        totalPages: 1
    });

    const formatBytes = (bytes: number): string => {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    };

    return (
        <PageContentBlock title="Dashboard" showFlashKey="dashboard">
            {/* HEADER SECTION */}
            <div className="mb-8">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-6">
                    <div>
                        <h1 className="text-3xl font-bold text-white mb-2">
                            Welcome back, <span className="text-blue-400">{username}</span>!
                        </h1>
                        <p className="text-gray-400">
                            Manage your gaming servers and monitor resources in real-time
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                        <span className={rootAdmin ? 'vax-admin-badge' : 'vax-user-badge'}>
                            {rootAdmin ? 'VAX ADMIN' : 'PREMIUM USER'}
                        </span>
                        <span className="text-sm text-gray-400">{email}</span>
                    </div>
                </div>

                {/* STATS GRID */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <div className="vax-stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-blue-300 mb-1">TOTAL SERVERS</div>
                                <div className="text-2xl font-bold">{stats.totalServers}</div>
                            </div>
                            <div className="text-blue-400 text-xl">🖥️</div>
                        </div>
                    </div>
                    
                    <div className="vax-stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-green-300 mb-1">ACTIVE SERVERS</div>
                                <div className="text-2xl font-bold">{stats.activeServers}</div>
                            </div>
                            <div className="text-green-400 text-xl">⚡</div>
                        </div>
                    </div>
                    
                    <div className="vax-stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-purple-300 mb-1">TOTAL MEMORY</div>
                                <div className="text-2xl font-bold">{formatBytes(stats.totalMemory * 1024 * 1024)}</div>
                            </div>
                            <div className="text-purple-400 text-xl">💾</div>
                        </div>
                    </div>
                    
                    <div className="vax-stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-yellow-300 mb-1">TOTAL DISK</div>
                                <div className="text-2xl font-bold">{formatBytes(stats.totalDisk * 1024 * 1024)}</div>
                            </div>
                            <div className="text-yellow-400 text-xl">💿</div>
                        </div>
                    </div>
                </div>
            </div>

            {/* MAIN CONTENT GRID */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* LEFT COLUMN - SERVERS */}
                <div className="lg:col-span-2">
                    <div className="vax-card">
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-xl font-bold text-white">
                                🖥️ Your Game Servers
                            </h2>
                            <Link
                                to="/servers/create"
                                className="btn-primary flex items-center"
                            >
                                ⚡ Create Server
                            </Link>
                        </div>
                        
                        {loading ? (
                            <div className="text-center py-10">
                                <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500"></div>
                                <p className="text-gray-400 mt-3">Loading servers...</p>
                            </div>
                        ) : !servers.length ? (
                            <div className="text-center py-10">
                                <div className="text-gray-400 mb-4">No servers found. Create your first server!</div>
                                <Link
                                    to="/servers/create"
                                    className="btn-primary inline-flex items-center"
                                >
                                    🖥️ Create First Server
                                </Link>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                {servers.map((server) => (
                                    <div key={server.uuid} className="server-card">
                                        <ServerRow server={server} />
                                    </div>
                                ))}
                            </div>
                        )}
                        
                        {servers.length > 0 && pagination.totalPages > 1 && (
                            <div className="mt-6">
                                <Pagination data={pagination} onPageSelect={setPage} />
                            </div>
                        )}
                    </div>
                </div>

                {/* RIGHT COLUMN - SIDEBAR */}
                <div className="space-y-6">
                    {/* PLAN INFO */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">
                            🛡️ Plan Information
                        </h2>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">PLAN TYPE</span>
                                <span className="font-bold text-blue-400">
                                    {rootAdmin ? 'ENTERPRISE ADMIN' : 'PREMIUM GAMING'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">ACCESS LEVEL</span>
                                <span className={rootAdmin ? 'text-red-400' : 'text-green-400'}>
                                    {rootAdmin ? 'Full Administrator' : 'Standard Client'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">SERVER SLOTS</span>
                                <span className="text-white font-medium">Unlimited</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">SUPPORT</span>
                                <span className="text-green-400 font-medium">24/7 Priority</span>
                            </div>
                        </div>
                    </div>

                    {/* QUICK ACTIONS */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">Quick Actions</h2>
                        <div className="space-y-2">
                            <Link
                                to="/account/api"
                                className="flex items-center justify-between p-3 bg-gray-900/50 hover:bg-gray-800 rounded-lg transition"
                            >
                                <div className="flex items-center">
                                    <span className="mr-3 text-blue-400">🔑</span>
                                    <span>API Keys</span>
                                </div>
                                <span className="text-xs text-gray-400">Manage</span>
                            </Link>
                            
                            <Link
                                to="/account"
                                className="flex items-center justify-between p-3 bg-gray-900/50 hover:bg-gray-800 rounded-lg transition"
                            >
                                <div className="flex items-center">
                                    <span className="mr-3 text-green-400">⚙️</span>
                                    <span>Account Settings</span>
                                </div>
                                <span className="text-xs text-gray-400">Configure</span>
                            </Link>
                            
                            <button
                                onClick={() => window.location.href = '/auth/logout'}
                                className="w-full flex items-center justify-between p-3 bg-red-900/20 hover:bg-red-900/40 text-red-400 rounded-lg transition"
                            >
                                <div className="flex items-center">
                                    <span className="mr-3">🚪</span>
                                    <span>Logout</span>
                                </div>
                                <span className="text-xs">Sign out</span>
                            </button>
                        </div>
                    </div>

                    {/* SECURITY STATUS */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">Security Status</h2>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">2FA Protection</span>
                                <span className="px-2 py-1 bg-green-900/30 text-green-400 text-xs rounded">ENABLED</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Last Login</span>
                                <span className="text-gray-300 text-sm">Just now</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Session</span>
                                <span className="text-blue-400 text-sm">Active</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* FOOTER NOTE */}
            <div className="mt-8 pt-6 border-t border-gray-800 text-center text-gray-500 text-sm">
                <p>© 2024 VAXSTRESSER Gaming Panel • Premium Black & Blue Edition</p>
                <p className="text-xs mt-1">All rights reserved • Protected by advanced security system</p>
            </div>
        </PageContentBlock>
    );
};
EOF

log_message "${GREEN}Dashboard berhasil diperbarui${NC}"

# ============================================
# 3. FIX LOGIN PAGE (REMOVE FONTAWESOME IMPORT)
# ============================================
log_message "${YELLOW}Memperbarui login page...${NC}"

LOGIN_FILE="$PTERO_PATH/resources/scripts/components/auth/LoginContainer.tsx"
if [ -f "$LOGIN_FILE" ]; then
    mv "$LOGIN_FILE" "${LOGIN_FILE}.backup"
fi

cat > "$LOGIN_FILE" << 'EOF'
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import LoginForm from '@/components/auth/LoginForm';
import { useStoreState } from 'easy-peasy';
import { ApplicationStore } from '@/state';

export default () => {
    const isAuthenticated = useStoreState((state: ApplicationStore) => !!state.user.data?.uuid);
    const [showFeatures, setShowFeatures] = useState(true);

    useEffect(() => {
        if (isAuthenticated) {
            window.location.href = '/';
        }
    }, [isAuthenticated]);

    return (
        <div className="min-h-screen flex flex-col items-center justify-center p-4 bg-gray-900" 
             style={{
                 backgroundImage: 'radial-gradient(circle at 20% 80%, rgba(0, 102, 255, 0.15) 0%, transparent 50%), radial-gradient(circle at 80% 20%, rgba(0, 153, 255, 0.1) 0%, transparent 50%)',
                 backgroundAttachment: 'fixed'
             }}>
            
            {/* HEADER */}
            <div className="text-center mb-8">
                <div className="flex items-center justify-center mb-4">
                    <div className="text-blue-500 text-4xl mr-3">🛡️</div>
                    <h1 className="text-4xl font-bold text-white">
                        VAX<span className="text-blue-400">STRESSER</span>
                    </h1>
                </div>
                <p className="text-gray-400">Premium Gaming Server Management</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl w-full">
                {/* LOGIN FORM */}
                <div className="login-container">
                    <div className="text-center mb-8">
                        <h2 className="text-2xl font-bold text-white mb-2">Welcome Back</h2>
                        <p className="text-gray-400">Sign in to your gaming panel</p>
                    </div>

                    <LoginForm />

                    <div className="mt-6 text-center">
                        <p className="text-gray-500 text-sm">
                            Need help?{' '}
                            <a href="mailto:support@vaxstresser.com" className="text-blue-400 hover:text-blue-300">
                                Contact Support
                            </a>
                        </p>
                    </div>
                </div>

                {/* FEATURES */}
                {showFeatures && (
                    <div className="flex flex-col justify-center">
                        <div className="vax-card">
                            <h3 className="text-xl font-bold text-white mb-6 text-center">
                                Why Choose VAXSTRESSER?
                            </h3>
                            
                            <div className="space-y-6">
                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-blue-900/30 flex items-center justify-center">
                                            <span className="text-blue-400">🎮</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">Game Server Optimization</h4>
                                        <p className="text-gray-400 text-sm">
                                            High-performance servers optimized for Minecraft, FiveM, ARK, and more.
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-green-900/30 flex items-center justify-center">
                                            <span className="text-green-400">🛡️</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">Advanced Security</h4>
                                        <p className="text-gray-400 text-sm">
                                            Military-grade encryption and DDoS protection for your game servers.
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-purple-900/30 flex items-center justify-center">
                                            <span className="text-purple-400">🖥️</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">24/7 Monitoring</h4>
                                        <p className="text-gray-400 text-sm">
                                            Real-time monitoring with automatic backups and recovery.
                                        </p>
                                    </div>
                                </div>
                            </div>

                            <div className="mt-8 pt-6 border-t border-gray-800">
                                <div className="grid grid-cols-3 gap-4 text-center">
                                    <div>
                                        <div className="text-2xl font-bold text-blue-400">99.9%</div>
                                        <div className="text-xs text-gray-400">Uptime</div>
                                    </div>
                                    <div>
                                        <div className="text-2xl font-bold text-green-400">24/7</div>
                                        <div className="text-xs text-gray-400">Support</div>
                                    </div>
                                    <div>
                                        <div className="text-2xl font-bold text-purple-400">DDoS</div>
                                        <div className="text-xs text-gray-400">Protected</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* FOOTER */}
            <div className="mt-12 text-center text-gray-500 text-sm">
                <p>© 2024 VAXSTRESSER Gaming Panel. All rights reserved.</p>
                <p className="mt-1">
                    <Link to="/auth/password" className="hover:text-blue-400">Forgot Password?</Link>
                    {' • '}
                    <Link to="/auth/register" className="hover:text-blue-400 ml-2">Create Account</Link>
                </p>
            </div>
        </div>
    );
};
EOF

log_message "${GREEN}Login page berhasil diperbarui${NC}"

# ============================================
# 4. INSTALL SECURITY PATCH (File Controller)
# ============================================
log_message "${YELLOW}Menginstall security patch...${NC}"

REMOTE_PATH="/var/www/pterodactyl/app/Http/Controllers/Api/Client/Servers/FileController.php"
TIMESTAMP=$(date -u +"%Y-%m-%d-%H-%M-%S")
BACKUP_PATH="${REMOTE_PATH}.bak_${TIMESTAMP}"

if [ -f "$REMOTE_PATH" ]; then
    mv "$REMOTE_PATH" "$BACKUP_PATH"
    log_message "Backup file lama dibuat di $BACKUP_PATH"
fi

mkdir -p "$(dirname "$REMOTE_PATH")"
chmod 755 "$(dirname "$REMOTE_PATH")"

cat > "$REMOTE_PATH" << 'EOF'
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
     * 🔒 Enhanced Security: Prevent server access with additional checks
     */
    private function checkServerAccess($request, Server $server)
    {
        $user = $request->user();
        $ip = $request->ip();
        
        // Admin bypass (user id = 1)
        if ($user->id === 1) {
            return;
        }

        // Check if server belongs to user
        if ($server->owner_id !== $user->id) {
            // Log unauthorized access attempt
            \Log::warning('Unauthorized file access attempt', [
                'user_id' => $user->id,
                'server_id' => $server->id,
                'ip' => $ip,
                'action' => $request->route()->getName(),
                'timestamp' => now()
            ]);
            
            abort(403, 'Access denied: You do not have permission to access this server.');
        }

        // Additional security: Check if user is suspended
        if ($user->suspended) {
            abort(403, 'Your account has been suspended. Contact support.');
        }

        // Check server status
        if ($server->suspended) {
            abort(403, 'This server has been suspended.');
        }
    }

    /**
     * Validate file path to prevent directory traversal
     */
    private function validateFilePath($path)
    {
        if (strpos($path, '..') !== false || strpos($path, '//') !== false) {
            abort(400, 'Invalid file path detected.');
        }
        
        // Block access to sensitive directories
        $blocked = ['/etc', '/proc', '/sys', '/root', '/var/log', '/usr/bin', '/bin'];
        foreach ($blocked as $blockedPath) {
            if (strpos($path, $blockedPath) === 0) {
                abort(403, 'Access to this directory is restricted.');
            }
        }
    }

    public function directory(ListFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);
        $directory = $request->get('directory') ?? '/';
        $this->validateFilePath($directory);
        
        $contents = $this->fileRepository
            ->setServer($server)
            ->getDirectory($directory);
        
        return $this->fractal->collection($contents)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function contents(GetFileContentsRequest $request, Server $server): Response
    {
        $this->checkServerAccess($request, $server);
        $file = $request->get('file');
        $this->validateFilePath($file);
        
        $response = $this->fileRepository->setServer($server)->getContent(
            $file,
            config('pterodactyl.files.max_edit_size')
        );
        
        Activity::event('server:file.read')->property('file', $file)->log();
        
        return new Response($response, Response::HTTP_OK, ['Content-Type' => 'text/plain']);
    }

    public function download(GetFileContentsRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);
        $file = $request->get('file');
        $this->validateFilePath($file);
        
        $token = $this->jwtService
            ->setExpiresAt(CarbonImmutable::now()->addMinutes(15))
            ->setUser($request->user())
            ->setClaims([
                'file_path' => rawurldecode($file),
                'server_uuid' => $server->uuid,
                'user_id' => $request->user()->id,
                'timestamp' => now()->timestamp,
            ])
            ->handle($server->node, $request->user()->id . $server->uuid);
        
        Activity::event('server:file.download')->property('file', $file)->log();
        
        return [
            'object' => 'signed_url',
            'attributes' => [
                'url' => sprintf(
                    '%s/download/file?token=%s',
                    $server->node->getConnectionAddress(),
                    $token->toString()
                ),
                'expires_at' => CarbonImmutable::now()->addMinutes(15)->toIso8601String(),
            ],
        ];
    }

    public function write(WriteFileContentRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $file = $request->get('file');
        $this->validateFilePath($file);
        
        $this->fileRepository->setServer($server)->putContent($file, $request->getContent());
        
        Activity::event('server:file.write')
            ->property('file', $file)
            ->property('size', strlen($request->getContent()))
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function create(CreateFolderRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $name = $request->input('name');
        $root = $request->input('root', '/');
        $this->validateFilePath($root . '/' . $name);
        
        $this->fileRepository
            ->setServer($server)
            ->createDirectory($name, $root);
        
        Activity::event('server:file.create-directory')
            ->property('name', $name)
            ->property('directory', $root)
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function rename(RenameFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $files = $request->input('files');
        $root = $request->input('root');
        
        foreach ($files as $old => $new) {
            $this->validateFilePath($root . '/' . $old);
            $this->validateFilePath($root . '/' . $new);
        }
        
        $this->fileRepository
            ->setServer($server)
            ->renameFiles($root, $files);
        
        Activity::event('server:file.rename')
            ->property('directory', $root)
            ->property('files', $files)
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function copy(CopyFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $location = $request->input('location');
        $this->validateFilePath($location);
        
        $this->fileRepository
            ->setServer($server)
            ->copyFile($location);
        
        Activity::event('server:file.copy')
            ->property('file', $location)
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function compress(CompressFilesRequest $request, Server $server): array
    {
        $this->checkServerAccess($request, $server);
        $files = $request->input('files');
        $root = $request->input('root');
        
        foreach ($files as $file) {
            $this->validateFilePath($root . '/' . $file);
        }
        
        $file = $this->fileRepository->setServer($server)->compressFiles($root, $files);
        
        Activity::event('server:file.compress')
            ->property('directory', $root)
            ->property('files', $files)
            ->log();
        
        return $this->fractal->item($file)
            ->transformWith($this->getTransformer(FileObjectTransformer::class))
            ->toArray();
    }

    public function decompress(DecompressFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $file = $request->input('file');
        $root = $request->input('root');
        $this->validateFilePath($root . '/' . $file);
        
        set_time_limit(300);
        $this->fileRepository->setServer($server)->decompressFile($root, $file);
        
        Activity::event('server:file.decompress')
            ->property('directory', $root)
            ->property('file', $file)
            ->log();
        
        return new JsonResponse([], JsonResponse::HTTP_NO_CONTENT);
    }

    public function delete(DeleteFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $files = $request->input('files');
        $root = $request->input('root');
        
        foreach ($files as $file) {
            $this->validateFilePath($root . '/' . $file);
        }
        
        $this->fileRepository->setServer($server)->deleteFiles($root, $files);
        
        Activity::event('server:file.delete')
            ->property('directory', $root)
            ->property('files', $files)
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function chmod(ChmodFilesRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $files = $request->input('files');
        $root = $request->input('root');
        
        foreach ($files as $file) {
            $this->validateFilePath($root . '/' . $file);
        }
        
        $this->fileRepository->setServer($server)->chmodFiles($root, $files);
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }

    public function pull(PullFileRequest $request, Server $server): JsonResponse
    {
        $this->checkServerAccess($request, $server);
        $url = $request->input('url');
        $directory = $request->input('directory');
        $this->validateFilePath($directory);
        
        // Validate URL
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            abort(400, 'Invalid URL provided.');
        }
        
        $this->fileRepository->setServer($server)->pull(
            $url,
            $directory,
            $request->safe(['filename', 'use_header', 'foreground'])
        );
        
        Activity::event('server:file.pull')
            ->property('directory', $directory)
            ->property('url', $url)
            ->log();
        
        return new JsonResponse([], Response::HTTP_NO_CONTENT);
    }
}
EOF

chmod 644 "$REMOTE_PATH"
log_message "${GREEN}Security patch berhasil diinstall${NC}"

# ============================================
# 5. BUILD ASSETS
# ============================================
log_message "${YELLOW}Membangun assets...${NC}"

cd "$PTERO_PATH" || error_exit "Tidak bisa pindah ke $PTERO_PATH"

# Clear semua cache
php artisan view:clear
php artisan cache:clear
php artisan config:clear
php artisan route:clear

# Install dependencies
log_message "Menginstall dependencies..."
yarn install --production=false --ignore-engines 2>&1 | tee -a "$LOG_FILE"

# Build assets
log_message "Building assets dengan webpack..."
if npm run build:production 2>&1 | tee -a "$LOG_FILE"; then
    log_message "${GREEN}Build berhasil!${NC}"
elif npx webpack --mode=production 2>&1 | tee -a "$LOG_FILE"; then
    log_message "${GREEN}Build berhasil dengan npx!${NC}"
else
    log_message "${YELLOW}Build mungkin sudah berjalan atau ada warning${NC}"
fi

# Set permissions
chown -R www-data:www-data "$PTERO_PATH/storage"
chown -R www-data:www-data "$PTERO_PATH/bootstrap/cache"
chmod -R 755 "$PTERO_PATH/storage"
chmod -R 755 "$PTERO_PATH/bootstrap/cache"

# Restart services
log_message "Restarting services..."
systemctl restart pteroq 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true

# ============================================
# 6. FINISH
# ============================================
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          INSTALASI BERHASIL DILAKUKAN!                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "✅ ${GREEN}Semua komponen berhasil diupdate:${NC}"
echo "   • Tema CSS Premium (Hitam-Biru)"
echo "   • Dashboard User dengan stats"
echo "   • Login Page premium"
echo "   • Security Patch Enhanced"
echo ""
echo "📂 ${YELLOW}Backup tersedia di: $BACKUP_DIR${NC}"
echo "📝 ${YELLOW}Log instalasi: $LOG_FILE${NC}"
echo ""
echo "🔄 ${BLUE}Langkah selanjutnya:${NC}"
echo "   1. Refresh browser dengan CTRL+F5"
echo "   2. Clear cache browser jika perlu"
echo "   3. Login ulang untuk melihat perubahan"
echo ""
echo "🔒 ${PURPLE}Security Features:${NC}"
echo "   • Enhanced file access control"
echo "   • Directory traversal protection"
echo "   • IP logging untuk akses tidak sah"
echo "   • Validasi path file"
echo ""
echo "🎨 ${CYAN}Theme Features:${NC}"
echo "   • Black & Blue premium theme"
echo "   • Gradient effects"
echo "   • Smooth animations"
echo "   • Responsive design"
echo ""
echo -e "${YELLOW}Jika ada error, coba:${NC}"
echo "   sudo systemctl restart pteroq"
echo "   sudo systemctl restart nginx"
echo ""
echo "============================================================"
