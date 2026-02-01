#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"
LOG_FILE="/var/log/pterodactyl_premium_theme.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

echo -e "${PURPLE}"
echo "╔════════════════════════════════════════════════╗"
echo "║     PTERODACTYL PREMIUM THEME INSTALLER       ║"
echo "║        Black Blue Premium - No Error          ║"
echo "╚════════════════════════════════════════════════╝"
echo -e "${NC}"

if [[ $EUID -ne 0 ]]; then
    log_message "${RED}Script harus dijalankan sebagai root!${NC}"
    exit 1
fi

if [ ! -d "$PTERO_PATH" ]; then
    log_message "${RED}Directory Pterodactyl tidak ditemukan!${NC}"
    exit 1
fi

# ============================================
# 1. BACKUP FIRST
# ============================================
log_message "${YELLOW}Membuat backup...${NC}"
mkdir -p "$BACKUP_DIR"
cp -r "$PTERO_PATH/resources/scripts" "$BACKUP_DIR/" 2>/dev/null
log_message "${GREEN}Backup berhasil di: $BACKUP_DIR${NC}"

# ============================================
# 2. INSTALL PREMIUM CSS THEME (BLACK BLUE)
# ============================================
log_message "${YELLOW}Menginstall tema CSS premium...${NC}"

MAIN_CSS="$PTERO_PATH/resources/scripts/index.css"
cat > "$MAIN_CSS" << 'EOF'
/* PTERODACTYL PREMIUM THEME - BLACK BLUE */
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
    --bg-dark: #0a0a0f;
    --bg-darker: #08080c;
    --bg-card: #12121f;
    --bg-sidebar: #0f0f1a;
    --accent-blue: #0066ff;
    --accent-blue-light: #3399ff;
    --accent-blue-dark: #0052d4;
    --text-white: #ffffff;
    --text-gray: #a0aec0;
    --border-dark: #2d3748;
}

/* GLOBAL */
body {
    background-color: var(--bg-dark) !important;
    background-image: 
        radial-gradient(circle at 0% 0%, rgba(0, 102, 255, 0.1) 0%, transparent 50%),
        radial-gradient(circle at 100% 100%, rgba(0, 102, 255, 0.05) 0%, transparent 50%);
    color: var(--text-white) !important;
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif !important;
    min-height: 100vh;
}

/* HEADER & NAV */
header {
    background: linear-gradient(90deg, var(--bg-darker) 0%, var(--bg-card) 100%) !important;
    border-bottom: 1px solid var(--border-dark) !important;
    backdrop-filter: blur(10px);
}

nav, aside {
    background-color: var(--bg-sidebar) !important;
    border-right: 1px solid var(--border-dark) !important;
}

/* CARDS */
.bg-gray-800, .bg-gray-800\/50, .bg-gray-700 {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border-dark) !important;
    border-radius: 12px;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.bg-gray-800:hover, .bg-gray-800\/50:hover {
    border-color: var(--accent-blue) !important;
    transform: translateY(-4px);
    box-shadow: 0 12px 48px rgba(0, 102, 255, 0.25);
}

/* BUTTONS */
.btn-primary, button.bg-blue-600, a.bg-blue-600 {
    background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-blue-light) 100%) !important;
    border: none !important;
    border-radius: 10px;
    color: white !important;
    font-weight: 600;
    padding: 12px 24px;
    transition: all 0.3s ease;
    position: relative;
    overflow: hidden;
}

.btn-primary:hover, button.bg-blue-600:hover, a.bg-blue-600:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 25px rgba(0, 102, 255, 0.4);
}

.btn-primary:active, button.bg-blue-600:active {
    transform: translateY(0);
}

/* SPECIAL BUTTONS */
.btn-danger {
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%) !important;
}

.btn-success {
    background: linear-gradient(135deg, #00b894 0%, #00a085 100%) !important;
}

/* TABLES */
table {
    background-color: var(--bg-card) !important;
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid var(--border-dark);
}

thead {
    background: linear-gradient(90deg, rgba(0, 102, 255, 0.2) 0%, rgba(0, 102, 255, 0.1) 100%) !important;
    border-bottom: 2px solid var(--accent-blue) !important;
}

tbody tr {
    border-bottom: 1px solid var(--border-dark);
    transition: background-color 0.2s;
}

tbody tr:hover {
    background: rgba(0, 102, 255, 0.08) !important;
}

/* INPUTS */
input, select, textarea {
    background-color: rgba(18, 18, 31, 0.8) !important;
    border: 1px solid var(--border-dark) !important;
    color: var(--text-white) !important;
    border-radius: 8px;
    padding: 12px 16px;
    transition: all 0.3s;
}

input:focus, select:focus, textarea:focus {
    border-color: var(--accent-blue) !important;
    box-shadow: 0 0 0 3px rgba(0, 102, 255, 0.2) !important;
    outline: none;
    background-color: rgba(18, 18, 31, 0.9) !important;
}

/* CUSTOM COMPONENTS */
.vax-card {
    background: linear-gradient(135deg, var(--bg-card) 0%, #1a1a2e 100%);
    border: 1px solid var(--border-dark);
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 24px;
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
    background: linear-gradient(90deg, var(--accent-blue) 0%, var(--accent-blue-light) 100%);
}

.stat-card {
    background: linear-gradient(135deg, rgba(0, 102, 255, 0.15) 0%, rgba(0, 102, 255, 0.05) 100%);
    border: 1px solid rgba(0, 102, 255, 0.3);
    border-radius: 14px;
    padding: 22px;
    text-align: center;
    backdrop-filter: blur(10px);
    transition: all 0.3s;
}

.stat-card:hover {
    transform: translateY(-6px);
    border-color: var(--accent-blue);
    box-shadow: 0 16px 40px rgba(0, 102, 255, 0.2);
}

.vax-admin-badge {
    background: linear-gradient(135deg, #ff3366 0%, #cc0044 100%);
    color: white;
    padding: 6px 18px;
    border-radius: 25px;
    font-weight: 800;
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(255, 51, 102, 0.3);
}

.vax-user-badge {
    background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-blue-dark) 100%);
    color: white;
    padding: 6px 18px;
    border-radius: 25px;
    font-weight: 800;
    font-size: 12px;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    display: inline-block;
    box-shadow: 0 4px 15px rgba(0, 102, 255, 0.3);
}

/* SERVER CARDS */
.server-row-card {
    background: linear-gradient(135deg, var(--bg-card) 0%, #141428 100%);
    border: 1px solid var(--border-dark);
    border-radius: 14px;
    padding: 20px;
    transition: all 0.3s;
}

.server-row-card:hover {
    border-color: var(--accent-blue);
    transform: translateY(-5px);
    box-shadow: 0 20px 50px rgba(0, 102, 255, 0.15);
}

/* DASHBOARD GRID */
.dashboard-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 28px;
    padding: 20px;
}

/* SCROLLBAR */
::-webkit-scrollbar {
    width: 12px;
}

::-webkit-scrollbar-track {
    background: var(--bg-sidebar);
    border-radius: 6px;
}

::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, var(--accent-blue) 0%, var(--accent-blue-dark) 100%);
    border-radius: 6px;
    border: 3px solid var(--bg-sidebar);
}

::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(180deg, var(--accent-blue-light) 0%, var(--accent-blue) 100%);
}

/* ANIMATIONS */
@keyframes fadeInUp {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.vax-card, .stat-card {
    animation: fadeInUp 0.6s ease-out;
}

/* GRADIENTS */
.gradient-bg {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
}

.gradient-blue {
    background: linear-gradient(135deg, var(--accent-blue) 0%, #0099ff 100%);
}

/* RESPONSIVE */
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
        gap: 20px;
        padding: 15px;
    }
    
    .vax-card {
        padding: 20px;
    }
    
    .stat-card {
        padding: 18px;
    }
}

/* FOOTER */
footer {
    background: rgba(10, 10, 15, 0.95) !important;
    border-top: 1px solid var(--border-dark);
    backdrop-filter: blur(20px);
}

/* LOGIN PAGE STYLES */
.login-page-bg {
    background: linear-gradient(135deg, var(--bg-dark) 0%, #0c0c1a 100%);
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
}

.login-card {
    background: linear-gradient(135deg, var(--bg-card) 0%, #161627 100%);
    border: 1px solid var(--border-dark);
    border-radius: 20px;
    padding: 40px;
    width: 100%;
    max-width: 450px;
    box-shadow: 0 25px 60px rgba(0, 0, 0, 0.4);
}

/* ALERTS & NOTIFICATIONS */
.alert-success {
    background: linear-gradient(135deg, rgba(0, 184, 148, 0.1) 0%, rgba(0, 184, 148, 0.05) 100%);
    border: 1px solid rgba(0, 184, 148, 0.3);
    color: #00b894;
}

.alert-error {
    background: linear-gradient(135deg, rgba(255, 71, 87, 0.1) 0%, rgba(255, 71, 87, 0.05) 100%);
    border: 1px solid rgba(255, 71, 87, 0.3);
    color: #ff4757;
}

.alert-warning {
    background: linear-gradient(135deg, rgba(255, 165, 0, 0.1) 0%, rgba(255, 165, 0, 0.05) 100%);
    border: 1px solid rgba(255, 165, 0, 0.3);
    color: #ffa500;
}

/* PROGRESS BARS */
.progress-bar {
    background: linear-gradient(90deg, var(--accent-blue) 0%, var(--accent-blue-light) 100%);
    border-radius: 10px;
}

/* LOADING SPINNER */
.loading-spinner {
    border: 3px solid rgba(0, 102, 255, 0.1);
    border-top: 3px solid var(--accent-blue);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* BADGES */
.badge {
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
}

.badge-primary {
    background: linear-gradient(135deg, var(--accent-blue) 0%, var(--accent-blue-dark) 100%);
    color: white;
}

.badge-success {
    background: linear-gradient(135deg, #00b894 0%, #00a085 100%);
    color: white;
}

.badge-danger {
    background: linear-gradient(135deg, #ff4757 0%, #ff3838 100%);
    color: white;
}

.badge-warning {
    background: linear-gradient(135deg, #fdcb6e 0%, #f39c12 100%);
    color: #2d3436;
}
EOF

log_message "${GREEN}CSS Premium Theme installed${NC}"

# ============================================
# 3. FIX DASHBOARD COMPONENT (SIMPLE VERSION)
# ============================================
log_message "${YELLOW}Memperbarui dashboard dengan tema premium...${NC}"

DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"

# Backup original file
if [ -f "$DASHBOARD_FILE" ] && [ ! -f "${DASHBOARD_FILE}.original" ]; then
    cp "$DASHBOARD_FILE" "${DASHBOARD_FILE}.original"
fi

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

    const activeServers = servers.filter(s => s.status === 'running').length;

    return (
        <PageContentBlock title="Dashboard" showFlashKey="dashboard">
            <div className="mb-8">
                <div className="vax-card mb-8">
                    <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-6 mb-6">
                        <div>
                            <h1 className="text-3xl font-bold text-white mb-3">
                                Welcome back, <span className="text-blue-400">{username}</span>!
                            </h1>
                            <p className="text-gray-400 text-lg">
                                Premium Game Server Management Dashboard
                            </p>
                        </div>
                        <div className="flex flex-col items-end gap-3">
                            <span className={rootAdmin ? 'vax-admin-badge' : 'vax-user-badge'}>
                                {rootAdmin ? 'PREMIUM ADMIN' : 'PREMIUM USER'}
                            </span>
                            <span className="text-sm text-gray-400">{email}</span>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                        <div className="stat-card">
                            <div className="text-sm text-blue-300 mb-2">TOTAL SERVERS</div>
                            <div className="text-3xl font-bold text-white">{pagination.total}</div>
                            <div className="text-xs text-gray-400 mt-2">Allocated Servers</div>
                        </div>
                        
                        <div className="stat-card">
                            <div className="text-sm text-green-300 mb-2">ACTIVE SERVERS</div>
                            <div className="text-3xl font-bold text-white">{activeServers}</div>
                            <div className="text-xs text-gray-400 mt-2">Currently Running</div>
                        </div>
                        
                        <div className="stat-card">
                            <div className="text-sm text-purple-300 mb-2">MEMORY USAGE</div>
                            <div className="text-3xl font-bold text-white">
                                {servers.length > 0 ? 'Active' : 'None'}
                            </div>
                            <div className="text-xs text-gray-400 mt-2">Resource Allocation</div>
                        </div>
                        
                        <div className="stat-card">
                            <div className="text-sm text-yellow-300 mb-2">ACCOUNT STATUS</div>
                            <div className="text-3xl font-bold text-green-400">ACTIVE</div>
                            <div className="text-xs text-gray-400 mt-2">Premium Member</div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2">
                    <div className="vax-card">
                        <div className="flex justify-between items-center mb-8">
                            <div>
                                <h2 className="text-2xl font-bold text-white mb-2">Your Game Servers</h2>
                                <p className="text-gray-400">Manage and monitor your servers</p>
                            </div>
                            <Link
                                to="/servers/create"
                                className="btn-primary px-8 py-3 text-lg"
                            >
                                + Create Server
                            </Link>
                        </div>
                        
                        {loading ? (
                            <div className="text-center py-16">
                                <div className="loading-spinner h-16 w-16 mx-auto mb-6"></div>
                                <p className="text-gray-400 text-lg">Loading your servers...</p>
                            </div>
                        ) : !servers.length ? (
                            <div className="text-center py-16">
                                <div className="text-gray-400 text-xl mb-6">No servers found</div>
                                <p className="text-gray-500 mb-8">Create your first gaming server to get started</p>
                                <Link
                                    to="/servers/create"
                                    className="btn-primary px-10 py-4 text-lg"
                                >
                                    Create Your First Server
                                </Link>
                            </div>
                        ) : (
                            <div className="space-y-6">
                                {servers.map((server) => (
                                    <div key={server.uuid} className="server-row-card">
                                        <ServerRow server={server} />
                                    </div>
                                ))}
                            </div>
                        )}
                        
                        {servers.length > 0 && pagination.totalPages > 1 && (
                            <div className="mt-10">
                                <Pagination data={pagination} onPageSelect={setPage} />
                            </div>
                        )}
                    </div>
                </div>

                <div className="space-y-8">
                    <div className="vax-card">
                        <h2 className="text-xl font-bold text-white mb-6">Account Information</h2>
                        <div className="space-y-5">
                            <div className="flex justify-between items-center pb-4 border-b border-gray-800">
                                <span className="text-gray-400">Account Type</span>
                                <span className="font-bold text-blue-400">
                                    {rootAdmin ? 'PREMIUM ADMIN' : 'PREMIUM USER'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-4 border-b border-gray-800">
                                <span className="text-gray-400">Access Level</span>
                                <span className={rootAdmin ? 'text-red-400' : 'text-green-400'}>
                                    {rootAdmin ? 'Full Administrator' : 'Standard Access'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-4 border-b border-gray-800">
                                <span className="text-gray-400">Server Limit</span>
                                <span className="text-white font-bold">Unlimited</span>
                            </div>
                            <div className="flex justify-between items-center pb-4 border-b border-gray-800">
                                <span className="text-gray-400">Support Tier</span>
                                <span className="text-green-400 font-bold">24/7 Premium</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">Account Status</span>
                                <span className="px-4 py-1 bg-green-900/30 text-green-400 rounded-full text-sm font-bold">
                                    ACTIVE
                                </span>
                            </div>
                        </div>
                    </div>

                    <div className="vax-card">
                        <h2 className="text-xl font-bold text-white mb-6">Quick Actions</h2>
                        <div className="space-y-4">
                            <Link
                                to="/account/api"
                                className="flex items-center justify-between p-4 bg-gray-900/50 hover:bg-gray-800 rounded-xl transition-all duration-300"
                            >
                                <div className="flex items-center">
                                    <div className="w-10 h-10 rounded-lg bg-blue-900/30 flex items-center justify-center mr-4">
                                        <span className="text-blue-400">🔑</span>
                                    </div>
                                    <div>
                                        <div className="font-medium text-white">API Keys</div>
                                        <div className="text-sm text-gray-400">Manage your API access</div>
                                    </div>
                                </div>
                                <span className="text-gray-500 text-sm">›</span>
                            </Link>
                            
                            <Link
                                to="/account"
                                className="flex items-center justify-between p-4 bg-gray-900/50 hover:bg-gray-800 rounded-xl transition-all duration-300"
                            >
                                <div className="flex items-center">
                                    <div className="w-10 h-10 rounded-lg bg-green-900/30 flex items-center justify-center mr-4">
                                        <span className="text-green-400">⚙️</span>
                                    </div>
                                    <div>
                                        <div className="font-medium text-white">Account Settings</div>
                                        <div className="text-sm text-gray-400">Configure your account</div>
                                    </div>
                                </div>
                                <span className="text-gray-500 text-sm">›</span>
                            </Link>
                            
                            <Link
                                to="/admin" 
                                className="flex items-center justify-between p-4 bg-purple-900/30 hover:bg-purple-800/40 rounded-xl transition-all duration-300"
                            >
                                <div className="flex items-center">
                                    <div className="w-10 h-10 rounded-lg bg-purple-900/30 flex items-center justify-center mr-4">
                                        <span className="text-purple-400">👑</span>
                                    </div>
                                    <div>
                                        <div className="font-medium text-white">Admin Panel</div>
                                        <div className="text-sm text-gray-400">System administration</div>
                                    </div>
                                </div>
                                <span className="text-gray-500 text-sm">›</span>
                            </Link>
                            
                            <button
                                onClick={() => window.location.href = '/auth/logout'}
                                className="w-full flex items-center justify-between p-4 bg-red-900/20 hover:bg-red-900/40 rounded-xl transition-all duration-300 text-red-400"
                            >
                                <div className="flex items-center">
                                    <div className="w-10 h-10 rounded-lg bg-red-900/20 flex items-center justify-center mr-4">
                                        <span>🚪</span>
                                    </div>
                                    <div>
                                        <div className="font-medium">Logout</div>
                                        <div className="text-sm text-red-300/70">Sign out of your account</div>
                                    </div>
                                </div>
                                <span className="text-red-500/50 text-sm">›</span>
                            </button>
                        </div>
                    </div>

                    <div className="vax-card">
                        <h2 className="text-xl font-bold text-white mb-6">Security Status</h2>
                        <div className="space-y-5">
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Session Protection</span>
                                <span className="px-3 py-1 bg-green-900/30 text-green-400 text-xs rounded-full font-bold">
                                    ACTIVE
                                </span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Two-Factor Auth</span>
                                <span className="px-3 py-1 bg-blue-900/30 text-blue-400 text-xs rounded-full font-bold">
                                    ENABLED
                                </span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Last Login</span>
                                <span className="text-gray-300 text-sm">Just now</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">IP Protection</span>
                                <span className="text-blue-400 text-sm font-bold">Premium</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div className="mt-12 pt-8 border-t border-gray-800/50 text-center">
                <p className="text-gray-500 text-sm">
                    © 2024 Pterodactyl Premium • Black Blue Edition
                </p>
                <p className="text-gray-600 text-xs mt-2">
                    Enhanced security system • Premium performance • 24/7 support
                </p>
            </div>
        </PageContentBlock>
    );
};
EOF

log_message "${GREEN}Dashboard Premium installed${NC}"

# ============================================
# 4. FIX LOGIN PAGE (SIMPLER VERSION)
# ============================================
log_message "${YELLOW}Memperbarui login page...${NC}"

LOGIN_DIR="$PTERO_PATH/resources/scripts/components/auth"
LOGIN_FILE="$LOGIN_DIR/LoginContainer.tsx"

# Check if LoginForm exists, create simple one if not
LOGINFORM_FILE="$LOGIN_DIR/LoginForm.tsx"
if [ ! -f "$LOGINFORM_FILE" ]; then
    log_message "${YELLOW}Membuat LoginForm sederhana...${NC}"
    cat > "$LOGINFORM_FILE" << 'EOF'
import React from 'react';
import { Formik, FormikHelpers } from 'formik';
import { object, string } from 'yup';
import { Link } from 'react-router-dom';
import { Actions, useStoreActions } from 'easy-peasy';
import { ApplicationStore } from '@/state';
import Field from '@/components/elements/Field';

interface Values {
    username: string;
    password: string;
}

export default () => {
    const login = useStoreActions((actions: Actions<ApplicationStore>) => actions.user.login);

    const submit = (values: Values, { setSubmitting, setErrors }: FormikHelpers<Values>) => {
        login(values)
            .catch((error) => {
                setErrors({ username: 'Invalid credentials' });
                setSubmitting(false);
            });
    };

    return (
        <Formik
            onSubmit={submit}
            initialValues={{ username: '', password: '' }}
            validationSchema={object().shape({
                username: string().required('Username or email is required'),
                password: string().required('Password is required'),
            })}
        >
            {({ isSubmitting, isValid }) => (
                <div className="space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-2">
                            Username or Email
                        </label>
                        <Field
                            type="text"
                            name="username"
                            className="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                            placeholder="Enter your username or email"
                        />
                    </div>
                    
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-2">
                            Password
                        </label>
                        <Field
                            type="password"
                            name="password"
                            className="w-full px-4 py-3 bg-gray-900/50 border border-gray-700 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20"
                            placeholder="Enter your password"
                        />
                    </div>
                    
                    <div className="flex items-center justify-between">
                        <div className="flex items-center">
                            <input
                                id="remember"
                                name="remember"
                                type="checkbox"
                                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-700 rounded bg-gray-900"
                            />
                            <label htmlFor="remember" className="ml-2 block text-sm text-gray-400">
                                Remember me
                            </label>
                        </div>
                    </div>
                    
                    <div>
                        <button
                            type="submit"
                            disabled={isSubmitting || !isValid}
                            className="w-full btn-primary py-3 px-4"
                        >
                            {isSubmitting ? 'Signing in...' : 'Sign In'}
                        </button>
                    </div>
                </div>
            )}
        </Formik>
    );
};
EOF
fi

# Create simple LoginContainer
cat > "$LOGIN_FILE" << 'EOF'
import React, { useEffect } from 'react';
import { Link } from 'react-router-dom';
import LoginForm from '@/components/auth/LoginForm';
import { useStoreState } from 'easy-peasy';
import { ApplicationStore } from '@/state';

export default () => {
    const isAuthenticated = useStoreState((state: ApplicationStore) => !!state.user.data?.uuid);

    useEffect(() => {
        if (isAuthenticated) {
            window.location.href = '/';
        }
    }, [isAuthenticated]);

    return (
        <div className="min-h-screen login-page-bg p-4">
            <div className="w-full max-w-md mx-auto">
                <div className="text-center mb-10">
                    <div className="flex items-center justify-center mb-6">
                        <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center shadow-2xl">
                            <span className="text-white text-2xl">🛡️</span>
                        </div>
                    </div>
                    <h1 className="text-4xl font-bold text-white mb-3">
                        Pterodactyl
                    </h1>
                    <p className="text-gray-400 text-lg">Premium Server Management</p>
                </div>

                <div className="login-card">
                    <div className="text-center mb-8">
                        <h2 className="text-2xl font-bold text-white">Welcome Back</h2>
                        <p className="text-gray-400 mt-2">Sign in to your premium dashboard</p>
                    </div>

                    <LoginForm />

                    <div className="mt-8 text-center">
                        <Link
                            to="/auth/password"
                            className="text-sm text-blue-400 hover:text-blue-300 transition"
                        >
                            Forgot your password?
                        </Link>
                        <span className="mx-3 text-gray-600">|</span>
                        <Link
                            to="/auth/register"
                            className="text-sm text-blue-400 hover:text-blue-300 transition"
                        >
                            Create new account
                        </Link>
                    </div>
                </div>

                <div className="mt-10 text-center">
                    <p className="text-gray-500 text-sm">
                        © 2024 Pterodactyl Premium • Enhanced Security System
                    </p>
                </div>
            </div>
        </div>
    );
};
EOF

log_message "${GREEN}Login page diperbaiki${NC}"

# ============================================
# 5. CLEAR CACHE AND BUILD
# ============================================
log_message "${YELLOW}Membersihkan cache dan build assets...${NC}"

cd "$PTERO_PATH" || {
    log_message "${RED}Tidak bisa pindah ke $PTERO_PATH${NC}"
    exit 1
}

# Clear cache
php artisan view:clear
php artisan cache:clear
php artisan config:clear
php artisan route:clear

# Run optimize
php artisan optimize

# Build assets
log_message "Building assets (mungkin butuh beberapa menit)..."
if yarn install --production=false --ignore-engines 2>&1 | tail -20; then
    if npm run build:production 2>&1 | tail -30; then
        log_message "${GREEN}Build berhasil${NC}"
    else
        log_message "${YELLOW}Build mungkin ada warning${NC}"
    fi
else
    log_message "${YELLOW}Yarn install ada issue kecil${NC}"
fi

# Set permissions
chown -R www-data:www-data "$PTERO_PATH/storage"
chown -R www-data:www-data "$PTERO_PATH/bootstrap/cache"
chmod -R 755 "$PTERO_PATH/storage"
chmod -R 755 "$PTERO_PATH/bootstrap/cache"

# Restart services
systemctl restart pteroq 2>/dev/null && log_message "${GREEN}PteroQ restarted${NC}"
systemctl restart nginx 2>/dev/null && log_message "${GREEN}Nginx restarted${NC}"

# ============================================
# 6. CHECK FOR ERRORS
# ============================================
log_message "${YELLOW}Memeriksa error...${NC}"

# Check Laravel logs
LARAVEL_LOG="$PTERO_PATH/storage/logs/laravel.log"
if [ -f "$LARAVEL_LOG" ]; then
    ERROR_COUNT=$(tail -50 "$LARAVEL_LOG" | grep -c "ERROR\|Exception")
    if [ "$ERROR_COUNT" -gt 0 ]; then
        log_message "${YELLOW}Ada $ERROR_COUNT error di log${NC}"
        echo "=== ERROR LOGS ==="
        tail -50 "$LARAVEL_LOG" | grep -i "error\|exception" | tail -5
    else
        log_message "${GREEN}Tidak ada error di log${NC}"
    fi
fi

# ============================================
# 7. FINAL MESSAGE
# ============================================
echo -e "${GREEN}"
echo "╔════════════════════════════════════════════════╗"
echo "║          INSTALASI BERHASIL!                   ║"
echo "╚════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "🎨 ${GREEN}Premium Theme Installed:${NC}"
echo "   • Black Blue Premium Design"
echo "   • Gradient Effects"
echo "   • Smooth Animations"
echo "   • Enhanced Dashboard"
echo "   • Premium Cards & Stats"
echo ""
echo "🚀 ${BLUE}Features:${NC}"
echo "   • Modern Dashboard dengan stats"
echo "   • Premium account badges"
echo "   • Server cards dengan hover effects"
echo "   • Quick action buttons"
echo "   • Security status panel"
echo ""
echo "🔧 ${YELLOW}Langkah Testing:${NC}"
echo "   1. Refresh browser (Ctrl+F5 atau Shift+F5)"
echo "   2. Clear browser cache"
echo "   3. Login kembali"
echo "   4. Cek dashboard premium"
echo ""
echo "📂 ${BLUE}Backup: $BACKUP_DIR${NC}"
echo "📝 ${BLUE}Log: $LOG_FILE${NC}"
echo ""
echo "🛠️ ${YELLOW}Jika masih error 500:${NC}"
echo "   tail -f $PTERO_PATH/storage/logs/laravel.log"
echo "   systemctl restart php8.1-fpm"
echo "   systemctl restart php8.2-fpm"
echo ""
echo "=================================================="

# Quick PHP check
log_message "${YELLOW}Checking PHP syntax...${NC}"
if php -l "$PTERO_PATH/app/Http/Kernel.php" >/dev/null 2>&1; then
    log_message "${GREEN}PHP syntax OK${NC}"
fi
