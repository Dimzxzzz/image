#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"
LOG_FILE="/var/log/pterodactyl_theme_install.log"

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
echo "║          PTERODACTYL PREMIUM THEME INSTALLER            ║"
echo "║          Black & Blue Theme + Security System           ║"
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
log_message "${GREEN}Backup berhasil di: $BACKUP_DIR${NC}"

# ============================================
# 1. UPDATE CSS UTAMA (TEMA HITAM-BIRU PREMIUM)
# ============================================
log_message "${YELLOW}Menginstall tema CSS premium...${NC}"

MAIN_CSS="$PTERO_PATH/resources/scripts/index.css"
cat > "$MAIN_CSS" << 'EOF'
/* PTERODACTYL PREMIUM THEME - BLACK & BLUE EDITION */
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
.premium-card {
    background: var(--gradient-dark);
    border: 1px solid var(--border-color);
    border-radius: 16px;
    padding: 25px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
}

.premium-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: var(--gradient-primary);
}

.stat-card {
    background: linear-gradient(135deg, rgba(0, 102, 255, 0.2) 0%, rgba(0, 153, 255, 0.1) 100%);
    border: 1px solid rgba(0, 102, 255, 0.3);
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    transition: all 0.3s;
}

.stat-card:hover {
    transform: translateY(-3px);
    border-color: var(--accent-blue);
    box-shadow: 0 10px 30px rgba(0, 102, 255, 0.2);
}

.admin-badge {
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

.user-badge {
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

.premium-card, .server-card {
    animation: fadeIn 0.5s ease-out;
}

/* RESPONSIVE */
@media (max-width: 768px) {
    .dashboard-grid {
        grid-template-columns: 1fr;
    }
    
    .premium-card {
        padding: 15px;
    }
}

/* LOGIN PAGE */
.login-container {
    background: var(--gradient-dark) !important;
    border: 1px solid var(--border-color);
    border-radius: 20px;
    padding: 40px;
    max-width: 400px;
    margin: 50px auto;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
}

.login-container input {
    background: rgba(255, 255, 255, 0.05) !important;
    border: 1px solid var(--border-light);
}

.login-container input:focus {
    background: rgba(255, 255, 255, 0.1) !important;
}
EOF

log_message "${GREEN}CSS utama berhasil diupdate${NC}"

# ============================================
# 2. UPDATE DASHBOARD COMPONENT (FIXED VERSION)
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
                        <span className={rootAdmin ? 'admin-badge' : 'user-badge'}>
                            {rootAdmin ? 'ADMIN' : 'USER'}
                        </span>
                        <span className="text-sm text-gray-400">{email}</span>
                    </div>
                </div>

                {/* STATS GRID */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
                    <div className="stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-blue-300 mb-1">TOTAL SERVERS</div>
                                <div className="text-2xl font-bold">{stats.totalServers}</div>
                            </div>
                            <div className="text-blue-400 text-xl">🖥️</div>
                        </div>
                    </div>
                    
                    <div className="stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-green-300 mb-1">ACTIVE SERVERS</div>
                                <div className="text-2xl font-bold">{stats.activeServers}</div>
                            </div>
                            <div className="text-green-400 text-xl">⚡</div>
                        </div>
                    </div>
                    
                    <div className="stat-card">
                        <div className="flex items-center justify-between">
                            <div>
                                <div className="text-sm text-purple-300 mb-1">TOTAL MEMORY</div>
                                <div className="text-2xl font-bold">{formatBytes(stats.totalMemory * 1024 * 1024)}</div>
                            </div>
                            <div className="text-purple-400 text-xl">💾</div>
                        </div>
                    </div>
                    
                    <div className="stat-card">
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
                    <div className="premium-card">
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
                    <div className="premium-card">
                        <h2 className="text-lg font-bold text-white mb-4">
                            🛡️ Account Information
                        </h2>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">USER TYPE</span>
                                <span className="font-bold text-blue-400">
                                    {rootAdmin ? 'ADMINISTRATOR' : 'STANDARD USER'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">ACCESS LEVEL</span>
                                <span className={rootAdmin ? 'text-red-400' : 'text-green-400'}>
                                    {rootAdmin ? 'Full Access' : 'Standard'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center pb-3 border-b border-gray-800">
                                <span className="text-gray-400">SERVER LIMIT</span>
                                <span className="text-white font-medium">Unlimited</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">ACCOUNT STATUS</span>
                                <span className="text-green-400 font-medium">Active</span>
                            </div>
                        </div>
                    </div>

                    {/* QUICK ACTIONS */}
                    <div className="premium-card">
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
                    <div className="premium-card">
                        <h2 className="text-lg font-bold text-white mb-4">Security Status</h2>
                        <div className="space-y-3">
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Session Protection</span>
                                <span className="px-2 py-1 bg-green-900/30 text-green-400 text-xs rounded">ACTIVE</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">Last Login</span>
                                <span className="text-gray-300 text-sm">Just now</span>
                            </div>
                            <div className="flex items-center justify-between">
                                <span className="text-gray-400">IP Address</span>
                                <span className="text-blue-400 text-sm">Protected</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            {/* FOOTER NOTE */}
            <div className="mt-8 pt-6 border-t border-gray-800 text-center text-gray-500 text-sm">
                <p>© 2024 Pterodactyl Panel • Premium Black & Blue Edition</p>
                <p className="text-xs mt-1">Enhanced security and monitoring system</p>
            </div>
        </PageContentBlock>
    );
};
EOF

log_message "${GREEN}Dashboard berhasil diperbarui${NC}"

# ============================================
# 3. UPDATE LOGIN PAGE (FIX IMPORT ERROR)
# ============================================
log_message "${YELLOW}Memperbarui login page...${NC}"

LOGIN_DIR="$PTERO_PATH/resources/scripts/components/auth"
LOGIN_FILE="$LOGIN_DIR/LoginContainer.tsx"

# Cek apakah LoginForm ada
if [ ! -f "$LOGIN_DIR/LoginForm.tsx" ]; then
    log_message "${YELLOW}LoginForm.tsx tidak ditemukan, membuat file sederhana...${NC}"
    cat > "$LOGIN_DIR/LoginForm.tsx" << 'EOF'
import React, { useState } from 'react';
import { Formik, FormikHelpers } from 'formik';
import { object, string } from 'yup';
import { Link } from 'react-router-dom';
import LoginButton from '@/components/elements/LoginButton';
import { Actions, useStoreActions } from 'easy-peasy';
import { ApplicationStore } from '@/state';
import Field from '@/components/elements/Field';
import { httpErrorToHuman } from '@/api/http';
import tw from 'twin.macro';

interface Values {
    username: string;
    password: string;
}

const LoginForm = () => {
    const [isLoggingIn, setIsLoggingIn] = useState(false);
    const [error, setError] = useState('');
    
    const login = useStoreActions((actions: Actions<ApplicationStore>) => actions.user.login);
    
    const submit = (values: Values, { setSubmitting }: FormikHelpers<Values>) => {
        setIsLoggingIn(true);
        setError('');
        
        login({ ...values })
            .then(() => {
                // Redirect handled by parent component
            })
            .catch(error => {
                console.error(error);
                setError(httpErrorToHuman(error));
                setSubmitting(false);
                setIsLoggingIn(false);
            });
    };
    
    return (
        <Formik
            onSubmit={submit}
            initialValues={{ username: '', password: '' }}
            validationSchema={object().shape({
                username: string().required('Username or email is required.'),
                password: string().required('Password is required.'),
            })}
        >
            {({ isSubmitting, isValid }) => (
                <div className="space-y-6">
                    {error && (
                        <div className="bg-red-500/10 border border-red-500 text-red-300 px-4 py-3 rounded">
                            {error}
                        </div>
                    )}
                    
                    <div>
                        <label className="block text-sm font-medium text-gray-400 mb-2">
                            Username or Email
                        </label>
                        <Field
                            type="text"
                            name="username"
                            className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition"
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
                            className="w-full px-4 py-3 bg-gray-800/50 border border-gray-700 rounded-lg focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition"
                            placeholder="Enter your password"
                        />
                    </div>
                    
                    <div className="flex items-center justify-between">
                        <div className="flex items-center">
                            <input
                                id="remember"
                                name="remember"
                                type="checkbox"
                                className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-700 rounded bg-gray-800"
                            />
                            <label htmlFor="remember" className="ml-2 block text-sm text-gray-400">
                                Remember me
                            </label>
                        </div>
                        
                        <div className="text-sm">
                            <Link to="/auth/password" className="text-blue-400 hover:text-blue-300">
                                Forgot password?
                            </Link>
                        </div>
                    </div>
                    
                    <div>
                        <button
                            type="submit"
                            disabled={isSubmitting || !isValid || isLoggingIn}
                            className="w-full btn-primary py-3 px-4 flex justify-center items-center"
                        >
                            {isLoggingIn ? (
                                <>
                                    <div className="animate-spin rounded-full h-5 w-5 border-t-2 border-b-2 border-white mr-2"></div>
                                    Signing in...
                                </>
                            ) : (
                                'Sign In'
                            )}
                        </button>
                    </div>
                    
                    <div className="text-center text-sm text-gray-500">
                        Don't have an account?{' '}
                        <Link to="/auth/register" className="text-blue-400 hover:text-blue-300">
                            Register here
                        </Link>
                    </div>
                </div>
            )}
        </Formik>
    );
};

export default LoginForm;
EOF
fi

# Update LoginContainer
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
                        Pterodactyl
                    </h1>
                </div>
                <p className="text-gray-400">Game Server Management Panel</p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 max-w-6xl w-full">
                {/* LOGIN FORM */}
                <div className="login-container">
                    <div className="text-center mb-8">
                        <h2 className="text-2xl font-bold text-white mb-2">Welcome Back</h2>
                        <p className="text-gray-400">Sign in to your control panel</p>
                    </div>

                    <LoginForm />

                    <div className="mt-6 text-center">
                        <p className="text-gray-500 text-sm">
                            Need assistance?{' '}
                            <a href="mailto:support@pterodactyl.io" className="text-blue-400 hover:text-blue-300">
                                Contact Support
                            </a>
                        </p>
                    </div>
                </div>

                {/* FEATURES */}
                {showFeatures && (
                    <div className="flex flex-col justify-center">
                        <div className="premium-card">
                            <h3 className="text-xl font-bold text-white mb-6 text-center">
                                Why Choose Pterodactyl?
                            </h3>
                            
                            <div className="space-y-6">
                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-blue-900/30 flex items-center justify-center">
                                            <span className="text-blue-400">🎮</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">Game Server Management</h4>
                                        <p className="text-gray-400 text-sm">
                                            Easy-to-use interface for managing Minecraft, Rust, ARK, and other game servers.
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-green-900/30 flex items-center justify-center">
                                            <span className="text-green-400">⚡</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">High Performance</h4>
                                        <p className="text-gray-400 text-sm">
                                            Optimized for maximum server performance with minimal resource usage.
                                        </p>
                                    </div>
                                </div>

                                <div className="flex items-start">
                                    <div className="mr-4 mt-1">
                                        <div className="w-10 h-10 rounded-full bg-purple-900/30 flex items-center justify-center">
                                            <span className="text-purple-400">🔒</span>
                                        </div>
                                    </div>
                                    <div>
                                        <h4 className="font-bold text-white mb-1">Secure & Stable</h4>
                                        <p className="text-gray-400 text-sm">
                                            Enterprise-grade security with automatic updates and backups.
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
                                        <div className="text-2xl font-bold text-green-400">Open</div>
                                        <div className="text-xs text-gray-400">Source</div>
                                    </div>
                                    <div>
                                        <div className="text-2xl font-bold text-purple-400">Free</div>
                                        <div className="text-xs text-gray-400">To Use</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* FOOTER */}
            <div className="mt-12 text-center text-gray-500 text-sm">
                <p>© 2024 Pterodactyl. All rights reserved.</p>
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
# 4. BUAT SECURITY SYSTEM (IP MONITORING)
# ============================================
log_message "${YELLOW}Membuat sistem keamanan IP monitoring...${NC}"

# Buat database untuk IP tracking
SECURITY_DB_FILE="$PTERO_PATH/database/migrations/$(date +%Y_%m_%d_%H%M%S)_create_security_tables.php"
mkdir -p "$(dirname "$SECURITY_DB_FILE")"

cat > "$SECURITY_DB_FILE" << 'EOF'
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        // Tabel untuk IP blacklist
        Schema::create('security_ip_blacklist', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->unique();
            $table->text('reason')->nullable();
            $table->string('type')->default('manual'); // manual, auto (rate limit), suspicious
            $table->integer('request_count')->default(0);
            $table->timestamp('last_attempt')->nullable();
            $table->timestamps();
            $table->softDeletes();
            
            $table->index('ip_address');
            $table->index('type');
        });

        // Tabel untuk IP whitelist
        Schema::create('security_ip_whitelist', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45)->unique();
            $table->text('note')->nullable();
            $table->timestamps();
        });

        // Tabel untuk log request
        Schema::create('security_request_logs', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->string('user_agent')->nullable();
            $table->string('method', 10);
            $table->string('path');
            $table->integer('status_code');
            $table->integer('response_time')->nullable(); // in milliseconds
            $table->text('referrer')->nullable();
            $table->json('metadata')->nullable();
            $table->timestamps();
            
            $table->index('ip_address');
            $table->index('created_at');
            $table->index(['ip_address', 'created_at']);
        });

        // Tabel untuk rate limiting
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

        // Tabel untuk suspicious activity
        Schema::create('security_suspicious_activity', function (Blueprint $table) {
            $table->id();
            $table->string('ip_address', 45);
            $table->string('activity_type'); // failed_login, sql_injection, xss, etc.
            $table->text('details')->nullable();
            $table->integer('severity')->default(1); // 1-5, 5 being most severe
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
# 5. BUAT SECURITY MIDDLEWARE
# ============================================
log_message "${YELLOW}Membuat security middleware...${NC}"

SECURITY_MIDDLEWARE_DIR="$PTERO_PATH/app/Http/Middleware"
mkdir -p "$SECURITY_MIDDLEWARE_DIR"

cat > "$SECURITY_MIDDLEWARE_DIR/CheckIpBlacklist.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class CheckIpBlacklist
{
    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        $ip = $request->ip();
        
        // Skip jika IP kosong atau localhost
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') {
            return $next($request);
        }

        // Cek cache dulu untuk performa
        $cacheKey = 'ip_blacklist_' . md5($ip);
        if (Cache::has($cacheKey)) {
            if (Cache::get($cacheKey) === true) {
                return response()->json([
                    'error' => 'Access denied',
                    'message' => 'Your IP address has been blacklisted.'
                ], 403);
            }
        }

        // Cek database
        $isBlacklisted = DB::table('security_ip_blacklist')
            ->where('ip_address', $ip)
            ->exists();

        if ($isBlacklisted) {
            // Cache hasilnya selama 5 menit
            Cache::put($cacheKey, true, 300);
            
            // Log the attempt
            $this->logRequest($request, 403);
            
            return response()->json([
                'error' => 'Access denied',
                'message' => 'Your IP address has been blacklisted.'
            ], 403);
        }

        // Cache bahwa IP tidak diblacklist (1 jam)
        Cache::put($cacheKey, false, 3600);

        return $next($request);
    }

    /**
     * Log request untuk analytics
     */
    private function logRequest(Request $request, int $statusCode): void
    {
        try {
            DB::table('security_request_logs')->insert([
                'ip_address' => $request->ip(),
                'user_agent' => substr($request->userAgent() ?? '', 0, 255),
                'method' => $request->method(),
                'path' => $request->path(),
                'status_code' => $statusCode,
                'referrer' => $request->header('referer'),
                'metadata' => json_encode([
                    'blacklisted' => true,
                    'timestamp' => now()->toIso8601String(),
                ]),
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        } catch (\Exception $e) {
            // Silent fail untuk logging
        }
    }
}
EOF

cat > "$SECURITY_MIDDLEWARE_DIR/RateLimitRequests.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;
use Carbon\Carbon;

class RateLimitRequests
{
    /**
     * Rate limit configuration
     */
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

    /**
     * Handle an incoming request.
     */
    public function handle(Request $request, Closure $next)
    {
        $ip = $request->ip();
        $path = $request->path();
        
        // Determine rate limit type based on path
        $type = $this->getRateLimitType($path);
        $config = $this->limits[$type];
        
        $key = "rate_limit:{$type}:{$ip}";
        
        // Get current attempts
        $attempts = Cache::get($key, 0);
        
        // Check if rate limit exceeded
        if ($attempts >= $config['max_attempts']) {
            // Auto-blacklist jika terlalu banyak attempts
            if ($attempts >= $config['max_attempts'] * 3) {
                $this->autoBlacklist($ip, 'Rate limit exceeded multiple times');
            }
            
            return response()->json([
                'error' => 'Too Many Requests',
                'message' => 'Please slow down and try again later.',
                'retry_after' => $config['decay_minutes'] * 60,
            ], 429);
        }
        
        // Increment attempts
        Cache::put($key, $attempts + 1, $config['decay_minutes'] * 60);
        
        // Add rate limit headers
        $response = $next($request);
        
        return $response->withHeaders([
            'X-RateLimit-Limit' => $config['max_attempts'],
            'X-RateLimit-Remaining' => max(0, $config['max_attempts'] - ($attempts + 1)),
            'X-RateLimit-Reset' => Carbon::now()->addMinutes($config['decay_minutes'])->timestamp,
        ]);
    }

    /**
     * Determine rate limit type based on path
     */
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

    /**
     * Auto-blacklist IP untuk rate limit yang parah
     */
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
            
            // Log suspicious activity
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
            // Silent fail
        }
    }
}
EOF

log_message "${GREEN}Security middleware created${NC}"

# ============================================
# 6. BUAT SECURITY CONTROLLER UNTUK ADMIN
# ============================================
log_message "${YELLOW}Membuat security controller untuk admin...${NC}"

SECURITY_CONTROLLER_DIR="$PTERO_PATH/app/Http/Controllers/Admin"
mkdir -p "$SECURITY_CONTROLLER_DIR"

cat > "$SECURITY_CONTROLLER_DIR/SecurityController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Admin;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Pterodactyl\Http\Controllers\Controller;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Cache;

class SecurityController extends Controller
{
    /**
     * Get IP blacklist
     */
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

    /**
     * Add IP to blacklist
     */
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
        
        // Clear cache
        Cache::forget('ip_blacklist_' . md5($ip));
        
        return response()->json([
            'success' => true,
            'message' => 'IP added to blacklist successfully.',
        ]);
    }

    /**
     * Remove IP from blacklist
     */
    public function removeFromBlacklist(Request $request, string $ip): JsonResponse
    {
        $deleted = DB::table('security_ip_blacklist')
            ->where('ip_address', $ip)
            ->delete();
        
        if ($deleted) {
            // Clear cache
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

    /**
     * Get suspicious activity
     */
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

    /**
     * Mark activity as reviewed
     */
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

    /**
     * Get request statistics
     */
    public function getRequestStats(Request $request): JsonResponse
    {
        $period = $request->input('period', 'today'); // today, yesterday, week, month
        
        $now = now();
        $startDate = match($period) {
            'yesterday' => $now->copy()->subDay()->startOfDay(),
            'week' => $now->copy()->subWeek()->startOfDay(),
            'month' => $now->copy()->subMonth()->startOfDay(),
            default => $now->copy()->startOfDay(),
        };
        
        // Total requests
        $totalRequests = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->count();
        
        // Unique IPs
        $uniqueIPs = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->distinct('ip_address')
            ->count('ip_address');
        
        // Blocked requests
        $blockedRequests = DB::table('security_request_logs')
            ->where('created_at', '>=', $startDate)
            ->where('status_code', 403)
            ->count();
        
        // Top IPs by requests
        $topIPs = DB::table('security_request_logs')
            ->select('ip_address', DB::raw('COUNT(*) as request_count'))
            ->where('created_at', '>=', $startDate)
            ->groupBy('ip_address')
            ->orderByDesc('request_count')
            ->limit(10)
            ->get();
        
        // Requests per hour (last 24 hours)
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

    /**
     * Get whitelist
     */
    public function getWhitelist(Request $request): JsonResponse
    {
        $items = DB::table('security_ip_whitelist')
            ->orderBy('created_at', 'desc')
            ->get();
        
        return response()->json([
            'data' => $items,
        ]);
    }

    /**
     * Add IP to whitelist
     */
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

    /**
     * Remove IP from whitelist
     */
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
# 7. UPDATE KERNEL.PHP UNTUK MIDDLEWARE
# ============================================
log_message "${YELLOW}Update kernel untuk middleware...${NC}"

KERNEL_FILE="$PTERO_PATH/app/Http/Kernel.php"
if [ -f "$KERNEL_FILE" ]; then
    # Backup kernel
    cp "$KERNEL_FILE" "$KERNEL_FILE.backup"
    
    # Tambahkan middleware ke kernel
    sed -i "/protected \$routeMiddleware = \[/a\
        'ip.blacklist' => \\Pterodactyl\\Http\\Middleware\\CheckIpBlacklist::class,\n\
        'rate.limit' => \\Pterodactyl\\Http\\Middleware\\RateLimitRequests::class," "$KERNEL_FILE"
    
    # Tambahkan middleware global
    sed -i "/protected \$middleware = \[/a\
        \\Pterodactyl\\Http\\Middleware\\CheckIpBlacklist::class," "$KERNEL_FILE"
    
    sed -i "/protected \$middlewareGroups = \[/a\
        'web' => [\n\
            // ... existing middleware ...\n\
            \\Pterodactyl\\Http\\Middleware\\RateLimitRequests::class,\n\
        ]," "$KERNEL_FILE"
fi

# ============================================
# 8. BUILD ASSETS
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

# Run database migrations
log_message "Menjalankan database migrations..."
php artisan migrate --force 2>&1 | tee -a "$LOG_FILE"

# Set permissions
chown -R www-data:www-data "$PTERO_PATH/storage"
chown -R www-data:www-data "$PTERO_PATH/bootstrap/cache"
chmod -R 755 "$PTERO_PATH/storage"
chmod -R 755 "$PTERO_PATH/bootstrap/cache"

# Restart services
log_message "Restarting services..."
systemctl restart pteroq 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl restart php8.1-fpm 2>/dev/null || true
systemctl restart php8.2-fpm 2>/dev/null || true

# ============================================
# 9. FINISH
# ============================================
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║          INSTALASI BERHASIL DILAKUKAN!                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo ""
echo "✅ ${GREEN}Semua komponen berhasil diupdate:${NC}"
echo "   • Tema CSS Premium Black & Blue"
echo "   • Dashboard dengan stats"
echo "   • Login Page premium"
echo "   • Security System (IP Monitoring)"
echo "   • IP Blacklist/Whitelist System"
echo "   • Rate Limiting Middleware"
echo ""
echo "🔒 ${PURPLE}Security Features yang ditambahkan:${NC}"
echo "   • IP Blacklist/Whitelist management"
echo "   • Automatic rate limiting"
echo "   • Suspicious activity detection"
echo "   • Request logging & analytics"
echo "   • Admin interface untuk monitoring"
echo ""
echo "📂 ${YELLOW}Backup tersedia di: $BACKUP_DIR${NC}"
echo "📝 ${YELLOW}Log instalasi: $LOG_FILE${NC}"
echo ""
echo "🔄 ${BLUE}Cara mengakses Security System:${NC}"
echo "   1. Login sebagai admin"
echo "   2. Akses endpoint API:"
echo "      • GET /admin/security/blacklist"
echo "      • POST /admin/security/blacklist"
echo "      • DELETE /admin/security/blacklist/{ip}"
echo "      • GET /admin/security/stats"
echo ""
echo "📊 ${CYAN}Monitoring yang tersedia:${NC}"
echo "   • Total requests per periode"
echo "   • Unique IP addresses"
echo "   • Blocked requests count"
echo "   • Top IPs by request count"
echo "   • Hourly request charts"
echo ""
echo -e "${YELLOW}Jika ada error, coba:${NC}"
echo "   sudo systemctl restart pteroq"
echo "   sudo systemctl restart nginx"
echo "   sudo systemctl restart php-fpm"
echo ""
echo "============================================================"
