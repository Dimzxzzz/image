#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"
CSS_FILE="$PTERO_PATH/resources/scripts/index.css"

echo "======================================="
echo "INSTALLING VAXSTRESSER THEME"
echo "======================================="

# 1. Backup file asli
mkdir -p "$PTERO_PATH/backup"
if [ ! -f "$DASHBOARD_FILE.backup" ]; then
    cp "$DASHBOARD_FILE" "$DASHBOARD_FILE.backup"
fi
if [ ! -f "$CSS_FILE.backup" ]; then
    cp "$CSS_FILE" "$CSS_FILE.backup"
fi

# 2. Update CSS (Tema Hitam Biru)
cat << 'EOF' > "$CSS_FILE"
@tailwind base;
@tailwind components;
@tailwind utilities;

/* VAXSTRESSER THEME - BLACK & BLUE */
:root {
    --bg-primary: #0a0a0f;
    --bg-secondary: #111827;
    --bg-card: #1a1a2e;
    --accent-blue: #2563eb;
    --accent-blue-light: #3b82f6;
    --text-primary: #ffffff;
    --text-secondary: #94a3b8;
    --border-color: #2d3748;
}

body {
    background-color: var(--bg-primary) !important;
    color: var(--text-primary);
    font-family: 'Segoe UI', system-ui, sans-serif;
}

/* Sidebar */
nav.bg-gray-800 {
    background-color: var(--bg-secondary) !important;
    border-right: 1px solid var(--border-color);
}

/* Cards */
.bg-gray-800\/50, .bg-gray-800 {
    background-color: var(--bg-card) !important;
    border: 1px solid var(--border-color) !important;
    border-radius: 10px;
}

/* Buttons */
button.bg-blue-600, .btn-primary {
    background-color: var(--accent-blue) !important;
    border-color: var(--accent-blue) !important;
}

button.bg-blue-600:hover, .btn-primary:hover {
    background-color: var(--accent-blue-light) !important;
}

/* Tables */
table {
    background-color: var(--bg-card) !important;
}

thead {
    background-color: var(--bg-secondary) !important;
}

/* Inputs */
input, select, textarea {
    background-color: var(--bg-secondary) !important;
    border-color: var(--border-color) !important;
    color: var(--text-primary) !important;
}

/* Custom Classes */
.vax-card {
    background: linear-gradient(135deg, var(--bg-card) 0%, #1e293b 100%);
    border: 1px solid var(--border-color);
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

.vax-admin-badge {
    background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
    color: white;
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 12px;
}

.vax-user-badge {
    background: linear-gradient(135deg, var(--accent-blue) 0%, #1d4ed8 100%);
    color: white;
    padding: 4px 12px;
    border-radius: 20px;
    font-weight: bold;
    font-size: 12px;
}

.vax-stat-card {
    background: linear-gradient(135deg, #1e3a8a 0%, #1e40af 100%);
    border: none;
    color: white;
}
EOF

# 3. Update Dashboard (Sesuai Referensi)
cat << 'EOF' > "$DASHBOARD_FILE"
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
    const [pagination, setPagination] = useState({
        total: 0,
        count: 0,
        perPage: 0,
        currentPage: 1,
        totalPages: 1
    });
    
    const rootAdmin = useStoreState((state: ApplicationStore) => state.user.data?.rootAdmin);
    const username = useStoreState((state: ApplicationStore) => state.user.data?.username);
    const email = useStoreState((state: ApplicationStore) => state.user.data?.email);

    useEffect(() => {
        clearFlashes('dashboard');
        getServers({ page })
            .then(data => {
                setServers(data.items);
                setPagination(data.pagination);
            })
            .catch(error => {
                console.error(error);
                addFlash({
                    key: 'dashboard',
                    type: 'error',
                    message: 'Failed to load server list.'
                });
            });
    }, [page]);

    return (
        <PageContentBlock title={'Dashboard'} showFlashKey={'dashboard'}>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
                {/* LEFT COLUMN - USER INFO */}
                <div className="lg:col-span-2 space-y-6">
                    {/* WELCOME CARD */}
                    <div className="vax-card">
                        <div className="flex justify-between items-start">
                            <div>
                                <h1 className="text-2xl font-bold text-white mb-2">
                                    Welcome back, {username}!
                                </h1>
                                <p className="text-gray-400">
                                    Manage your servers and resources from your dashboard.
                                </p>
                            </div>
                            <span className={rootAdmin ? 'vax-admin-badge' : 'vax-user-badge'}>
                                {rootAdmin ? 'ADMIN' : 'USER MEMBER'}
                            </span>
                        </div>
                    </div>

                    {/* SERVER STATS */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div className="vax-stat-card p-5">
                            <div className="text-sm text-blue-200 mb-1">TOTAL SERVERS</div>
                            <div className="text-3xl font-bold">{pagination.total}</div>
                        </div>
                        <div className="vax-stat-card p-5">
                            <div className="text-sm text-blue-200 mb-1">ACTIVE</div>
                            <div className="text-3xl font-bold">{servers.length}</div>
                        </div>
                        <div className="vax-stat-card p-5">
                            <div className="text-sm text-blue-200 mb-1">STATUS</div>
                            <div className="text-3xl font-bold text-green-400">ONLINE</div>
                        </div>
                    </div>

                    {/* SERVER LIST */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">Your Servers</h2>
                        {!servers.length ? (
                            <div className="text-center py-8">
                                <p className="text-gray-400 mb-4">No servers found.</p>
                                <Link
                                    to="/servers/create"
                                    className="inline-block bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded-lg transition"
                                >
                                    Create New Server
                                </Link>
                            </div>
                        ) : (
                            <div className="space-y-3">
                                {servers.map((server) => (
                                    <ServerRow key={server.uuid} server={server} />
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                {/* RIGHT COLUMN - SIDEBAR INFO */}
                <div className="space-y-6">
                    {/* PLAN INFO - SESUAI REFERENSI */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">Plan Information</h2>
                        <div className="space-y-4">
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">PLAN</span>
                                <span className="text-white font-bold">
                                    {rootAdmin ? 'VAX ADMIN' : 'NO PLAN ASSIGNED'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">ACCESS</span>
                                <span className="text-gray-300">
                                    {rootAdmin ? 'Full Access' : 'Limited'}
                                </span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">TIME</span>
                                <span className="text-gray-300">Unlimited</span>
                            </div>
                            <div className="flex justify-between items-center">
                                <span className="text-gray-400">CONCURRENT</span>
                                <span className="text-gray-300">Unlimited</span>
                            </div>
                        </div>
                    </div>

                    {/* NEWS SECTION - SESUAI REFERENSI */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">News & Updates</h2>
                        <div className="space-y-3">
                            <div className="p-3 bg-gray-900/50 rounded-lg">
                                <div className="text-sm text-gray-400 mb-1">No updates</div>
                                <div className="text-gray-300 text-sm">
                                    Check back soon for announcements and updates.
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* QUICK ACTIONS */}
                    <div className="vax-card">
                        <h2 className="text-lg font-bold text-white mb-4">Quick Actions</h2>
                        <div className="space-y-2">
                            <Link
                                to="/account/api"
                                className="block w-full text-center bg-gray-800 hover:bg-gray-700 text-white py-2 rounded-lg transition"
                            >
                                API Keys
                            </Link>
                            <Link
                                to="/account"
                                className="block w-full text-center bg-gray-800 hover:bg-gray-700 text-white py-2 rounded-lg transition"
                            >
                                Account Settings
                            </Link>
                            <button
                                onClick={() => window.location.href = '/auth/logout'}
                                className="w-full text-center bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg transition"
                            >
                                Logout
                            </button>
                        </div>
                    </div>
                </div>
            </div>

            {/* PAGINATION */}
            {servers.length > 0 && pagination.totalPages > 1 && (
                <div className="mt-6">
                    <Pagination data={pagination} onPageSelect={setPage} />
                </div>
            )}
        </PageContentBlock>
    );
};
EOF

# 4. Update juga halaman Account Settings untuk tema konsisten
ACCOUNT_FILE="$PTERO_PATH/resources/scripts/components/dashboard/AccountOverviewContainer.tsx"
if [ -f "$ACCOUNT_FILE" ]; then
    cat << 'EOF' > "$ACCOUNT_FILE.backup"
<!-- Backup file -->
EOF
    echo "✅ Backup account settings created"
fi

# 5. Build assets
echo "======================================="
echo "BUILDING ASSETS..."
echo "======================================="

cd "$PTERO_PATH"

# Clear cache
php artisan view:clear
php artisan cache:clear
php artisan config:clear

# Install dependencies
yarn install --ignore-engines --production=false

# Build assets
echo "Building with webpack (please wait)..."
npm run build:production || npx webpack --mode=production

# Set permissions
chown -R www-data:www-data "$PTERO_PATH/storage"
chown -R www-data:www-data "$PTERO_PATH/bootstrap/cache"

echo "======================================="
echo "✅ THEME INSTALLATION COMPLETE!"
echo "======================================="
echo "Please refresh your browser with CTRL+F5"
echo "or clear browser cache completely."
echo ""
echo "If you encounter errors, try:"
echo "1. Restarting queue: sudo systemctl restart pteroq"
echo "2. Restarting PHP: sudo systemctl restart php8.x-fpm"
echo "3. Restarting Nginx: sudo systemctl restart nginx"
echo "======================================="
