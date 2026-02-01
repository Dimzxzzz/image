#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"
CSS_FILE="$PTERO_PATH/resources/scripts/index.css"

echo "======================================="
echo "Memperbaiki & Menginstall VaxStresser Theme"
echo "======================================="

# 1. Backup file asli jika belum ada
if [ ! -f "$DASHBOARD_FILE.bak" ]; then
    cp "$DASHBOARD_FILE" "$DASHBOARD_FILE.bak"
    echo "✅ Backup file dashboard dibuat: $DASHBOARD_FILE.bak"
fi

if [ ! -f "$CSS_FILE.bak" ]; then
    cp "$CSS_FILE" "$CSS_FILE.bak"
    echo "✅ Backup file CSS dibuat: $CSS_FILE.bak"
fi

# 2. Inject CSS (Deep Dark Theme)
echo "🔄 Mengupdate CSS tema..."
cat << 'EOF' > "$CSS_FILE"
@tailwind base;
@tailwind components;
@tailwind utilities;

:root {
    --bg-main: #0d0e12;
    --bg-secondary: #15161d;
    --bg-card: #1b1c24;
}

body {
    background-color: var(--bg-main) !important;
    font-family: 'Inter', sans-serif;
    color: #e2e8f0;
}

aside {
    background-color: var(--bg-secondary) !important;
    border-right: 1px solid #2d2d2d !important;
}

.vax-card {
    background-color: var(--bg-card);
    border: 1px solid #2d2d2d;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}

/* Tambahan untuk konsistensi tema */
.bg-gray-800 {
    background-color: var(--bg-card) !important;
}

.border-gray-700 {
    border-color: #2d2d2d !important;
}
EOF

# 3. Inject Dashboard Code dengan Role Admin/User
echo "🔄 Mengupdate dashboard dengan role system..."
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
                    message: 'Gagal memuat daftar server.'
                });
            });
    }, [page]);

    return (
        <PageContentBlock title={'Dashboard'} showFlashKey={'dashboard'}>
            {/* Info Plan & User */}
            <div className="vax-card mb-8">
                <h2 className="text-lg font-bold text-white mb-4">Informasi Akun</h2>
                <div className="space-y-4">
                    <div className="flex justify-between items-center border-b border-gray-700 pb-2">
                        <span className="text-gray-400">Username</span>
                        <span className="text-white font-medium">{username}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-gray-700 pb-2">
                        <span className="text-gray-400">Email</span>
                        <span className="text-white font-medium">{email}</span>
                    </div>
                    <div className="flex justify-between items-center border-b border-gray-700 pb-2">
                        <span className="text-gray-400">Status Akun</span>
                        <span className="px-3 py-1 rounded-full text-xs font-bold bg-green-900 text-green-300">
                            Active
                        </span>
                    </div>
                    <div className="flex justify-between items-center">
                        <span className="text-gray-400">Role</span>
                        <span className={`px-3 py-1 rounded-full text-xs font-bold ${rootAdmin ? 'bg-red-900 text-red-300' : 'bg-blue-900 text-blue-300'}`}>
                            {rootAdmin ? 'VAX ADMIN' : 'USER MEMBER'}
                        </span>
                    </div>
                </div>
            </div>

            {/* Server List */}
            <div className="grid grid-cols-1 gap-4">
                {!servers.length ? (
                    <div className="vax-card text-center">
                        <p className="text-gray-400 py-6">Tidak ada server yang aktif.</p>
                        <button
                            onClick={() => window.location.href = '/servers/create'}
                            className="bg-blue-600 hover:bg-blue-700 text-white font-medium py-2 px-6 rounded-lg transition"
                        >
                            Buat Server Baru
                        </button>
                    </div>
                ) : (
                    servers.map((server) => (
                        <ServerRow key={server.uuid} server={server} />
                    ))
                )}
            </div>

            {/* Pagination */}
            {servers.length > 0 && (
                <div className="mt-6">
                    <Pagination data={pagination} onPageSelect={setPage} />
                </div>
            )}
        </PageContentBlock>
    );
};
EOF

# 4. Build assets
echo "🚀 Memulai proses build..."
cd "$PTERO_PATH" || exit

echo "1️⃣ Membersihkan cache Laravel..."
php artisan view:clear
php artisan cache:clear
php artisan config:clear

echo "2️⃣ Menginstall dependencies..."
yarn install --production=false --ignore-engines

echo "3️⃣ Building assets dengan webpack (mungkin memerlukan waktu)..."
if [ -f "node_modules/.bin/webpack" ]; then
    npm run build:production || npx webpack --mode=production
else
    npx webpack --mode=production
fi

echo "4️⃣ Memberikan permission yang tepat..."
chown -R www-data:www-data "$PTERO_PATH"

echo "======================================="
echo "✅ INSTALASI SELESAI!"
echo "======================================="
echo "Silakan refresh browser dengan CTRL+F5"
echo "atau clear cache browser Anda."
echo "======================================="
