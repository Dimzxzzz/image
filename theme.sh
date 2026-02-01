#!/bin/bash
PTERO_PATH="/var/www/pterodactyl"
DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"
CSS_FILE="$PTERO_PATH/resources/scripts/index.css"

if [ ! -d "$PTERO_PATH" ]; then
    echo "Folder Pterodactyl tidak ditemukan di $PTERO_PATH"
    exit 1
fi

echo "--- Memulai Instalasi VaxStresser Theme ---"

cp $DASHBOARD_FILE "${DASHBOARD_FILE}.bak"
cp $CSS_FILE "${CSS_FILE}.bak"
echo "[1/4] Backup file asli berhasil."

cat << 'EOF' > $CSS_FILE
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

/* Sidebar Styling */
aside {
    background-color: var(--bg-secondary) !important;
    border-right: 1px solid #2d2d2d !important;
}

/* Custom Card */
.vax-card {
    background-color: var(--bg-card);
    border: 1px solid #2d2d2d;
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1.5rem;
}

.vax-row {
    display: flex;
    justify-content: space-between;
    padding: 10px 0;
    border-bottom: 1px solid #2d2d2d;
    font-size: 14px;
}

.logout-btn {
    background: #471818 !important;
    color: #ff4d4d !important;
    border-radius: 10px !important;
}
EOF
echo "[2/4] Custom CSS disuntikkan."

cat << 'EOF' > $DASHBOARD_FILE
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
    const [ page, setPage ] = useState(1);
    const [ servers, setServers ] = useState<Server[]>([]);
    const [ pagination, setPagination ] = useState({ total: 0, count: 0, perPage: 0, currentPage: 1, totalPages: 1 });
    
    const rootAdmin = useStoreState((state: ApplicationStore) => state.user.data?.rootAdmin);
    const username = useStoreState((state: ApplicationStore) => state.user.data?.username);

    useEffect(() => {
        clearFlashes('dashboard');
        getServers({ page }).then(data => {
            setServers(data.items);
            setPagination(data.pagination);
        }).catch(error => {
            console.error(error);
            addFlash({ key: 'dashboard', type: 'error', message: 'Gagal memuat server.' });
        });
    }, [ page ]);

    return (
        <PageContentBlock title={'Dashboard'} showFlashKey={'dashboard'}>
            <div className={'grid grid-cols-1 md:grid-cols-3 gap-6 mb-8'}>
                <div className={'vax-card col-span-1 md:col-span-2'}>
                    <h1 className={'text-xl font-bold'}>Welcome back, {username}!</h1>
                    <p className={'text-gray-400 text-sm'}>Manage your servers and resources from here.</p>
                </div>
                <div className={'vax-card'}>
                    <p className={'text-gray-400 text-xs uppercase tracking-widest'}>Active Ongoing</p>
                    <h2 className={'text-2xl font-bold'}>{servers.length}</h2>
                </div>
            </div>

            <div className={'vax-card'}>
                <h2 className={'text-sm font-bold uppercase text-gray-500 mb-4'}>Plan Info</h2>
                <div className={'vax-row'}>
                    <span>PLAN</span>
                    <span className={rootAdmin ? 'text-red-500 font-bold' : 'text-blue-400 font-bold'}>
                        {rootAdmin ? 'VAX ADMIN' : 'USER MEMBER'}
                    </span>
                </div>
                <div className={'vax-row'}>
                    <span>ACCESS</span>
                    <span>{rootAdmin ? 'Full Administrator' : 'Standard Client'}</span>
                </div>
                <div className={'vax-row'}>
                    <span>STATUS</span>
                    <span className={'text-green-400'}>Active</span>
                </div>
            </div>

            <div className={'grid grid-cols-1 gap-4'}>
                {!servers.length ? (
                    <p className={'text-center text-gray-400'}>Kamu tidak memiliki server.</p>
                ) : (
                    servers.map((server, index) => (
                        <ServerRow key={server.uuid} server={server} className={index > 0 ? 'mt-2' : ''} />
                    ))
                )}
            </div>
            <Pagination data={pagination} onPageSelect={setPage} />
        </PageContentBlock>
    );
};
EOF
echo "[3/4] File Dashboard Container berhasil diperbarui."

echo "[4/4] Memulai proses Build (Yarn)..."
cd $PTERO_PATH
yarn install
yarn build:production

echo "--- INSTALASI SELESAI ---"
echo "Silakan cek dashboard Pterodactyl Anda."
