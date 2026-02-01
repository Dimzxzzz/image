#!/bin/bash

PTERO_PATH="/var/www/pterodactyl"
DASHBOARD_FILE="$PTERO_PATH/resources/scripts/components/dashboard/DashboardContainer.tsx"
CSS_FILE="$PTERO_PATH/resources/scripts/index.css"

echo "--- Memperbaiki & Menginstall VaxStresser Theme ---"

# 1. Inject CSS (Deep Dark)
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
EOF

# 2. Inject Dashboard Code (Full & Fixed)
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
            addFlash({ key: 'dashboard', type: 'error', message: 'Gagal memuat daftar server.' });
        });
    }, [ page ]);

    return (
        <PageContentBlock title={'Dashboard'} showFlashKey={'dashboard'}>
            <div className={'bg-gray-800/50 p-6 rounded-xl border border-gray-700 mb-8'}>
                <div className={'flex flex-col'}>
                    <h2 className={'text-sm font-bold uppercase text-gray-500 tracking-widest mb-4'}>Plan Info</h2>
                    <div className={'space-y-3'}>
                        <div className={'flex justify-between items-center border-b border-gray-700/50 pb-2'}>
                            <span className={'text-gray-400 text-sm'}>PLAN</span>
                            <span className={`font-bold ${rootAdmin ? 'text-red-500' : 'text-blue-400'}`}>
                                {rootAdmin ? 'VAX ADMIN' : 'USER MEMBER'}
                            </span>
                        </div>
                        <div className={'flex justify-between items-center border-b border-gray-700/50 pb-2'}>
                            <span className={'text-gray-400 text-sm'}>ACCESS</span>
                            <span className={'text-gray-200'}>{rootAdmin ? 'Full Administrator' : 'Standard Client'}</span>
                        </div>
                        <div className={'flex justify-between items-center'}>
                            <span className={'text-gray-400 text-sm'}>STATUS</span>
                            <span className={'text-green-400 font-medium'}>Active</span>
                        </div>
                    </div>
                </div>
            </div>

            <div className={'grid grid-cols-1 gap-4'}>
                {!servers.length ? (
                    <p className={'text-center text-gray-400 py-10'}>Kamu tidak memiliki server aktif.</p>
                ) : (
                    servers.map((server) => (
                        <ServerRow key={server.uuid} server={server} />
                    ))
                )}
            </div>
            <Pagination data={pagination} onPageSelect={setPage} />
        </PageContentBlock>
    );
};
EOF

# 3. Build Ulang
cd $PTERO_PATH
php artisan view:clear
php artisan cache:clear
yarn install --ignore-engines
yarn build:production --ignore-engines

echo "--- SELESAI! SILAKAN REFRESH BROWSER (CTRL+F5) ---"
