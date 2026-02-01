cd /var/www/pterodactyl

# Pastikan folder bisa ditulis
chown -R www-data:www-data /var/www/pterodactyl/*
chmod -R 775 storage bootstrap/cache

# Injeksi menu Security tepat di bawah menu Settings
sed -i '/fa-gears/!b;n;a\        <li class="{{ request()->is("admin/security*") ? "active" : "" }}">\n            <a href="{{ route("admin.security") }}">\n                <i class="fa fa-shield"></i> <span>Security Settings</span>\n            </a>\n        </li>' resources/views/layouts/admin.blade.php

# Tambahkan rute Security ke paling bawah file admin.php
echo -e "\nRoute::get('/security', function () { return view('admin.security.index'); })->name('admin.security');" >> routes/admin.php
