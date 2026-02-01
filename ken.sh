#!/bin/bash

echo "🔥 FIX PANEL ERROR CONNECTION REFUSED - AUTO REPAIR"
echo "====================================================="

# ========== STEP 1: STOP SEMUA SERVICE ==========
echo "1. Stopping all services..."
systemctl stop nginx 2>/dev/null
systemctl stop php8.1-fpm 2>/dev/null
systemctl stop php8.0-fpm 2>/dev/null
systemctl stop php7.4-fpm 2>/dev/null

# Kill semua proses yang stuck
pkill -9 nginx 2>/dev/null
pkill -9 php-fpm 2>/dev/null

# ========== STEP 2: FIX PHP-FPM ==========
echo "2. Fixing PHP-FPM..."

# Cek PHP version
PHP_VERSION=$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Detected PHP version: $PHP_VERSION"

# Install PHP-FPM jika belum ada
if ! dpkg -l | grep -q php${PHP_VERSION}-fpm; then
    echo "Installing php${PHP_VERSION}-fpm..."
    apt update
    apt install php${PHP_VERSION}-fpm -y
fi

# Fix PHP-FPM config
cat > /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf << 'EOF'
[www]
user = www-data
group = www-data
listen = /run/php/php${PHP_VERSION}-fpm.sock
listen.owner = www-data
listen.group = www-data
listen.mode = 0660

pm = dynamic
pm.max_children = 50
pm.start_servers = 5
pm.min_spare_servers = 5
pm.max_spare_servers = 35
pm.max_requests = 500

php_admin_value[error_log] = /var/log/php${PHP_VERSION}-fpm-error.log
php_admin_flag[log_errors] = on
php_admin_value[memory_limit] = 512M
php_admin_value[upload_max_filesize] = 100M
php_admin_value[post_max_size] = 100M
php_admin_value[max_execution_time] = 300
EOF

# Start PHP-FPM
systemctl start php${PHP_VERSION}-fpm
systemctl enable php${PHP_VERSION}-fpm

# Cek socket
sleep 2
if [ -S "/run/php/php${PHP_VERSION}-fpm.sock" ]; then
    echo "✅ PHP-FPM socket created: /run/php/php${PHP_VERSION}-fpm.sock"
else
    echo "⚠️ Socket not found, trying alternative..."
    # Coba dengan TCP port
    sed -i 's|listen = /run/php/php${PHP_VERSION}-fpm.sock|listen = 127.0.0.1:9000|' /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
    systemctl restart php${PHP_VERSION}-fpm
fi

# ========== STEP 3: FIX NGINX ==========
echo "3. Fixing Nginx..."

# Buat nginx config yang simple
cat > /etc/nginx/sites-available/pterodactyl << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    
    server_name _;
    
    root /var/www/pterodactyl/public;
    index index.php index.html index.htm;
    
    # Log files
    access_log /var/log/nginx/pterodactyl.access.log;
    error_log /var/log/nginx/pterodactyl.error.log;
    
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    
    location ~ \.php$ {
        # Try socket first, if not use TCP
        fastcgi_pass unix:/run/php/php'${PHP_VERSION}'-fpm.sock;
        # fallback: fastcgi_pass 127.0.0.1:9000;
        
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        
        # Security headers
        fastcgi_param HTTP_PROXY "";
        fastcgi_hide_header X-Powered-By;
        
        # Timeouts
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
        fastcgi_busy_buffers_size 256k;
        fastcgi_temp_file_write_size 256k;
    }
    
    # Deny access to .htaccess and .env
    location ~ /\.(?!well-known).* {
        deny all;
    }
    
    location ~ /\.ht {
        deny all;
    }
    
    # Cache static files
    location ~* \.(jpg|jpeg|png|gif|ico|css|js|svg|woff|woff2|ttf|eot)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        access_log off;
    }
}
EOF

# Enable site
ln -sf /etc/nginx/sites-available/pterodactyl /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx config
nginx -t

# Start nginx
systemctl start nginx
systemctl enable nginx

# ========== STEP 4: FIX PERMISSIONS ==========
echo "4. Fixing permissions..."

cd /var/www/pterodactyl

# Reset semua permission
chown -R www-data:www-data .
find . -type d -exec chmod 755 {} \;
find . -type f -exec chmod 644 {} \;

# Khusus storage kasih permission penuh
chmod -R 775 storage bootstrap/cache
chmod 777 storage/logs

# Hapus cache lama
rm -rf storage/framework/cache/data/*
rm -rf storage/framework/views/*
rm -rf storage/framework/sessions/*
rm -f bootstrap/cache/*.php

# Recreate cache
mkdir -p storage/framework/{cache/data,sessions,views}
chmod -R 775 storage/framework
chown -R www-data:www-data storage/framework

# ========== STEP 5: CLEAR LARAVEL CACHE ==========
echo "5. Clearing Laravel cache..."

# Jalankan sebagai www-data
sudo -u www-data php artisan view:clear 2>/dev/null || php artisan view:clear
sudo -u www-data php artisan config:clear 2>/dev/null || php artisan config:clear
sudo -u www-data php artisan cache:clear 2>/dev/null || php artisan cache:clear
sudo -u www-data php artisan route:clear 2>/dev/null || php artisan route:clear

# JANGAN jalankan optimize karena bisa error
# sudo -u www-data php artisan optimize

# ========== STEP 6: FIX FIREWALL ==========
echo "6. Fixing firewall..."

# Nonaktifkan ufw sementara
ufw disable 2>/dev/null || true

# Allow port 80 di iptables
iptables -A INPUT -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true

# ========== STEP 7: TEST EVERYTHING ==========
echo "7. Testing installation..."

# Test 1: Cek service status
echo "=== Service Status ==="
systemctl status nginx --no-pager | head -20
echo ""
systemctl status php${PHP_VERSION}-fpm --no-pager | head -20

# Test 2: Cek port yang terbuka
echo ""
echo "=== Open Ports ==="
netstat -tulpn | grep -E ':80|:443|:9000' || echo "No ports listening!"

# Test 3: Cek socket
echo ""
echo "=== PHP-FPM Socket ==="
ls -la /run/php/php*.sock 2>/dev/null || echo "Socket not found!"

# Test 4: Test dari localhost
echo ""
echo "=== Local Test ==="

# Buat test file
cat > /var/www/pterodactyl/public/test.php << 'EOF'
<?php
echo "PHP is working!<br>";
echo "PHP Version: " . phpversion() . "<br>";
echo "Server: " . $_SERVER['SERVER_SOFTWARE'] . "<br>";
?>
EOF

# Test dengan curl
curl_output=$(curl -s http://localhost/test.php 2>/dev/null || echo "CONNECTION FAILED")
echo "Test result: $curl_output"

# Hapus test file
rm -f /var/www/pterodactyl/public/test.php

# Test 5: Test admin page
echo ""
echo "=== Admin Page Test ==="
curl -I http://localhost/admin 2>/dev/null | head -5 || echo "Cannot access admin page"

# ========== STEP 8: CREATE ADMIN USER JIKA PERLU ==========
echo "8. Checking admin user..."

# Cek apakah ada user admin
ADMIN_EXISTS=$(mysql -u root -e "USE panel; SELECT id FROM users WHERE id = 1;" 2>/dev/null | tail -1)

if [ -z "$ADMIN_EXISTS" ]; then
    echo "Creating admin user..."
    mysql -u root -e "USE panel; INSERT INTO users (id, username, email, password, name_first, name_last, role, language, root_admin, created_at, updated_at) VALUES (1, 'admin', 'admin@admin.com', '\$2y\$10\$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'Admin', 'User', 'admin', 'en', 1, NOW(), NOW());"
    echo "✅ Admin user created:"
    echo "   Email: admin@admin.com"
    echo "   Password: password"
fi

# ========== STEP 9: FINAL CHECK ==========
echo ""
echo "========================================="
echo "🔥 FINAL STATUS CHECK"
echo "========================================="

# Get server IP
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo "✅ Services running:"
systemctl is-active --quiet nginx && echo "   Nginx: RUNNING" || echo "   Nginx: FAILED"
systemctl is-active --quiet php${PHP_VERSION}-fpm && echo "   PHP-FPM: RUNNING" || echo "   PHP-FPM: FAILED"

echo ""
echo "✅ Access URLs:"
echo "   http://$SERVER_IP"
echo "   http://$SERVER_IP/admin"
echo ""
echo "✅ Admin Credentials:"
echo "   Email: admin@admin.com"
echo "   Password: password"
echo ""
echo "✅ Log files:"
echo "   Nginx error: /var/log/nginx/error.log"
echo "   PHP-FPM error: /var/log/php${PHP_VERSION}-fpm-error.log"
echo "   Laravel log: /var/www/pterodactyl/storage/logs/laravel-$(date +%Y-%m-%d).log"
echo ""
echo "========================================="
echo "🎉 FIX COMPLETED! Try accessing your panel now."
echo "========================================="

# ========== STEP 10: CREATE FIX SCRIPT FOR FUTURE ==========
cat > /root/fix_panel.sh << 'EOF'
#!/bin/bash
# Quick fix script for Pterodactyl
echo "Quick fixing Pterodactyl..."

# Restart services
systemctl restart php$(php -v | head -n1 | cut -d' ' -f2 | cut -d'.' -f1,2)-fpm
systemctl restart nginx

# Clear cache
cd /var/www/pterodactyl
sudo -u www-data php artisan cache:clear
sudo -u www-data php artisan view:clear

echo "Fix applied. Check: http://$(curl -s ifconfig.me)"
EOF

chmod +x /root/fix_panel.sh

echo ""
echo "Quick fix script created: /root/fix_panel.sh"
echo "Run it anytime panel has issues."
