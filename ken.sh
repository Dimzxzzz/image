#!/bin/bash
echo "🔥 FIX PHP-FPM & NGINX SOCKET ERROR"

# 1. Stop nginx dulu
systemctl stop nginx

# 2. Install PHP-FPM jika belum
if ! systemctl is-active --quiet php8.1-fpm; then
    echo "Installing php8.1-fpm..."
    apt update
    apt install php8.1-fpm php8.1-common php8.1-mysql php8.1-mbstring php8.1-xml php8.1-curl php8.1-zip php8.1-gd -y
fi

# 3. Start PHP-FPM
systemctl start php8.1-fpm
systemctl enable php8.1-fpm

# 4. Cek socket path
echo "Checking PHP-FPM socket..."
SOCKET_PATH=""
if [ -S "/run/php/php8.1-fpm.sock" ]; then
    SOCKET_PATH="/run/php/php8.1-fpm.sock"
elif [ -S "/var/run/php/php8.1-fpm.sock" ]; then
    SOCKET_PATH="/var/run/php/php8.1-fpm.sock"
else
    # Cari socket
    SOCKET_PATH=$(find /run /var/run -name "*.sock" 2>/dev/null | grep php | head -1)
fi

echo "Socket found at: $SOCKET_PATH"

# 5. Update nginx config
cat > /etc/nginx/sites-available/pterodactyl.conf << EOF
server {
    listen 80;
    listen [::]:80;
    server_name _;
    root /var/www/pterodactyl/public;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)\$;
        fastcgi_pass unix:$SOCKET_PATH;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param HTTP_PROXY "";
        fastcgi_intercept_errors off;
        fastcgi_buffer_size 16k;
        fastcgi_buffers 4 16k;
        fastcgi_connect_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_read_timeout 300;
    }

    location ~ /\.ht {
        deny all;
    }
    
    location ~ /\.(?!well-known).* {
        deny all;
    }
}
EOF

# 6. Test dan restart nginx
nginx -t
systemctl restart nginx

# 7. Cek semua service
echo "Checking services..."
systemctl status php8.1-fpm
systemctl status nginx

# 8. Test dengan curl
echo "Testing with curl..."
curl -I http://localhost

echo ""
echo "✅ PHP-FPM FIXED! Sekarang coba akses panel."
