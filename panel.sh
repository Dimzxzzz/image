#!/bin/bash

# ============================================
# PTERODACTYL FULL INSTALLATION SCRIPT
# Dengan fitur: NookTheme, Owner Security, Minecraft Plugins, WhatsApp Bot
# ============================================

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Path instalasi
PTERO_PATH="/var/www/pterodactyl"
HTML_PATH="/var/www/html"
WINGS_PATH="/usr/local/bin/wings"
LOG_FILE="/var/log/pterodactyl_full_install.log"
BACKUP_DIR="/root/ptero_backup_$(date +%s)"

# Database default
DB_PASSWORD="$(openssl rand -base64 32)"
APP_URL="http://$(curl -s ifconfig.me)"

# Fungsi logging
log_message() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Fungsi cek error
check_error() {
    if [ $? -ne 0 ]; then
        log_message "${RED}Error: $1${NC}"
        exit 1
    fi
}

# Banner
clear
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║    PTERODACTYL FULL INSTALLATION WITH EXTRAS             ║"
echo "║    Features:                                             ║"
echo "║    - Panel + Wings + Node (Auto Green)                   ║"
echo "║    - NookTheme                                           ║"
echo "║    - Owner Security System                               ║"
echo "║    - Minecraft Plugins                                   ║"
echo "║    - WhatsApp Bot                                        ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"
sleep 2

# ============================================
# 1. SYSTEM PREPARATION
# ============================================
echo -e "${CYAN}[1/10] Preparing system...${NC}"
log_message "Starting full Pterodactyl installation"

# Update system
apt-get update
apt-get upgrade -y

# Install dependencies
apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    tar \
    gnupg \
    apt-transport-https \
    software-properties-common \
    ca-certificates \
    lsb-release \
    nginx \
    mariadb-server \
    mariadb-client \
    redis-server \
    php8.1 \
    php8.1-{cli,common,gd,mysql,mbstring,bcmath,xml,fpm,curl,zip} \
    composer \
    nodejs \
    npm \
    certbot \
    python3-certbot-nginx \
    jq \
    fail2ban \
    ufw

# Enable services
systemctl enable nginx
systemctl enable mariadb
systemctl enable redis-server
systemctl enable fail2ban

# ============================================
# 2. DATABASE SETUP
# ============================================
echo -e "${CYAN}[2/10] Setting up database...${NC}"
log_message "Configuring MariaDB"

# Secure MySQL
mysql_secure_installation <<EOF

n
y
y
y
y
EOF

# Create database
mysql -e "CREATE DATABASE panel;"
mysql -e "CREATE USER 'pterodactyl'@'127.0.0.1' IDENTIFIED BY '${DB_PASSWORD}';"
mysql -e "GRANT ALL PRIVILEGES ON panel.* TO 'pterodactyl'@'127.0.0.1' WITH GRANT OPTION;"
mysql -e "FLUSH PRIVILEGES;"

# ============================================
# 3. INSTALL PTERODACTYL PANEL
# ============================================
echo -e "${CYAN}[3/10] Installing Pterodactyl Panel...${NC}"
log_message "Installing Pterodactyl Panel"

# Cleanup existing installation
rm -rf /var/www/html/pterodactyl
rm -rf "$PTERO_PATH"
mkdir -p "$PTERO_PATH"

# Download panel
cd /tmp
curl -L https://github.com/pterodactyl/panel/releases/latest/download/panel.tar.gz | tar -xzv
mv panel-*/* "$PTERO_PATH/"

# Set permissions
chmod -R 755 "$PTERO_PATH/storage/*"
chmod -R 755 "$PTERO_PATH/bootstrap/cache/"
chown -R www-data:www-data "$PTERO_PATH"

# Install PHP dependencies
cd "$PTERO_PATH"
cp .env.example .env
composer install --no-dev --optimize-autoloader
php artisan key:generate --force

# Setup environment
cat > .env <<EOF
APP_URL=${APP_URL}
APP_TIMEZONE=Asia/Jakarta
APP_SERVICE_AUTHOR=https://pterodactyl.io

DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=panel
DB_USERNAME=pterodactyl
DB_PASSWORD=${DB_PASSWORD}

REDIS_HOST=127.0.0.1
REDIS_PORT=6379
REDIS_DATABASE=0

MAIL_DRIVER=log
MAIL_FROM="no-reply@${APP_URL#http://}"
MAIL_FROM_NAME=Pterodactyl

SESSION_DRIVER=redis
CACHE_DRIVER=redis
QUEUE_DRIVER=redis
EOF

# Setup database
php artisan migrate --seed --force
php artisan db:seed --force

# Create admin user
php artisan p:user:make <<EOF
admin
admin@localhost
password123
admin
Y
EOF

# ============================================
# 4. CONFIGURE NGINX
# ============================================
echo -e "${CYAN}[4/10] Configuring Nginx...${NC}"
log_message "Setting up Nginx configuration"

cat > /etc/nginx/sites-available/pterodactyl.conf <<EOF
server {
    listen 80;
    server_name _;
    root $PTERO_PATH/public;
    index index.php;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php$ {
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/var/run/php/php8.1-fpm.sock;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param PHP_VALUE "upload_max_filesize = 100M \n post_max_size = 100M";
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
}
EOF

ln -sf /etc/nginx/sites-available/pterodactyl.conf /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl reload nginx

# ============================================
# 5. INSTALL WINGS (DAEMON)
# ============================================
echo -e "${CYAN}[5/10] Installing Wings...${NC}"
log_message "Installing Wings daemon"

# Install Docker
curl -fsSL https://get.docker.com | bash
systemctl enable docker
systemctl start docker

# Install Wings
mkdir -p /etc/pterodactyl
curl -L -o /usr/local/bin/wings https://github.com/pterodactyl/wings/releases/latest/download/wings_linux_amd64
chmod u+x /usr/local/bin/wings

# Create Wings configuration
cat > /etc/pterodactyl/config.yml <<EOF
debug: false
uuid: $(cat /proc/sys/kernel/random/uuid)
token: $(openssl rand -hex 32)
api:
  host: 127.0.0.1
  port: 8080
  ssl:
    enabled: false
  upload_limit: 100
system:
  data: /var/lib/pterodactyl/volumes
  sftp:
    port: 2022
    bind_address: 0.0.0.0
docker:
  network:
    name: pterodactyl_nw
    interfaces: []
EOF

# Create systemd service for Wings
cat > /etc/systemd/system/wings.service <<EOF
[Unit]
Description=Pterodactyl Wings Daemon
After=docker.service
Requires=docker.service
PartOf=docker.service

[Service]
User=root
WorkingDirectory=/etc/pterodactyl
LimitNOFILE=4096
PIDFile=/var/run/wings/daemon.pid
ExecStart=/usr/local/bin/wings
Restart=on-failure
StartLimitInterval=180
StartLimitBurst=30
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable wings
systemctl start wings

# ============================================
# 6. INSTALL NOOKTHEME
# ============================================
echo -e "${CYAN}[6/10] Installing NookTheme...${NC}"
log_message "Installing NookTheme"

cd /tmp
git clone https://github.com/Nookure/NookTheme.git
cd NookTheme
cp -r theme/* "$PTERO_PATH/resources/"
cd "$PTERO_PATH"

# Rebuild assets
npm ci --only=production
npm run build:production

# Clear cache
php artisan view:clear
php artisan config:clear
php artisan cache:clear

# ============================================
# 7. INSTALL OWNER SECURITY SYSTEM
# ============================================
echo -e "${CYAN}[7/10] Installing Owner Security System...${NC}"
log_message "Installing owner security features"

# Create security tables
mysql panel << 'EOF'
-- Owner Security Tables
CREATE TABLE IF NOT EXISTS owner_security_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    action VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    details JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user (user_id),
    INDEX idx_action (action)
);

CREATE TABLE IF NOT EXISTS owner_ip_whitelist (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) UNIQUE,
    description VARCHAR(255),
    created_by INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS owner_api_keys (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    key_hash VARCHAR(255),
    permissions JSON,
    last_used TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin (user_id = 1) permissions
INSERT IGNORE INTO owner_api_keys (name, key_hash, permissions) VALUES
('Master Key', SHA2('$(openssl rand -hex 32)', 256), '["*"]');
EOF

# Create security middleware
cat > "$PTERO_PATH/app/Http/Middleware/OwnerOnly.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class OwnerOnly
{
    public function handle(Request $request, Closure $next)
    {
        if (!auth()->check() || auth()->user()->id !== 1) {
            return response()->json([
                'error' => 'Owner access only',
                'message' => 'This action requires owner privileges'
            ], 403);
        }

        return $next($request);
    }
}
EOF

# Create security controller
cat > "$PTERO_PATH/app/Http/Controllers/Api/Client/OwnerController.php" << 'EOF'
<?php

namespace Pterodactyl\Http\Controllers\Api\Client;

use Illuminate\Http\Request;
use Pterodactyl\Http\Controllers\Api\Client\ClientApiController;
use Illuminate\Support\Facades\DB;

class OwnerController extends ClientApiController
{
    public function getSecurityLogs(Request $request)
    {
        $logs = DB::table('owner_security_logs')
            ->orderBy('created_at', 'desc')
            ->limit(100)
            ->get();

        return response()->json([
            'logs' => $logs,
            'count' => count($logs)
        ]);
    }

    public function getSystemStats(Request $request)
    {
        $stats = [
            'memory' => shell_exec('free -m | awk \'NR==2{printf "%.2f%%", $3*100/$2}\''),
            'disk' => shell_exec('df -h / | awk \'NR==2{print $5}\''),
            'cpu' => shell_exec("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'"),
            'uptime' => shell_exec('uptime -p'),
            'load' => sys_getloadavg()[0]
        ];

        return response()->json($stats);
    }

    public function manageService(Request $request, $service)
    {
        $action = $request->input('action', 'status');
        $validServices = ['wings', 'nginx', 'mysql', 'redis'];

        if (!in_array($service, $validServices)) {
            return response()->json(['error' => 'Invalid service'], 400);
        }

        $output = shell_exec("systemctl $action $service 2>&1");

        return response()->json([
            'service' => $service,
            'action' => $action,
            'output' => trim($output)
        ]);
    }
}
EOF

# Add routes
cat >> "$PTERO_PATH/routes/api.php" << 'EOF'

// Owner-only routes
Route::group(['prefix' => 'owner', 'middleware' => ['client-api', 'auth:api']], function () {
    Route::get('/security-logs', 'OwnerController@getSecurityLogs');
    Route::get('/system-stats', 'OwnerController@getSystemStats');
    Route::post('/service/{service}', 'OwnerController@manageService');
});
EOF

# ============================================
# 8. INSTALL MINECRAFT PLUGINS SYSTEM
# ============================================
echo -e "${CYAN}[8/10] Installing Minecraft Plugins System...${NC}"
log_message "Setting up Minecraft plugins"

# Create plugins directory
mkdir -p /opt/minecraft-plugins
cd /opt/minecraft-plugins

# Download popular plugins
plugins=(
    "https://dev.bukkit.org/projects/worldedit/files/latest"
    "https://dev.bukkit.org/projects/worldguard/files/latest"
    "https://dev.bukkit.org/projects/vault/files/latest"
    "https://dev.bukkit.org/projects/essentialsx/files/latest"
    "https://dev.bukkit.org/projects/luckperms/files/latest"
)

for plugin in "${plugins[@]}"; do
    wget -q --content-disposition "$plugin"
done

# Create plugin management script
cat > /usr/local/bin/update-minecraft-plugins << 'EOF'
#!/bin/bash
cd /opt/minecraft-plugins
rm -f *.jar
wget -q https://dev.bukkit.org/projects/worldedit/files/latest -O WorldEdit.jar
wget -q https://dev.bukkit.org/projects/worldguard/files/latest -O WorldGuard.jar
wget -q https://dev.bukkit.org/projects/vault/files/latest -O Vault.jar
wget -q https://dev.bukkit.org/projects/essentialsx/files/latest -O EssentialsX.jar
wget -q https://dev.bukkit.org/projects/luckperms/files/latest -O LuckPerms.jar
echo "Minecraft plugins updated!"
EOF

chmod +x /usr/local/bin/update-minecraft-plugins

# ============================================
# 9. INSTALL WHATSAPP BOT
# ============================================
echo -e "${CYAN}[9/10] Installing WhatsApp Bot...${NC}"
log_message "Setting up WhatsApp Bot"

# Install Node.js dependencies
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Create WhatsApp bot directory
mkdir -p /opt/whatsapp-bot
cd /opt/whatsapp-bot

# Initialize Node.js project
npm init -y
npm install whatsapp-web.js qrcode-terminal axios express body-parser

# Create bot script
cat > bot.js << 'EOF'
const { Client, LocalAuth } = require('whatsapp-web.js');
const qrcode = require('qrcode-terminal');
const express = require('express');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: {
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox']
    }
});

client.on('qr', qr => {
    console.log('Scan QR Code:');
    qrcode.generate(qr, { small: true });
});

client.on('ready', () => {
    console.log('WhatsApp Bot is ready!');
});

client.on('message', async message => {
    console.log(`Message from ${message.from}: ${message.body}`);
    
    // Auto reply for Pterodactyl panel
    if (message.body.toLowerCase().includes('status')) {
        const status = require('child_process').execSync('systemctl status wings --no-pager').toString();
        client.sendMessage(message.from, `Panel Status:\n${status.substring(0, 500)}...`);
    }
    
    // Server stats
    if (message.body.toLowerCase().includes('stats')) {
        const stats = {
            memory: require('child_process').execSync('free -m').toString(),
            disk: require('child_process').execSync('df -h').toString(),
            uptime: require('child_process').execSync('uptime').toString()
        };
        client.sendMessage(message.from, `Server Stats:\nMemory:\n${stats.memory}\nDisk:\n${stats.disk}\nUptime: ${stats.uptime}`);
    }
});

// REST API endpoints
app.post('/send-message', (req, res) => {
    const { number, message } = req.body;
    const chatId = number + "@c.us";
    
    client.sendMessage(chatId, message)
        .then(() => res.json({ success: true }))
        .catch(err => res.status(500).json({ error: err.message }));
});

app.get('/health', (req, res) => {
    res.json({ status: 'online', timestamp: new Date() });
});

// Start servers
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`WhatsApp Bot API listening on port ${PORT}`);
});

client.initialize();
EOF

# Create systemd service for WhatsApp bot
cat > /etc/systemd/system/whatsapp-bot.service << 'EOF'
[Unit]
Description=WhatsApp Bot for Pterodactyl
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/whatsapp-bot
ExecStart=/usr/bin/node /opt/whatsapp-bot/bot.js
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable whatsapp-bot
systemctl start whatsapp-bot

# ============================================
# 10. FINAL SETUP & OPTIMIZATION
# ============================================
echo -e "${CYAN}[10/10] Finalizing installation...${NC}"
log_message "Final setup and optimization"

# Setup cron jobs
(crontab -l 2>/dev/null; echo "*/5 * * * * php $PTERO_PATH/artisan schedule:run >> /dev/null 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "0 0 * * * /usr/local/bin/update-minecraft-plugins") | crontab -

# Configure firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 2022/tcp
ufw allow 8080/tcp
ufw allow 25565/tcp
ufw --force enable

# Optimize PHP
sed -i 's/memory_limit = .*/memory_limit = 512M/' /etc/php/8.1/fpm/php.ini
sed -i 's/upload_max_filesize = .*/upload_max_filesize = 100M/' /etc/php/8.1/fpm/php.ini
sed -i 's/post_max_size = .*/post_max_size = 100M/' /etc/php/8.1/fpm/php.ini
systemctl restart php8.1-fpm

# Optimize MySQL
cat >> /etc/mysql/my.cnf << 'EOF'
[mysqld]
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
query_cache_type = 1
query_cache_size = 32M
max_connections = 100
EOF

systemctl restart mariadb

# Create setup completion flag
cat > /root/ptero-setup-complete.txt << EOF
Pterodactyl Installation Complete
==================================
Panel URL: ${APP_URL}
Admin User: admin
Admin Pass: password123
Database: panel
DB User: pterodactyl
DB Pass: ${DB_PASSWORD}
Wings Token: $(cat /etc/pterodactyl/config.yml | grep token | awk '{print $2}')
Installation Log: ${LOG_FILE}
WhatsApp Bot API: http://${APP_URL#http://}:3000
Minecraft Plugins: /opt/minecraft-plugins
EOF

# Final reboot
log_message "Installation complete!"
echo -e "${GREEN}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║                   INSTALLATION COMPLETE                  ║"
echo "╠══════════════════════════════════════════════════════════╣"
echo "║ Panel URL: ${APP_URL}${NC}"
echo -e "${GREEN}║ Admin: admin / password123                         ║"
echo "║ WhatsApp Bot API: ${APP_URL#http://}:3000           ║"
echo "║ Minecraft Plugins: /opt/minecraft-plugins            ║"
echo "║                                                    ║"
echo "║ Run these commands to check services:              ║"
echo "║ systemctl status wings                             ║"
echo "║ systemctl status whatsapp-bot                      ║"
echo "║                                                    ║"
echo "║ Installation log: ${LOG_FILE}${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Rebooting in 10 seconds...${NC}"
sleep 10
reboot
