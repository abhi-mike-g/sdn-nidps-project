#!/bin/bash

##############################################################################
# Redis Setup Script for SDN-NIDPS
# Installs and configures Redis for distributed threat detection
##############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}SDN-NIDPS Redis Setup Script${NC}"
echo -e "${GREEN}=========================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[-] Please run as root (sudo)${NC}"
    exit 1
fi

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
fi

echo -e "${YELLOW}[*] Detected OS: $OS${NC}"

# Install Redis based on OS
case $OS in
    ubuntu|debian)
        echo -e "${YELLOW}[*] Installing Redis on Debian/Ubuntu${NC}"
        apt-get update
        apt-get install -y redis-server redis-tools
        ;;
    centos|rhel|fedora)
        echo -e "${YELLOW}[*] Installing Redis on CentOS/RHEL${NC}"
        yum install -y redis
        ;;
    alpine)
        echo -e "${YELLOW}[*] Installing Redis on Alpine${NC}"
        apk add --no-cache redis
        ;;
    *)
        echo -e "${RED}[-] Unsupported OS: $OS${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}[+] Redis installed${NC}"

# Create configuration directory
echo -e "${YELLOW}[*] Setting up Redis configuration${NC}"
mkdir -p /etc/redis/sdn-nidps

# Create Redis configuration for SDN-NIDPS
cat > /etc/redis/sdn-nidps/redis.conf << 'EOF'
# SDN-NIDPS Redis Configuration

# Server settings
port 6379
bind 127.0.0.1
timeout 0
tcp-keepalive 300

# Memory settings
maxmemory 256mb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
rdbcompression yes
dbfilename dump.rdb
dir /var/lib/redis/sdn-nidps

# Logging
loglevel notice
logfile /var/log/redis/sdn-nidps.log

# Database
databases 16

# Replication
slave-read-only yes
repl-diskless-sync no

# AOF
appendonly yes
appendfilename "appendonly.aof"
appendfsync everysec

# Security
# requirepass your_password_here

# Clients
maxclients 10000

# Cluster settings
# cluster-enabled no

# Slowlog
slowlog-log-slower-than 10000
slowlog-max-len 128
EOF

chmod 644 /etc/redis/sdn-nidps/redis.conf
echo -e "${GREEN}[+] Redis configuration created${NC}"

# Create data directory
echo -e "${YELLOW}[*] Creating Redis data directory${NC}"
mkdir -p /var/lib/redis/sdn-nidps
mkdir -p /var/log/redis

chown redis:redis /var/lib/redis/sdn-nidps
chown redis:redis /var/log/redis
chmod 755 /var/lib/redis/sdn-nidps
chmod 755 /var/log/redis

echo -e "${GREEN}[+] Data directories created${NC}"

# Create systemd service file
echo -e "${YELLOW}[*] Creating systemd service${NC}"
cat > /etc/systemd/system/redis-sdn-nidps.service << 'EOF'
[Unit]
Description=Redis Server for SDN-NIDPS
After=syslog.target network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/redis-server /etc/redis/sdn-nidps/redis.conf
ExecStop=/bin/kill -s TERM $MAINPID
Restart=on-failure
RestartSec=5s

StandardOutput=journal
StandardError=journal

# User and Group
User=redis
Group=redis

# Security settings
PrivateTmp=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/redis/sdn-nidps /var/log/redis

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}[+] Systemd service created${NC}"

# Start Redis
echo -e "${YELLOW}[*] Starting Redis service${NC}"
systemctl enable redis-sdn-nidps
systemctl start redis-sdn-nidps

# Wait for Redis to start
sleep 2

# Test Redis connection
echo -e "${YELLOW}[*] Testing Redis connection${NC}"
if redis-cli ping > /dev/null 2>&1; then
    echo -e "${GREEN}[+] Redis is running and responding${NC}"
else
    echo -e "${RED}[-] Redis connection failed${NC}"
    exit 1
fi

# Get Redis info
echo -e "${YELLOW}[*] Redis Information:${NC}"
redis-cli INFO server | grep -E "redis_version|process_id|uptime"

echo ""
echo -e "${GREEN}[+] Redis configuration:${NC}"
redis-cli CONFIG GET maxmemory
redis-cli CONFIG GET maxmemory_policy
redis-cli CONFIG GET appendonly

# Create test key
echo -e "${YELLOW}[*] Creating test key${NC}"
redis-cli SET "sdn-nidps:test" "$(date)" EX 60
TEST_VALUE=$(redis-cli GET "sdn-nidps:test")

if [ ! -z "$TEST_VALUE" ]; then
    echo -e "${GREEN}[+] Test key created successfully: $TEST_VALUE${NC}"
else
    echo -e "${RED}[-] Failed to create test key${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Redis Setup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Redis Details:${NC}"
echo "  Host: localhost"
echo "  Port: 6379"
echo "  Config: /etc/redis/sdn-nidps/redis.conf"
echo "  Data Dir: /var/lib/redis/sdn-nidps"
echo "  Log File: /var/log/redis/sdn-nidps.log"
echo ""
echo -e "${YELLOW}Useful Commands:${NC}"
echo "  Start: systemctl start redis-sdn-nidps"
echo "  Stop: systemctl stop redis-sdn-nidps"
echo "  Status: systemctl status redis-sdn-nidps"
echo "  CLI: redis-cli"
echo "  Logs: journalctl -u redis-sdn-nidps -f"
echo ""
