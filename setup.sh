#!/bin/bash

# Home Network IDS/IDP - Complete Setup Script
# GitHub: https://github.com/yourusername/home-network-ids-idp
# License: MIT

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    print_error "Please run with sudo: sudo bash $0"
    exit 1
fi

# Configuration
ACTUAL_USER=${SUDO_USER:-$USER}
USER_HOME=$(eval echo ~$ACTUAL_USER)
PROJECT_DIR="$USER_HOME/home-ids"
REPO_DIR=$(pwd)

echo "================================================"
echo "🛡️  HOME NETWORK IDS/IDP - COMPLETE SETUP"
echo "================================================"
echo ""
echo "GitHub: https://github.com/yourusername/home-network-ids-idp"
echo "License: MIT"
echo ""
echo "This script will:"
echo "  ✓ Install all dependencies (Python, Ollama, nmap)"
echo "  ✓ Download AI model (llama3.2:1b - 1GB)" 
echo "  ✓ Create network monitoring system"
echo "  ✓ Configure firewall rules"
echo "  ✓ Set up web interface"
echo ""
read -p "Press Enter to start installation..." 

echo ""
echo "========================================"
echo "📦 STEP 1/6: System Update & Dependencies"
echo "========================================"
print_status "Updating system packages..."
pacman -Sy --noconfirm

print_status "Installing base dependencies..."
pacman -S --noconfirm python python-pip git iptables nmap tcpdump jq net-tools

echo ""
echo "========================================"
echo "🤖 STEP 2/6: Installing AI (Ollama)"
echo "========================================"
if ! command -v ollama &> /dev/null; then
    print_status "Downloading and installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    print_success "Ollama already installed"
fi

systemctl enable ollama
systemctl start ollama
sleep 10

print_status "Downloading AI model (llama3.2:1b - 1GB)..."
print_warning "This may take 2-5 minutes depending on your connection..."
sudo -u $ACTUAL_USER timeout 300 bash -c "ollama pull llama3.2:1b" || print_warning "Model download may continue in background"

echo ""
echo "========================================"
echo "🐍 STEP 3/6: Python Environment Setup"
echo "========================================"
print_status "Installing Python packages..."
pip install --break-system-packages fastapi uvicorn websockets httpx psutil scapy plyer

echo ""
echo "========================================"
echo "📁 STEP 4/6: Project Setup"
echo "========================================"
print_status "Creating project directory: $PROJECT_DIR"
mkdir -p "$PROJECT_DIR/static"
mkdir -p "$PROJECT_DIR/logs"
mkdir -p "$PROJECT_DIR/config"

# Copy source files
print_status "Setting up application files..."
cp "$REPO_DIR/src/main.py" "$PROJECT_DIR/main.py"
cp "$REPO_DIR/src/static/index.html" "$PROJECT_DIR/static/index.html"

# Set permissions
chown -R $ACTUAL_USER:$ACTUAL_USER "$PROJECT_DIR"
chmod +x "$PROJECT_DIR/main.py"

echo ""
echo "========================================"
echo "🔧 STEP 5/6: System Configuration"
echo "========================================"
print_status "Configuring firewall rules..."

# Create basic iptables rules if they don't exist
if ! iptables -L | grep -q "INPUT.*DROP"; then
    print_status "Setting up basic iptables rules..."
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Allow loopback
    iptables -A INPUT -i lo -j ACCEPT
    # Allow SSH (modify as needed)
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT
    print_success "Basic firewall rules configured"
else
    print_success "Firewall rules already exist"
fi

print_status "Creating systemd service..."
cat > /etc/systemd/system/home-ids.service << EOF
[Unit]
Description=Home Network IDS/IDP System
After=network.target ollama.service
Wants=ollama.service

[Service]
Type=exec
User=root
WorkingDirectory=$PROJECT_DIR
ExecStart=/usr/bin/python $PROJECT_DIR/main.py
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

echo ""
echo "========================================"
echo "🎨 STEP 6/6: Final Setup"
echo "========================================"
print_status "Creating startup scripts..."

# Create startup script
cat > "$PROJECT_DIR/start.sh" << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
sudo python main.py
EOF

chmod +x "$PROJECT_DIR/start.sh"

# Create management script
cat > "$PROJECT_DIR/manage.sh" << 'EOF'
#!/bin/bash
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

case "$1" in
    start)
        cd "$PROJECT_DIR"
        sudo python main.py
        ;;
    stop)
        sudo pkill -f "python main.py"
        echo "🛑 IDS/IDP system stopped"
        ;;
    status)
        if pgrep -f "python main.py" > /dev/null; then
            echo "🟢 IDS/IDP system is running"
        else
            echo "🔴 IDS/IDP system is not running"
        fi
        ;;
    restart)
        sudo pkill -f "python main.py"
        sleep 2
        cd "$PROJECT_DIR"
        sudo python main.py
        ;;
    logs)
        tail -f "$PROJECT_DIR/logs/system.log"
        ;;
    *)
        echo "Usage: $0 {start|stop|status|restart|logs}"
        echo ""
        echo "Commands:"
        echo "  start   - Start the IDS/IDP system"
        echo "  stop    - Stop the IDS/IDP system"
        echo "  status  - Check if system is running"
        echo "  restart - Restart the system"
        echo "  logs    - View system logs"
        exit 1
        ;;
esac
EOF

chmod +x "$PROJECT_DIR/manage.sh"

echo ""
echo "========================================"
echo "✅ INSTALLATION COMPLETE!"
echo "========================================"
echo ""
print_success "Home Network IDS/IDP has been successfully installed!"
echo ""
echo "📁 Project Location: $PROJECT_DIR"
echo "🌐 Web Interface: http://localhost:8000"
echo ""
echo "🚀 QUICK START:"
echo "========================================"
echo ""
echo "Start the system:"
echo "  cd $PROJECT_DIR"
echo "  sudo python main.py"
echo ""
echo "Or use the management script:"
echo "  cd $PROJECT_DIR"
echo "  ./manage.sh start"
echo ""
echo "Access from other devices:"
echo "  Find your IP: ip addr show"
echo "  Open: http://YOUR_IP:8000"
echo ""
echo "🔧 MANAGEMENT COMMANDS:"
echo "========================================"
echo "  ./manage.sh start    - Start system"
echo "  ./manage.sh stop     - Stop system" 
echo "  ./manage.sh status   - Check status"
echo "  ./manage.sh restart  - Restart system"
echo "  ./manage.sh logs     - View logs"
echo ""
echo "🎯 FEATURES AVAILABLE:"
echo "========================================"
echo "✓ Real-time network monitoring"
echo "✓ AI-powered threat analysis"
echo "✓ Device discovery with nmap"
echo "✓ IP and port blocking"
echo "✓ Counter attack system"
echo "✓ Responsive web interface"
echo "✓ Desktop notifications"
echo ""
echo "📚 DOCUMENTATION:"
echo "========================================"
echo "Full documentation: $REPO_DIR/docs/"
echo "GitHub: https://github.com/yourusername/home-network-ids-idp"
echo ""
echo "⚠️  IMPORTANT NOTES:"
echo "========================================"
echo "• Run with sudo for network monitoring"
echo "• Ensure Ollama service is running"
echo "• Configure firewall rules as needed"
echo "• Monitor system resources"
echo ""
print_success "Setup complete! Your home network is now protected! 🛡️"
echo ""

# Display network information
echo "🌐 NETWORK INFORMATION:"
echo "========================================"
INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
IP_ADDR=$(ip addr show $INTERFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1)
echo "Primary interface: $INTERFACE"
echo "Your IP address: $IP_ADDR"
echo "Web interface: http://$IP_ADDR:8000"
echo ""

# Test Ollama
print_status "Testing Ollama installation..."
if sudo -u $ACTUAL_USER ollama list | grep -q "llama3.2:1b"; then
    print_success "AI model is ready"
else
    print_warning "AI model may still be downloading. Check with: ollama list"
fi

echo ""
echo "🎉 Ready to protect your network! Start the system with:"
echo "   cd $PROJECT_DIR && sudo python main.py"
echo ""
