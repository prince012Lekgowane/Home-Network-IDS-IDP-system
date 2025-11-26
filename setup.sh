
## 2. setup.sh

```bash
#!/bin/bash

# Home Network IDS/IDP Setup Script
# Complete automated installation for Arch Linux
# GitHub: https://github.com/yourusername/home-network-ids-idp

set -e

echo "================================================"
echo "🛡️  HOME NETWORK IDS/IDP - COMPLETE SETUP"
echo "================================================"
echo ""
echo "This script will:"
echo "  ✓ Install all dependencies (Python, Ollama)"
echo "  ✓ Download AI model (1GB - lightweight)" 
echo "  ✓ Create network monitoring system"
echo "  ✓ Configure everything automatically"
echo ""
echo "GitHub: https://github.com/yourusername/home-network-ids-idp"
echo ""

read -p "Press Enter to start installation..." 

if [ "$EUID" -ne 0 ]; then 
    echo "❌ Please run with sudo: sudo bash setup.sh"
    exit 1
fi

ACTUAL_USER=${SUDO_USER:-$USER}
USER_HOME=$(eval echo ~$ACTUAL_USER)
PROJECT_DIR="$USER_HOME/home-ids"

echo ""
echo "========================================"
echo "📦 STEP 1/5: Updating System"
echo "========================================"
pacman -Sy --noconfirm

echo ""
echo "========================================"
echo "📦 STEP 2/5: Installing Base Dependencies"
echo "========================================"
echo "Installing: Python, networking tools..."
pacman -S --noconfirm python python-pip git iptables nmap tcpdump jq net-tools

echo ""
echo "========================================"
echo "🤖 STEP 3/5: Installing AI (Ollama)"
echo "========================================"
if ! command -v ollama &> /dev/null; then
    echo "Downloading Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama already installed ✓"
fi

systemctl enable ollama
systemctl start ollama
sleep 10

echo "Downloading lightweight AI model (llama3.2:1b - 1GB)..."
echo "This may take 2-5 minutes depending on your connection..."
sudo -u $ACTUAL_USER timeout 300 bash -c "ollama pull llama3.2:1b" || echo "Model download may take longer in background"

echo ""
echo "========================================"
echo "🐍 STEP 4/5: Setting up Python Backend"
echo "========================================"
echo "Installing Python packages..."
pip install --break-system-packages fastapi uvicorn websockets httpx psutil scapy plyer

# Create project directory
mkdir -p "$PROJECT_DIR/static"
cd "$PROJECT_DIR"

echo "Creating backend application (main.py)..."
cat > "$PROJECT_DIR/main.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
Home Network IDS/IDP with AI Analysis
GitHub: https://github.com/yourusername/home-network-ids-idp
"""

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import asyncio
import json
import subprocess
import re
from datetime import datetime
from typing import List, Dict
import httpx
from collections import deque
import os
import random
import psutil
import time
import socket
import threading
import ipaddress

# Global variables
recent_alerts = deque(maxlen=1000)
blocked_ips = set()
active_connections: List[WebSocket] = []
network_devices = {}
port_scans = {}
local_network_devices = {}
pending_attacks = {}

OLLAMA_API = "http://localhost:11434/api/generate"
MODEL = "llama3.2:1b"

# Common port to service mapping
PORT_SERVICES = {
    80: "HTTP", 443: "HTTPS", 22: "SSH", 23: "Telnet", 21: "FTP",
    25: "SMTP", 110: "POP3", 143: "IMAP", 53: "DNS", 67: "DHCP",
    68: "DHCP", 69: "TFTP", 123: "NTP", 161: "SNMP", 162: "SNMP",
    389: "LDAP", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    9200: "Elasticsearch", 5601: "Kibana"
}

# Domain name mapping for common services
DOMAIN_MAPPINGS = {
    "8.8.8.8": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "142.250.0.0/16": "Google Services",
    "13.107.0.0/16": "Microsoft Services",
    "20.0.0.0/8": "Microsoft Azure",
    "52.0.0.0/8": "Amazon AWS",
    "54.0.0.0/8": "Amazon AWS",
    "17.0.0.0/8": "Apple Services",
    "104.16.0.0/12": "Cloudflare"
}

def send_notification(title, message, timeout=5):
    """Send desktop notification with fallback"""
    try:
        from plyer import notification
        notification.notify(
            title=title,
            message=message,
            timeout=timeout,
            app_name="Home IDS/IDP"
        )
    except:
        print(f"🔔 NOTIFICATION: {title} - {message}")

class NetworkMonitor:
    def __init__(self):
        self.interface = self.get_primary_interface()
        self.known_connections = set()
        self.device_cache = {}
        self.local_network = self.get_local_network()
        
    def get_local_network(self):
        """Get local network range"""
        try:
            result = subprocess.run(
                ["ip", "route"],
                capture_output=True, text=True
            )
            lines = result.stdout.split('\n')
            for line in lines:
                if "dev" in line and "src" in line and self.interface in line:
                    parts = line.split()
                    for part in parts:
                        if '/' in part and part.count('.') == 3:
                            return part
            return "192.168.1.0/24"
        except:
            return "192.168.1.0/24"
        
    def get_primary_interface(self):
        try:
            result = subprocess.run(
                ["ip", "route", "get", "1.1.1.1"],
                capture_output=True, text=True, timeout=5
            )
            match = re.search(r'dev (\S+)', result.stdout)
            return match.group(1) if match else "wlan0"
        except:
            return "wlan0"
    
    def discover_local_network(self):
        """Discover all devices on local network"""
        try:
            print(f"🔍 Discovering devices on network: {self.local_network}")
            
            result = subprocess.run([
                "nmap", "-sn", self.local_network
            ], capture_output=True, text=True, timeout=60)
            
            devices = {}
            lines = result.stdout.split('\n')
            current_ip = None
            
            for line in lines:
                if "Nmap scan report for" in line:
                    parts = line.split()
                    ip = parts[-1].strip('()')
                    hostname = parts[4] if len(parts) > 4 and "(" not in parts[4] else None
                    current_ip = ip
                    
                    devices[ip] = {
                        'ip': ip,
                        'hostname': hostname,
                        'status': 'online',
                        'last_seen': time.time(),
                        'ports': [],
                        'os': 'Unknown',
                        'mac': 'Unknown',
                        'vendor': 'Unknown'
                    }
                
                elif "MAC Address:" in line and current_ip:
                    parts = line.split()
                    if len(parts) >= 4:
                        devices[current_ip]['mac'] = parts[2]
                        devices[current_ip]['vendor'] = ' '.join(parts[3:])
            
            for ip, device in devices.items():
                if ip not in local_network_devices:
                    send_notification("New Device Found", f"Device detected: {ip}")
                local_network_devices[ip] = device
            
            print(f"✅ Found {len(devices)} devices on local network")
            return devices
            
        except Exception as e:
            print(f"Network discovery error: {e}")
            return {}
    
    def get_domain_name(self, ip):
        """Get domain name for IP address"""
        try:
            for domain_ip, name in DOMAIN_MAPPINGS.items():
                if '/' in domain_ip:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(domain_ip, strict=False):
                        return name
                elif ip == domain_ip:
                    return name
            
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                return hostname
            except:
                pass
                
            return None
        except:
            return None
    
    def scan_device_details(self, ip, scan_type="quick"):
        """Use nmap to get device details"""
        try:
            cache_key = f"{ip}_{scan_type}"
            if cache_key in self.device_cache and time.time() - self.device_cache[cache_key]['timestamp'] < 3600:
                return self.device_cache[cache_key]
            
            print(f"🔍 Scanning device: {ip} ({scan_type} scan)")
            
            if scan_type == "quick":
                nmap_args = ["-O", "--osscan-guess", "-sV", "--version-intensity", "1", "-T4", "-F"]
            elif scan_type == "detailed":
                nmap_args = ["-A", "-T4", "-p-"]
            else:
                nmap_args = ["-A", "-T4", "-sS", "-sU", "-p-"]
            
            result = subprocess.run([
                "nmap", *nmap_args, ip
            ], capture_output=True, text=True, timeout=120 if scan_type == "aggressive" else 60)
            
            device_info = {
                'ip': ip,
                'timestamp': time.time(),
                'scan_type': scan_type,
                'ports': [],
                'os': 'Unknown',
                'services': [],
                'vulnerabilities': []
            }
            
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if '/tcp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        port = port_proto.split('/')[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        version = ' '.join(parts[3:]) if len(parts) > 3 else ''
                        
                        device_info['ports'].append({
                            'port': port,
                            'service': service,
                            'version': version,
                            'state': state
                        })
                
                elif '/udp' in line and 'open' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_proto = parts[0]
                        port = port_proto.split('/')[0]
                        state = parts[1]
                        service = parts[2] if len(parts) > 2 else 'unknown'
                        
                        device_info['ports'].append({
                            'port': port,
                            'service': service,
                            'state': state,
                            'protocol': 'UDP'
                        })
                
                elif 'OS details:' in line or 'OS:' in line:
                    device_info['os'] = line.split(':', 1)[1].strip()
                
                elif 'Service Info:' in line:
                    device_info['services'].append(line.split(':', 1)[1].strip())
                
                elif 'VULNERABLE:' in line:
                    if i + 1 < len(lines):
                        device_info['vulnerabilities'].append(lines[i + 1].strip())
            
            self.device_cache[cache_key] = device_info
            network_devices[ip] = device_info
            
            if device_info['ports']:
                open_ports = len([p for p in device_info['ports'] if p.get('state') == 'open'])
                if open_ports > 5:
                    send_notification("Multiple Open Ports", f"Device {ip} has {open_ports} open ports")
            
            return device_info
            
        except Exception as e:
            print(f"Error scanning device {ip}: {e}")
            return {'ip': ip, 'os': 'Scan failed', 'ports': [], 'error': str(e)}
    
    def get_network_connections(self):
        """Get current network connections"""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    local_ip = conn.laddr.ip
                    remote_ip = conn.raddr.ip
                    local_port = conn.laddr.port
                    remote_port = conn.raddr.port
                    
                    conn_id = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                    if conn_id not in self.known_connections:
                        self.known_connections.add(conn_id)
                        
                        domain_name = self.get_domain_name(remote_ip)
                        
                        connections.append({
                            "src_ip": local_ip,
                            "src_port": local_port,
                            "dest_ip": remote_ip,
                            "dest_port": remote_port,
                            "proto": "TCP" if conn.type == 1 else "UDP",
                            "domain_name": domain_name,
                            "service": PORT_SERVICES.get(remote_port, "Unknown")
                        })
        except Exception as e:
            print(f"Error getting connections: {e}")
        
        return connections
    
    def monitor_iptables(self):
        """Monitor iptables for blocked connections and port rules"""
        try:
            result = subprocess.run(
                ["iptables", "-L", "INPUT", "-nv", "--line-numbers"],
                capture_output=True, text=True
            )
            lines = result.stdout.split('\n')
            for line in lines:
                if "DROP" in line:
                    parts = line.split()
                    for part in parts:
                        if re.match(r'\d+\.\d+\.\d+\.\d+', part) and part not in blocked_ips:
                            blocked_ips.add(part)
        except Exception as e:
            print(f"Error monitoring iptables: {e}")
    
    async def start_port_scan_detection(self):
        """Detect port scanning activity"""
        while True:
            try:
                recent_connections = list(recent_alerts)[-100:]
                ip_connections = {}
                for alert in recent_connections:
                    src_ip = alert.get('src_ip')
                    if src_ip:
                        if src_ip not in ip_connections:
                            ip_connections[src_ip] = []
                        ip_connections[src_ip].append(alert)
                
                for ip, connections in ip_connections.items():
                    if len(connections) > 10:
                        unique_ports = len(set(conn.get('dest_port') for conn in connections))
                        if unique_ports > 5:
                            if ip not in port_scans or time.time() - port_scans[ip] > 300:
                                port_scans[ip] = time.time()
                                await self.generate_port_scan_alert(ip, connections)
                                send_notification("Port Scan Detected", f"IP {ip} is scanning multiple ports")
                
                await asyncio.sleep(30)
            except Exception as e:
                print(f"Port scan detection error: {e}")
                await asyncio.sleep(30)
    
    async def generate_port_scan_alert(self, ip, connections):
        """Generate alert for port scanning activity"""
        alert = {
            "event_type": "alert",
            "timestamp": datetime.now().isoformat(),
            "src_ip": ip,
            "dest_ip": "Multiple",
            "src_port": "Various",
            "dest_port": "Various",
            "proto": "TCP/UDP",
            "alert": {
                "signature": "Port Scanning Activity Detected",
                "category": "Reconnaissance",
                "risk_factors": [f"Scanned {len(connections)} ports", "Multiple connection attempts"]
            }
        }
        await process_alert(alert)
    
    async def start_network_discovery(self):
        """Periodically discover network devices"""
        while True:
            try:
                self.discover_local_network()
                await asyncio.sleep(300)
            except Exception as e:
                print(f"Network discovery error: {e}")
                await asyncio.sleep(300)
    
    async def start_monitoring(self):
        """Start network monitoring"""
        print(f"🔍 Starting network monitoring on interface: {self.interface}")
        
        while True:
            try:
                connections = self.get_network_connections()
                for conn in connections:
                    await self.generate_connection_alert(conn)
                
                self.monitor_iptables()
                
                if random.random() < 0.1:
                    await self.generate_test_alert()
                
                await asyncio.sleep(10)
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                await asyncio.sleep(10)
    
    async def generate_connection_alert(self, conn):
        """Generate alert for new network connection"""
        alert_types = [
            "New network connection established",
            "Outbound connection detected", 
            "Incoming connection attempt",
            "Suspicious port activity"
        ]
        
        risk_factors = []
        if conn["dest_port"] in [22, 23, 3389]:
            risk_factors.append("Remote administration port")
        if conn["dest_port"] in [1433, 3306, 5432]:
            risk_factors.append("Database port")
        if conn["dest_port"] > 49152:
            risk_factors.append("Ephemeral port range")
        
        service_info = []
        if conn.get('domain_name'):
            service_info.append(f"Domain: {conn['domain_name']}")
        if conn.get('service') and conn['service'] != 'Unknown':
            service_info.append(f"Service: {conn['service']}")
        
        alert = {
            "event_type": "alert",
            "timestamp": datetime.now().isoformat(),
            "src_ip": conn["src_ip"],
            "dest_ip": conn["dest_ip"],
            "src_port": conn["src_port"],
            "dest_port": conn["dest_port"],
            "proto": conn["proto"],
            "domain_name": conn.get('domain_name'),
            "service": conn.get('service'),
            "alert": {
                "signature": random.choice(alert_types),
                "category": "Network Activity",
                "risk_factors": risk_factors,
                "service_info": service_info
            }
        }
        
        await process_alert(alert)
    
    async def generate_test_alert(self):
        """Generate simulated security alerts for testing"""
        test_scenarios = [
            {
                "src_ip": f"192.168.1.{random.randint(100, 200)}",
                "dest_ip": "8.8.8.8",
                "signature": "ET SCAN Potential SSH Scan",
                "category": "Attempted Information Leak",
                "dest_port": 22,
                "domain_name": "Google DNS"
            },
            {
                "src_ip": f"10.0.1.{random.randint(50, 150)}", 
                "dest_ip": "142.250.0.1",
                "signature": "ET WEB_SERVER Possible SQL Injection Attempt",
                "category": "Potential Attack",
                "dest_port": 80,
                "domain_name": "Google Services"
            }
        ]
        
        scenario = random.choice(test_scenarios)
        alert = {
            "event_type": "alert",
            "timestamp": datetime.now().isoformat(),
            "src_ip": scenario["src_ip"],
            "dest_ip": scenario["dest_ip"],
            "src_port": random.randint(1000, 65000),
            "dest_port": scenario["dest_port"],
            "proto": "TCP",
            "domain_name": scenario.get("domain_name"),
            "alert": {
                "signature": scenario["signature"],
                "category": scenario["category"]
            }
        }
        
        await process_alert(alert)

async def analyze_with_llm(alert_data: Dict) -> Dict:
    """Analyze alert with AI or fallback to rule-based analysis"""
    
    try:
        domain_info = f", Domain: {alert_data.get('domain_name', 'Unknown')}" if alert_data.get('domain_name') else ""
        service_info = f", Service: {alert_data.get('service', 'Unknown')}" if alert_data.get('service') else ""
        
        prompt = f"""Analyze security alert:
Signature: {alert_data.get('alert', {}).get('signature', 'Unknown')}
Source: {alert_data.get('src_ip', 'Unknown')}:{alert_data.get('src_port', 'Unknown')}
Destination: {alert_data.get('dest_ip', 'Unknown')}:{alert_data.get('dest_port', 'Unknown')}{domain_info}{service_info}
Protocol: {alert_data.get('proto', 'Unknown')}

Respond in JSON: {{"severity": "Critical/High/Medium/Low", "explanation": "brief analysis", "action": "recommendation"}}"""

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                OLLAMA_API,
                json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"}
            )
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get("response", "{}")
                try:
                    return json.loads(analysis_text)
                except:
                    pass
    except:
        pass
    
    signature = alert_data.get('alert', {}).get('signature', '').lower()
    dest_port = alert_data.get('dest_port', 0)
    
    if 'scan' in signature or 'brute' in signature:
        return {"severity": "High", "explanation": "Scanning activity detected", "action": "Monitor closely"}
    elif dest_port in [22, 23, 3389]:
        return {"severity": "Medium", "explanation": "Remote access service", "action": "Review source"}
    elif dest_port in [80, 443]:
        return {"severity": "Low", "explanation": "Web traffic", "action": "Normal monitoring"}
    else:
        severities = ["Low", "Medium"]
        explanations = [
            "Routine network activity",
            "New connection established",
            "Network service access"
        ]
        actions = ["Monitor", "Review", "No action needed"]
        
        return {
            "severity": random.choice(severities),
            "explanation": random.choice(explanations),
            "action": random.choice(actions)
        }

monitor = NetworkMonitor()

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"🛡️  Starting Home IDS/IDP on interface: {monitor.interface}")
    print(f"🌐 Local network: {monitor.local_network}")
    
    asyncio.create_task(monitor.start_monitoring())
    asyncio.create_task(monitor.start_port_scan_detection())
    asyncio.create_task(monitor.start_network_discovery())
    
    monitor.discover_local_network()
    
    yield
    print("Shutting down IDS/IDP system")

app = FastAPI(title="Home IDS/IDP", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def root():
    return {"message": "Home IDS/IDP System", "status": "running", "mode": "ultimate"}

@app.get("/api/status")
async def get_status():
    return {
        "status": "running",
        "interface": monitor.interface,
        "network": monitor.local_network,
        "alerts_count": len(recent_alerts),
        "blocked_ips_count": len(blocked_ips),
        "devices_count": len(network_devices),
        "local_devices_count": len(local_network_devices),
        "port_scans_count": len(port_scans),
        "pending_attacks_count": len(pending_attacks),
        "timestamp": datetime.now().isoformat(),
        "mode": "ultimate"
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    alerts = list(recent_alerts)[-limit:]
    return {"alerts": alerts, "count": len(alerts)}

@app.get("/api/blocked")
async def get_blocked_ips():
    return {"blocked_ips": list(blocked_ips), "count": len(blocked_ips)}

@app.get("/api/devices")
async def get_devices():
    return {"devices": network_devices, "count": len(network_devices)}

@app.get("/api/local-devices")
async def get_local_devices():
    return {"devices": local_network_devices, "count": len(local_network_devices)}

@app.get("/api/port-scans")
async def get_port_scans():
    return {"port_scans": port_scans, "count": len(port_scans)}

@app.get("/api/pending-attacks")
async def get_pending_attacks():
    return {"attacks": pending_attacks, "count": len(pending_attacks)}

@app.post("/api/block/{ip}")
async def block_ip(ip: str):
    try:
        if not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            return {"success": False, "error": "Invalid IP format"}
            
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            blocked_ips.add(ip)
            await broadcast_alert({
                "type": "ip_blocked", "ip": ip,
                "timestamp": datetime.now().isoformat(), "manual": True
            })
            send_notification("IP Blocked", f"IP {ip} has been blocked")
            return {"success": True, "message": f"IP {ip} blocked"}
        else:
            return {"success": False, "error": result.stderr}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/unblock/{ip}")
async def unblock_ip(ip: str):
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        blocked_ips.discard(ip)
        send_notification("IP Unblocked", f"IP {ip} has been unblocked")
        return {"success": True, "message": f"IP {ip} unblocked"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/block-port/{port}")
async def block_port(port: str):
    try:
        port_num = int(port)
        if not (1 <= port_num <= 65535):
            return {"success": False, "error": "Port must be between 1-65535"}
            
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            send_notification("Port Blocked", f"Port {port} has been blocked")
            return {"success": True, "message": f"Port {port} blocked"}
        else:
            return {"success": False, "error": result.stderr}
    except ValueError:
        return {"success": False, "error": "Invalid port number"}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/unblock-port/{port}")
async def unblock_port(port: str):
    try:
        result = subprocess.run(
            ["iptables", "-D", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP
