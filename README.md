```markdown
# 🛡️ Home Network IDS/IDP with AI

A comprehensive Intrusion Detection System (IDS) and Intrusion Prevention System (IDP) for home networks, powered by AI analysis and real-time monitoring.

![Platform](https://img.shields.io/badge/Platform-Arch%20Linux-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![AI](https://img.shields.io/badge/AI-Ollama%20Powered-orange)

## 🚀 Features

### 🔍 Network Monitoring
- Real-time Connection Tracking
- Automatic Threat Detection via AI
- Port Scan Detection
- Automatic Device Discovery on your network

### 🤖 AI Integration
- LLM-Powered Analysis using Ollama (default: lightweight `llama3.2:1b`)
- Smart Alert Classification with severity scoring
- Behavioral Analysis (learns normal network patterns)

### 🛡️ Security Features
- Manual & Automatic IP Blocking
- Port-level blocking controls
- Counter-attack system (request-based countermeasures)
- Real-time Alerts (web + system notifications)

### 🌐 Web Interface
- Fully responsive dashboard (desktop, tablet, mobile)
- Live updates via WebSocket
- Interactive controls for blocking, scanning, and countermeasures
- Comprehensive security overview

## 📋 Prerequisites

- Arch Linux (or compatible Linux distribution)
- Python 3.8 or higher
- Root/sudo privileges (required for packet monitoring and iptables)
- Internet connection (initial Ollama model download)

## ⚡ Installation

### Option 1: Automated Setup (Recommended)
```bash
curl -O https://raw.githubusercontent.com/yourusername/home-network-ids-idp/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
```

### Option 2: Manual Installation
```bash
git clone https://github.com/yourusername/home-network-ids-idp.git
cd home-network-ids-idp
sudo ./setup.sh
```

## 🎯 Usage

### Starting the System
```bash
cd ~/home-ids
sudo python main.py
```

### Accessing the Web Interface
- Local machine: http://localhost:8000
- From other devices on your network: http://YOUR_SERVER_IP:8000

### Key Operations
- View real-time alerts
- Manually block/unblock IPs
- Trigger network/device scans
- Control allowed ports
- Request counter measures against attackers (with confirmation)

## 🏗️ Architecture

**Components**
- Network Monitor → `psutil` + real-time connection tracking
- AI Analyzer → Ollama (local LLM)
- Web Interface → FastAPI + responsive frontend (WebSocket)
- Security Engine → iptables-based blocking

**Data Flow**
```
Network Traffic → Connection Monitor → AI Analysis → Alert System → Web Dashboard
                                              ↓
                                       Blocking Engine → iptables
```

## 🔧 Configuration

### Network Interface
Auto-detected by default. To set manually, edit in `main.py`:
```python
monitor.interface = "eth0"  # or wlan0, enp3s0, etc.
```

### AI Model
Default: `llama3.2:1b` (~1GB RAM). Change in config:
```python
MODEL = "llama3.2:1b"  # or "llama3.2:3b", "mistral", "phi3", etc.
```

### Alert Thresholds
Auto-blocking logic (edit in analysis function):
```python
if analysis.get("severity") in ["High", "Critical"]:
    block_ip(attacker_ip)
```

## 🛠️ Advanced Features

### Manual Network Discovery
```bash
curl -X POST http://localhost:8000/api/discover-network
```

### Scan Specific Device
```bash
curl -X POST "http://localhost:8000/api/scan-device/192.168.1.100?scan_type=detailed"
```

### Counter Attacks
Available via web interface with confirmation step (review target before execution).

## 📊 Alert Levels

- **Critical** – Immediate threat (auto-response likely)
- **High** – Significant risk (auto-block external IPs)
- **Medium** – Suspicious activity
- **Low** – Normal or informational

## 🔒 Security & Privacy

- All AI processing happens **locally** via Ollama
- No network data leaves your machine
- Lightweight model minimizes resource usage
- You retain full control over all blocking/counter decisions

## 🚨 Troubleshooting

**System won't start**
```bash
pip install -r requirements.txt
systemctl status ollama
netstat -tuln | grep 8000   # check if port is in use
```

**No alerts**
- Verify correct network interface
- Generate test traffic or use "Generate Test Alert" button

**Web UI not loading**
- Ensure `sudo python main.py` is running
- Check firewall (ufw/iptables) allows port 8000

**View logs**
```bash
journalctl -u ollama -f
ip addr show
```

## 🤝 Contributing

Contributions are welcome! Fork the repo, create a feature branch, and submit a pull request.

**Dev setup**
```bash
git clone https://github.com/yourusername/home-network-ids-idp.git
cd home-network-ids-idp
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 📄 License

This project is licensed under the **MIT License** – see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Ollama – local LLM inference
- FastAPI – high-performance web framework
- psutil – system monitoring
- Arch Linux community

## 📞 Support

- Issues → GitHub Issues
- Questions → GitHub Discussions
- Documentation → Project Wiki

## ⚠️ Disclaimer

This tool is intended for **educational purposes and personal home network protection only**. Use responsibly and ensure compliance with applicable laws and network policies. The authors are not responsible for misuse.
```

You can now copy and paste this entire block directly into your repository's `README.md`.
(Just remember to replace `yourusername` with your actual GitHub username in the links!)
```
