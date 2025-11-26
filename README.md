# 🛡️ Home Network IDS/IDP with AI

A comprehensive Intrusion Detection System (IDS) and Intrusion Prevention System (IDP) for home networks, powered by AI analysis and real-time monitoring.

![Home Network Security](https://img.shields.io/badge/Platform-Arch%20Linux-blue)
![Python](https://img.shields.io/badge/Python-3.8%2B-green)
![AI](https://img.shields.io/badge/AI-Ollama%20Powered-orange)

## 🚀 Features

### 🔍 Network Monitoring
- **Real-time Connection Tracking**: Monitor all network connections in real-time
- **Automatic Threat Detection**: AI-powered analysis of network traffic
- **Port Scan Detection**: Identify reconnaissance activities
- **Device Discovery**: Automatically discover devices on your network

### 🤖 AI Integration
- **LLM-Powered Analysis**: Uses Ollama with lightweight models (llama3.2:1b)
- **Smart Alert Classification**: Automatic severity assessment
- **Behavioral Analysis**: Learn normal network patterns

### 🛡️ Security Features
- **IP Blocking**: Manual and automatic blocking of suspicious IPs
- **Port Control**: Block specific ports to prevent attacks
- **Counter Attack System**: Request-based counter measures
- **Real-time Alerts**: Instant notifications for security events

### 🌐 Web Interface
- **Responsive Design**: Works on desktop, tablet, and mobile
- **Real-time Updates**: WebSocket-based live data
- **Interactive Controls**: Easy-to-use security management
- **Dashboard**: Comprehensive overview of network security

## 📋 Prerequisites

- **Arch Linux** (or compatible distribution)
- **Python 3.8+**
- **Root/sudo access** (for network monitoring)
- **Internet connection** (for AI model download)

## ⚡ Quick Installation

### Automated Setup (Recommended)
```bash
# Download and run the setup script
curl -O https://raw.githubusercontent.com/yourusername/home-network-ids-idp/main/setup.sh
chmod +x setup.sh
sudo ./setup.sh
