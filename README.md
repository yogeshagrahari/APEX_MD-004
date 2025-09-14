# APEX_MD-004
🍯RUN YOUROWN HONEYPOT
# APEX_MD-004 🍯RUN YOUR OWN HONEYPOT

## 🛡️ Project Overview
This project demonstrates the setup and monitoring of a basic honeypot using open-source tools like **Cowrie** or **T-Pot**. A honeypot simulates vulnerable services to attract and log unauthorized access attempts, helping analyze attack patterns and improve cybersecurity awareness.

## 📦 Tools & Technologies
- 🐍 Cowrie (SSH/Telnet honeypot)
- 🧱 T-Pot (multi-honeypot platform)
- 🐳 Docker or VirtualBox (for isolation)
- 📊 ELK Stack / Grafana (for dashboards)
- 📝 Python / Bash (for automation)

## 🧰 Setup Instructions
1. **Create a VM or container** (Ubuntu recommended).
2. **Install Cowrie**:
   ```bash
   git clone https://github.com/cowrie/cowrie.git
   cd cowrie
   ./install.sh
