# 🌐 IPSCAN v1.0

<div align="center">

![Version](https://img.shields.io/badge/version-3.0-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.7+-green?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-red?style=for-the-badge)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge)

**A high-performance asynchronous port scanner with country-based IP targeting**
<p align="center">
  <img src="screenshot.png" width="500">
</p>
[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Contributing](#-contributing)

</div>

---

## 📖 Overview

**IPSCAN** is an ultra-fast, asynchronous port scanner designed for large-scale network reconnaissance. Built with Python's `asyncio`, it can scan thousands of IPs per second, supporting both RDP (3389) and SSH (22) protocols, with customizable port options. The tool includes pre-configured country IP ranges sourced from IPDeny.com.

### 🎯 Key Capabilities

- **Massive-scale scanning** - Handle thousands of concurrent connections
- **Country-based targeting** - Pre-loaded IP ranges for 20+ countries
- **Dual protocol support** - Optimized for RDP and SSH detection
- **Real-time statistics** - Live progress tracking with ETA
- **Custom IP ranges** - Load your own CIDR ranges from files
- **Auto-saving results** - All open ports automatically logged to `open.txt`

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔥 Core Features
- ⚡ **Asynchronous I/O** - Non-blocking operations for maximum speed
- 🎯 **20+ Countries** - Built-in IP ranges for quick targeting
- 📊 **Live Dashboard** - Real-time scan progress visualization
- 💾 **Auto-export** - Results saved automatically to `open.txt`
- 🎨 **Color-coded Output** - Beautiful terminal interface
- 🔒 **Smart Connection Handling** - Proper resource cleanup

</td>
<td width="50%">

### 🛠️ Technical Highlights
- 🚀 **100-2000 Concurrent Connections** - Adjustable thread pool
- ⏱️ **1.5s Timeout** - Fast response detection
- 📦 **Zero Dependencies** - Pure Python standard library
- 🔄 **Auto-retry Logic** - Robust error handling
- 📈 **Speed Metrics** - IPs/second calculation with ETA
- 🌍 **International IP Support** - IPv4 CIDR parsing

</td>
</tr>
</table>

---

## 📥 Installation

### Prerequisites
- **Python 3.7** or higher
- **pip** (Python package manager)

### 🐧 Linux Installation

```bash
# Clone the repository
git clone https://github.com/S1A7ASH/IPSCAN-BLACKCAT_TM.git
cd iIPSCAN-BLACKCAT_TM

# Make the script executable (optional)
chmod +x IPSCAN-BLACKCAT_TM.py
python IPSCAN-BLACKCAT_TM.py

# Done! No additional dependencies needed
