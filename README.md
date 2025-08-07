# �️ Advanced Port Scanner Tool

A professional network security tool featuring both desktop GUI and web application versions. Built for network administrators, security professionals, cybersecurity students, and penetration testers.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production%20Ready-brightgreen.svg)

## 🌟 **Live Web Application**
**🔗 [Deploy Your Own Instance](https://render.com)** *(Follow deployment instructions below)*

## 📦 **Professional Versions**

### 🖥️ **Desktop Application** (`advanced_scanner.py`)
Full-featured GUI application with complete enterprise-grade port scanning capabilities.

### 🌐 **Web Application** (`web_app.py`)
Modern web-based port scanner with professional interface and API endpoints.

## ✨ **Desktop Features**

- 🖥️ **Professional GUI**: Modern tkinter interface with advanced controls
- ⚡ **High-Performance Scanning**: Multi-threaded concurrent scanning (up to 1000 threads)
- 🎯 **Comprehensive Targeting**: IP addresses, hostnames, and CIDR network ranges
- 🔍 **Advanced Protocols**: TCP Connect, TCP SYN, and UDP scanning modes
- 🏷️ **Service Discovery**: Banner grabbing with service version detection
- 🌐 **Network Discovery**: Live host discovery with ping sweep
- 📊 **Real-time Analytics**: Live charts, progress tracking, and statistics
- 📋 **Persistent History**: SQLite database with advanced search and filtering
- 💾 **Professional Reporting**: CSV, JSON, and HTML reports with styling
- ⚙️ **Enterprise Features**: Preferences, database management, help system
- 🛡️ **Security Focused**: Ethical guidelines and responsible use framework

## 🌐 **Web Application Features**

- 🎨 **Modern Interface**: Responsive design with professional styling
- 📱 **Cross-Platform**: Works on desktop, tablet, and mobile devices
- 🔍 **Flexible Scanning**: Single port, port range, and quick scan modes
- ⚡ **Fast Performance**: Multi-threaded backend with real-time updates
- 📊 **Live Results**: Dynamic result display with auto-scrolling
- 🛡️ **Professional Grade**: Full port range support with validation
- � **Export Capabilities**: JSON export for integration with other tools
- 🚀 **API Endpoints**: RESTful API for programmatic access

## 🚀 **Quick Start**

### Desktop Application
```bash
# Run the full-featured desktop version
python advanced_scanner.py

# Or run the basic version
python scanner.py
```

### Web Application
```bash
# Install dependencies
pip install -r requirements.txt

# Run web application
python web_app.py

# Access at: http://localhost:5000
```

## 🌐 **Deploy Web Application to Cloud**

### Option 1: Render.com (Recommended)
1. Fork this repository
2. Go to [render.com](https://render.com) and create account
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Use these settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python web_app.py`
   - **Plan:** Free
6. Deploy and get your live application!

### Option 2: Railway.app
1. Go to [railway.app](https://railway.app)
2. Connect GitHub repository
3. Deploy automatically
4. Get your live demo link

## 📋 **Usage Guide**

### Desktop Application
1. **Target Input**: Enter IP address, hostname, or network range
2. **Port Configuration**: Set individual ports, ranges, or comma-separated lists
3. **Advanced Options**: Choose TCP/UDP, enable banner grabbing, stealth mode
4. **Network Discovery**: Discover live hosts on networks (CIDR notation)
5. **View Results**: Real-time scanning with professional results table
6. **Export Data**: Save as CSV, JSON, or generate HTML reports
7. **History Management**: View past scans, statistics, and manage database

### Web Demo
1. **Select Target**: Choose from safe demo targets (google.com, github.com, etc.)
2. **Choose Port**: Pick common service ports (HTTP, HTTPS, SSH, etc.)
3. **Single Check**: Test individual port connectivity
4. **Quick Scan**: Automatically test multiple common ports
5. **View Results**: See real-time results with response times

## 🔧 **Requirements**

### Desktop Version
- Python 3.9+
- No external dependencies (uses standard library)
- Optional: matplotlib for visualization charts

### Web Demo Version
- Python 3.9+
- Flask 2.3.3+
- Standard library modules

## 📊 **Screenshots & Demo**

### Desktop Interface
- Modern GUI with tabbed interface
- Real-time progress tracking
- Professional results display
- Advanced scanning options

### Web Interface
- Responsive design with gradients
- Mobile-friendly layout
- Real-time scanning results
- Professional styling

## 🛡️ **Security & Ethics**

### Important Notes
- ⚠️ **Authorization Required**: Only scan networks you own or have explicit permission to test
- 🔒 **Responsible Use**: Follow ethical hacking guidelines and legal requirements
- 📚 **Educational Purpose**: Designed for learning and authorized security testing
- 🚫 **No Malicious Use**: Not intended for unauthorized access or malicious activities

### Web Demo Safety
- 🔒 **Limited Scope**: Only predefined safe targets allowed
- 🛡️ **Rate Limited**: Prevents abuse and ensures compliance
- ✅ **Platform Compliant**: Meets cloud provider security requirements
- 📚 **Educational Focus**: Demonstrates concepts safely

## 🏗️ **Project Structure**

```
PortScannerTool/
├── advanced_scanner.py    # 🎯 Full-featured desktop application
├── scanner.py             # 🔧 Basic scanner version
├── web_app.py             # 🌐 Web demo application
├── templates/
│   └── index.html         # 🎨 Web interface
├── requirements.txt       # 📦 Dependencies
├── render.yaml           # ⚙️ Render deployment config
├── runtime.txt           # 🐍 Python version
├── DEPLOYMENT.md         # 🚀 Deployment guide
└── README.md             # 📖 This file
```

## 🎯 **Use Cases**

### Professional
- **Penetration Testing**: Authorized security assessments
- **Network Auditing**: Infrastructure security reviews
- **Compliance Checking**: Verify security standards
- **Incident Response**: Network reconnaissance during investigations

### Educational
- **Cybersecurity Training**: Hands-on learning tool
- **Network Administration**: Understanding network services
- **Portfolio Development**: Demonstrate technical skills
- **Interview Preparation**: Showcase networking knowledge

## 🔧 **Advanced Features**

### Desktop Exclusive
- Raw socket operations
- Custom timeout configurations
- Unlimited target ranges
- Full network discovery
- Advanced stealth techniques
- Complete scan history database
- Professional reporting system

### Web Demo Benefits
- No installation required
- Cross-platform compatibility
- Easy sharing and demonstration
- Portfolio showcase capability
- Educational accessibility

## 📝 **Contributing**

Contributions welcome! Please feel free to submit issues, feature requests, or pull requests.

### Development Setup
```bash
git clone https://github.com/chaitanyamanyamgithub/port-scanner-tool.git
cd port-scanner-tool
pip install -r requirements.txt
python advanced_scanner.py  # Desktop version
python web_app.py           # Web version
```

## 📄 **License**

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ **Disclaimer**

This tool is for educational and authorized testing purposes only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

---

## 🌟 **Why This Project?**

This project demonstrates:
- **Network Programming**: Socket operations and protocol understanding
- **GUI Development**: Professional desktop application design
- **Web Development**: Modern responsive web applications
- **Cloud Deployment**: Platform-as-a-Service deployment skills
- **Security Awareness**: Ethical hacking and responsible disclosure
- **Software Engineering**: Clean code, documentation, and project structure

Perfect for portfolios, interviews, and demonstrating full-stack development capabilities! 🚀
