# 🔍 Advanced Port Scanner Tool

A comprehensive network security tool featuring both desktop GUI and web demo versions. Perfect for network administrators, security professionals, and educational purposes.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Web Demo](https://img.shields.io/badge/Demo-Live%20Web%20App-brightgreen.svg)

## 🌟 **Live Web Demo**
**🔗 [Try the Live Demo](https://port-scanner-tool-1.onrender.com)** 

## 📦 **Two Versions Available**

### 🖥️ **Desktop Version** (`advanced_scanner.py`)
Full-featured GUI application with complete port scanning capabilities.

### 🌐 **Web Demo Version** (`web_app.py`)
Safe, cloud-deployable demonstration version for online showcase.

## ✨ **Desktop Features**

- 🖥️ **Modern GUI Interface**: Professional tkinter-based interface
- ⚡ **Multi-threaded Scanning**: Fast, concurrent port scanning (configurable threads)
- 🎯 **Flexible Targeting**: IP addresses, hostnames, and network ranges
- 🔍 **Advanced Scanning**: TCP/UDP protocols with stealth mode
- 🏷️ **Banner Grabbing**: Service version detection and identification
- 🌐 **Network Discovery**: Live host discovery with CIDR support
- 📊 **Real-time Visualization**: Live charts and progress tracking
- 📋 **Scan History**: SQLite database with search and filtering
- 💾 **Multiple Export Formats**: CSV, JSON, and styled HTML reports
- ⚙️ **Professional Features**: Preferences, database manager, help system
- 🛡️ **Security Focused**: Ethical guidelines and responsible use features

## 🌐 **Web Demo Features**

- 🔒 **Cloud-Safe**: Compliant with platform security policies
- 🎨 **Modern UI**: Responsive design with gradient styling
- 📱 **Mobile Friendly**: Works on all devices
- 🔍 **Service Checking**: Test common ports on predefined targets
- ⚡ **Quick Scan**: Automated scanning of popular services
- 📊 **Real-time Results**: Live updates with response times
- 🛡️ **Educational**: Safe demonstration of networking concepts

## 🚀 **Quick Start**

### Desktop Version
```bash
# Run the advanced GUI version
python advanced_scanner.py

# Or run the basic version
python scanner.py
```

### Web Demo Version
```bash
# Install dependencies
pip install -r requirements.txt

# Run web application
python web_app.py

# Access at: http://localhost:5000
```

## 🌐 **Deploy Web Demo to Cloud**

### Option 1: Render.com (Recommended)
1. Fork this repository
2. Go to [render.com](https://render.com) and create account
3. Click "New +" → "Web Service"
4. Connect your GitHub repository
5. Use these settings:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python web_app.py`
   - **Plan:** Free
6. Deploy and get your live link!

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
