# 🔍 Port Scanner Tool

A powerful, user-friendly port scanning tool with a modern graphical interface built in Python. Perfect for network administrators, security professionals, and anyone who needs to scan network ports efficiently.

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

## ✨ Features

- 🖥️ **Modern GUI Interface**: Clean, intuitive interface built with tkinter
- ⚡ **Multi-threaded Scanning**: Fast, concurrent port scanning with configurable thread pools
- 🎯 **Flexible Targeting**: Supports both IP addresses and hostnames
- 📊 **Real-time Progress**: Live progress tracking with status updates
- 🔍 **Service Detection**: Automatically identifies common services running on open ports
- 💾 **Export Results**: Save scan results to CSV format for analysis
- ⚙️ **Configurable Settings**: Adjustable timeout, thread count, and port ranges
- 🛡️ **Error Handling**: Robust error handling with user-friendly messages

## 🚀 Quick Start

### Requirements
- Python 3.6 or higher
- No external dependencies (uses only standard library)

### Installation
1. Download or clone this repository
2. Navigate to the project directory
3. Run the scanner:

```bash
python scanner.py
```

## 📋 Usage Guide

### Basic Scanning
1. **Enter Target**: Input an IP address (e.g., `192.168.1.1`) or hostname (e.g., `google.com`)
2. **Set Port Range**: Define start and end ports (default: 1-1000)
3. **Configure Settings**: Adjust timeout and thread count if needed
4. **Start Scan**: Click "Start Scan" to begin
5. **View Results**: Monitor progress and view open ports in real-time

### GUI Components

| Component | Description | Default Value |
|-----------|-------------|---------------|
| **Target Host/IP** | Target to scan (IP or hostname) | `127.0.0.1` |
| **Port Range** | Start and end port numbers | `1` to `1000` |
| **Timeout** | Connection timeout in seconds | `1` second |
| **Thread Count** | Number of concurrent threads | `100` threads |

### Buttons
- **Start Scan**: Begin port scanning
- **Stop Scan**: Interrupt ongoing scan
- **Save Results**: Export results to CSV file
- **Clear Results**: Clear current scan results

## 📊 Sample Output

The tool displays results in a table format:

| Port | State | Service | Timestamp |
|------|-------|---------|-----------|
| 22 | Open | SSH | 2025-07-08 14:30:15 |
| 80 | Open | HTTP | 2025-07-08 14:30:16 |
| 443 | Open | HTTPS | 2025-07-08 14:30:17 |

Results are automatically saved to `results.csv` for further analysis.

## 🎯 Common Use Cases

### Local Network Scanning
```
Target: 192.168.1.1
Port Range: 1-1000
Timeout: 1
Threads: 100
```

### Web Server Check
```
Target: example.com
Port Range: 80,443
Timeout: 2
Threads: 50
```

### Comprehensive Scan
```
Target: target.com
Port Range: 1-65535
Timeout: 1
Threads: 200
```

## 🔧 Configuration Tips

### Performance Optimization
- **Higher Thread Count**: Faster scanning but may trigger firewalls
- **Lower Timeout**: Quicker scans but may miss slow services
- **Smaller Port Ranges**: Faster results for targeted scanning

### Network Considerations
- Local scans are significantly faster than internet scans
- Some firewalls may block or rate-limit port scanning
- Use lower thread counts for external targets

## 🛡️ Security & Ethics

### ⚠️ Important Notice
This tool is intended for:
- ✅ Testing your own systems and networks
- ✅ Educational and learning purposes
- ✅ Authorized security assessments
- ✅ Network troubleshooting and administration

### 🚫 Do NOT use for:
- ❌ Unauthorized scanning of systems you don't own
- ❌ Malicious activities or attacks
- ❌ Violating terms of service or laws

**Always ensure you have explicit permission before scanning any system.**

## 🔍 Detected Services

The tool automatically identifies common services:

| Port | Service | Description |
|------|---------|-------------|
| 21 | FTP | File Transfer Protocol |
| 22 | SSH | Secure Shell |
| 23 | Telnet | Telnet Protocol |
| 25 | SMTP | Simple Mail Transfer Protocol |
| 53 | DNS | Domain Name System |
| 80 | HTTP | Hypertext Transfer Protocol |
| 110 | POP3 | Post Office Protocol v3 |
| 143 | IMAP | Internet Message Access Protocol |
| 443 | HTTPS | HTTP over TLS/SSL |
| 993 | IMAPS | IMAP over TLS/SSL |
| 995 | POP3S | POP3 over TLS/SSL |
| 3306 | MySQL | MySQL Database |
| 3389 | RDP | Remote Desktop Protocol |
| 5432 | PostgreSQL | PostgreSQL Database |

## 🐛 Troubleshooting

### Common Issues

**"Permission denied" errors**
- Windows: Run as Administrator
- Linux/macOS: Use `sudo python scanner.py`

**Slow scanning performance**
- Reduce thread count (try 50-100)
- Increase timeout for slower networks
- Scan smaller port ranges

**No results found**
- Check firewall settings
- Verify network connectivity
- Try scanning localhost (127.0.0.1) first

**Hostname resolution fails**
- Use IP address instead of hostname
- Check DNS settings
- Verify internet connection

### Error Messages
- **"Could not resolve hostname"**: DNS resolution failed
- **"Input Error"**: Invalid port range or settings
- **"Scan Error"**: Network connectivity issues

## 📁 File Structure

```
PortScannerTool/
├── scanner.py       # Main application file
├── README.md        # This documentation
└── results.csv      # Generated after scan (auto-created)
```

## 🔧 Technical Details

- **Language**: Python 3.6+
- **GUI Framework**: tkinter (included with Python)
- **Threading**: `concurrent.futures.ThreadPoolExecutor`
- **Networking**: Standard `socket` library
- **File Format**: CSV (Comma-Separated Values)

## 📝 CSV Output Format

```csv
Port,State,Service,Timestamp
22,Open,SSH,2025-07-08 14:30:15
80,Open,HTTP,2025-07-08 14:30:16
443,Open,HTTPS,2025-07-08 14:30:17
```

## 🤝 Contributing

Contributions are welcome! Please feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

If you encounter any issues or have questions:
1. Check the troubleshooting section above
2. Review the error messages for clues
3. Ensure you're using Python 3.6+
4. Verify network connectivity

## 🎯 Future Enhancements

Potential improvements for future versions:
- [ ] UDP port scanning support
- [ ] OS detection capabilities
- [ ] Custom service definitions
- [ ] Scan scheduling
- [ ] Network range scanning
- [ ] Export to multiple formats (JSON, XML)
- [ ] Advanced filtering options

---

**⚡ Ready to scan? Run `python scanner.py` and start exploring your network!**

**⚠️ Remember: Use responsibly and only scan systems you own or have permission to test.**