#!/usr/bin/env python3
"""
Advanced Port Scanner Tool with GUI
A powerful and feature-rich port scanning tool with modern GUI interface.
"""

import socket
import threading
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import csv
import datetime
import queue
import time
import json
import random
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
import ipaddress

# Optional imports for visualization
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False


class AdvancedPortScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("🔍 Advanced Port Scanner Tool v2.0")
        self.root.geometry("1400x900")
        self.root.resizable(True, True)
        
        # Variables
        self.scanning = False
        self.results = []
        self.progress_queue = queue.Queue()
        self.scan_history = []
        
        # Initialize database
        self.setup_database()
        
        # Setup menu system
        self.setup_menu()
        
        # Setup GUI
        self.setup_gui()
        
        # Setup optional real-time visualization
        self.setup_visualization()
        
        # Setup network discovery
        self.setup_network_discovery()
        
        # Setup scan history viewer
        self.setup_scan_history_viewer()
    
    def setup_database(self):
        """Initialize SQLite database for scan history"""
        try:
            self.conn = sqlite3.connect('scan_history.db')
            cursor = self.conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT,
                    port INTEGER,
                    state TEXT,
                    service TEXT,
                    banner TEXT,
                    scan_time TIMESTAMP,
                    scan_type TEXT
                )
            ''')
            
            self.conn.commit()
        except Exception as e:
            print(f"Database setup error: {e}")
    
    def setup_gui(self):
        """Create and setup the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Target input
        ttk.Label(main_frame, text="🎯 Target Host/IP:").grid(row=0, column=0, sticky="w", pady=5)
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(main_frame, textvariable=self.target_var, width=30)
        self.target_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=(5, 0))
        
        # Port range input
        ttk.Label(main_frame, text="🚪 Port Range:").grid(row=1, column=0, sticky="w", pady=5)
        port_frame = ttk.Frame(main_frame)
        port_frame.grid(row=1, column=1, sticky="ew", pady=5, padx=(5, 0))
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1000")
        
        ttk.Entry(port_frame, textvariable=self.start_port_var, width=10).pack(side=tk.LEFT)
        ttk.Label(port_frame, text=" to ").pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.end_port_var, width=10).pack(side=tk.LEFT)
        
        # Timeout setting
        ttk.Label(main_frame, text="⏱️ Timeout (seconds):").grid(row=2, column=0, sticky="w", pady=5)
        self.timeout_var = tk.StringVar(value="1")
        ttk.Entry(main_frame, textvariable=self.timeout_var, width=10).grid(row=2, column=1, sticky="w", pady=5, padx=(5, 0))
        
        # Thread count
        ttk.Label(main_frame, text="🧵 Thread Count:").grid(row=3, column=0, sticky="w", pady=5)
        self.threads_var = tk.StringVar(value="100")
        ttk.Entry(main_frame, textvariable=self.threads_var, width=10).grid(row=3, column=1, sticky="w", pady=5, padx=(5, 0))
        
        # Advanced scanning options
        advanced_frame = ttk.LabelFrame(main_frame, text="🔧 Advanced Options", padding="5")
        advanced_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Scan type selection
        scan_type_frame = ttk.Frame(advanced_frame)
        scan_type_frame.pack(fill=tk.X, pady=2)
        
        ttk.Label(scan_type_frame, text="Scan Type:").pack(side=tk.LEFT)
        self.scan_type = tk.StringVar(value="tcp")
        ttk.Radiobutton(scan_type_frame, text="TCP Connect", variable=self.scan_type, value="tcp").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(scan_type_frame, text="UDP Scan", variable=self.scan_type, value="udp").pack(side=tk.LEFT, padx=5)
        
        # Additional options
        options_frame = ttk.Frame(advanced_frame)
        options_frame.pack(fill=tk.X, pady=2)
        
        self.banner_grab_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="🏷️ Banner Grabbing", variable=self.banner_grab_var).pack(side=tk.LEFT, padx=5)
        
        self.stealth_mode_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="🥷 Stealth Mode", variable=self.stealth_mode_var).pack(side=tk.LEFT, padx=5)
        
        self.host_discovery_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="🔍 Host Discovery", variable=self.host_discovery_var).pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
        self.scan_button = ttk.Button(button_frame, text="▶️ Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹️ Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="💾 Save CSV", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.export_json_button = ttk.Button(button_frame, text="📄 Export JSON", command=self.export_to_json)
        self.export_json_button.pack(side=tk.LEFT, padx=5)
        
        self.report_button = ttk.Button(button_frame, text="📊 HTML Report", command=self.generate_html_report)
        self.report_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="🗑️ Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=6, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=7, column=0, columnspan=2, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="📋 Scan Results", padding="5")
        results_frame.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(8, weight=1)
        
        # Treeview for results with additional columns
        columns = ("Port", "State", "Service", "Banner", "Timestamp")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            if col == "Banner":
                self.tree.column(col, width=200)
            else:
                self.tree.column(col, width=120)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout for tree and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Panels are setup by the individual setup methods called in __init__
    
    def setup_menu(self):
        """Create menu bar with additional functionality"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="💾 Save Results...", command=self.save_results)
        file_menu.add_command(label="📄 Export JSON...", command=self.export_to_json)
        file_menu.add_command(label="📊 Generate HTML Report...", command=self.generate_html_report)
        file_menu.add_separator()
        file_menu.add_command(label="🚪 Exit", command=self.root.quit)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="🔧 Tools", menu=tools_menu)
        tools_menu.add_command(label="🌐 Network Discovery", command=self.open_network_discovery)
        tools_menu.add_command(label="📋 Scan History", command=self.show_scan_history)
        tools_menu.add_command(label="📊 History Statistics", command=self.show_history_stats)
        tools_menu.add_command(label="🗄️ Database Manager", command=self.database_manager)
        tools_menu.add_command(label="🗑️ Clear History", command=self.clear_scan_history)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="⚙️ Settings", menu=settings_menu)
        settings_menu.add_command(label="🔧 Preferences", command=self.show_preferences)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="📖 User Guide", command=self.show_user_guide)
        help_menu.add_command(label="🛡️ Security Tips", command=self.show_security_tips)
        help_menu.add_command(label="ℹ️ About", command=self.show_about)
    
    def setup_visualization(self):
        """Setup real-time visualization if matplotlib is available"""
        try:
            import matplotlib.pyplot as plt
            from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
            from matplotlib.figure import Figure
            
            self.matplotlib_available = True
            self.visualization_data = {'open_ports': [], 'timestamps': []}
            
            # Create visualization frame
            viz_frame = ttk.LabelFrame(self.root, text="📈 Real-time Visualization", padding="5")
            viz_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
            
            # Create matplotlib figure
            self.fig = Figure(figsize=(12, 3), dpi=80)
            self.ax = self.fig.add_subplot(111)
            self.ax.set_title("Open Ports Discovery Rate")
            self.ax.set_xlabel("Time")
            self.ax.set_ylabel("Cumulative Open Ports")
            
            # Create canvas
            self.canvas = FigureCanvasTkAgg(self.fig, viz_frame)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            
        except ImportError:
            self.matplotlib_available = False
            # Create fallback text display
            viz_frame = ttk.LabelFrame(self.root, text="📊 Scan Progress", padding="5")
            viz_frame.grid(row=1, column=0, sticky="ew", padx=10, pady=5)
            
            self.progress_text = tk.Text(viz_frame, height=4, state=tk.DISABLED)
            self.progress_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_network_discovery(self):
        """Setup network discovery functionality"""
        self.discovered_hosts = []
    
    def setup_scan_history_viewer(self):
        """Setup scan history viewing functionality"""
        pass
    
    def validate_inputs(self):
        """Validate user inputs"""
        try:
            # Validate target
            target = self.target_var.get().strip()
            if not target:
                raise ValueError("Target host/IP cannot be empty")
            
            # Try to parse as IP address, if it fails, assume it's a hostname
            try:
                ipaddress.ip_address(target)
            except ipaddress.AddressValueError:
                # It's probably a hostname, which is fine
                pass
            
            # Validate port range
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            
            if start_port < 1 or start_port > 65535:
                raise ValueError("Start port must be between 1 and 65535")
            if end_port < 1 or end_port > 65535:
                raise ValueError("End port must be between 1 and 65535")
            if start_port > end_port:
                raise ValueError("Start port cannot be greater than end port")
            
            # Validate timeout
            timeout = float(self.timeout_var.get())
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0")
            
            # Validate thread count
            threads = int(self.threads_var.get())
            if threads < 1 or threads > 1000:
                raise ValueError("Thread count must be between 1 and 1000")
            
            return target, start_port, end_port, timeout, threads
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return None
    
    def get_service_name(self, port):
        """Get common service name for a port"""
        services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5432: "PostgreSQL", 3306: "MySQL",
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 5672: "RabbitMQ",
            8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "HTTP-Proxy", 3128: "Squid"
        }
        return services.get(port, "Unknown")
    
    def banner_grab(self, target, port, timeout):
        """Grab service banners for version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            elif port == 22:  # SSH
                pass  # SSH sends banner immediately
            elif port == 21:  # FTP
                pass  # FTP sends banner immediately
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            return banner[:100]  # Limit banner length
        except:
            return ""
    
    def detect_service_version(self, target, port, timeout):
        """Advanced service detection with banner grabbing"""
        service = self.get_service_name(port)
        banner = self.banner_grab(target, port, timeout)
        
        # Parse common service banners
        if banner:
            if "Apache" in banner:
                service += " (Apache)"
            elif "nginx" in banner:
                service += " (Nginx)"
            elif "SSH" in banner:
                version = banner.split()[0] if banner else ""
                service += f" ({version})"
            elif "FTP" in banner:
                service += " (FTP Server)"
            elif "Microsoft" in banner:
                service += " (Microsoft)"
        
        return service, banner
    
    def udp_scan_port(self, target, port, timeout):
        """UDP port scanning"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"UDP_PROBE", (target, port))
            
            try:
                data, addr = sock.recvfrom(1024)
                sock.close()
                return (port, "Open", self.get_service_name(port), "", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            except socket.timeout:
                sock.close()
                return (port, "Open|Filtered", self.get_service_name(port), "", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        except:
            return None
    
    def scan_port(self, target, port, timeout):
        """Scan a single port with advanced detection"""
        try:
            scan_type = self.scan_type.get()
            
            if scan_type == "udp":
                return self.udp_scan_port(target, port, timeout)
            
            # TCP scan
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = self.get_service_name(port)
                banner = ""
                
                # Banner grabbing if enabled
                if self.banner_grab_var.get():
                    service, banner = self.detect_service_version(target, port, timeout)
                
                # Stealth mode delay
                if self.stealth_mode_var.get():
                    time.sleep(random.uniform(0.1, 0.5))
                
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                return (port, "Open", service, banner, timestamp)
            
        except Exception:
            pass
        
        return None
    
    def scan_worker(self, target, ports, timeout, results_queue, progress_queue):
        """Worker function for scanning ports"""
        for port in ports:
            if not self.scanning:
                break
            
            result = self.scan_port(target, port, timeout)
            if result:
                results_queue.put(result)
            
            progress_queue.put(1)
    
    def start_scan(self):
        """Start the port scanning process"""
        validation_result = self.validate_inputs()
        if not validation_result:
            return
        
        target, start_port, end_port, timeout, max_threads = validation_result
        
        # Clear previous results
        self.clear_results()
        
        # Update UI state
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        self.status_var.set(f"🔍 Scanning {target}...")
        
        # Start scanning in a separate thread
        scan_thread = threading.Thread(
            target=self.run_scan, 
            args=(target, start_port, end_port, timeout, max_threads)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        # Start progress monitoring
        self.monitor_progress()
    
    def run_scan(self, target, start_port, end_port, timeout, max_threads):
        """Run the actual port scan"""
        try:
            # Resolve hostname to IP if needed
            try:
                target_ip = socket.gethostbyname(target)
                if target != target_ip:
                    self.status_var.set(f"🔍 Scanning {target} ({target_ip})...")
            except socket.gaierror:
                messagebox.showerror("Error", f"Could not resolve hostname: {target}")
                self.scan_finished()
                return
            
            total_ports = end_port - start_port + 1
            self.total_ports = total_ports
            self.scanned_ports = 0
            
            # Create port list
            ports = list(range(start_port, end_port + 1))
            
            # Randomize port order if stealth mode is enabled
            if self.stealth_mode_var.get():
                random.shuffle(ports)
            
            # Split ports among threads
            chunk_size = max(1, len(ports) // max_threads)
            port_chunks = [ports[i:i + chunk_size] for i in range(0, len(ports), chunk_size)]
            
            # Create queues for results and progress
            results_queue = queue.Queue()
            
            # Start thread pool
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for chunk in port_chunks:
                    if not self.scanning:
                        break
                    future = executor.submit(
                        self.scan_worker, target_ip, chunk, timeout, 
                        results_queue, self.progress_queue
                    )
                    futures.append(future)
                
                # Wait for all threads to complete
                for future in futures:
                    if not self.scanning:
                        break
                    future.result()
            
            # Collect remaining results
            while not results_queue.empty():
                result = results_queue.get()
                self.results.append(result)
                self.tree.insert("", tk.END, values=result)
            
            # Save to database
            if self.results:
                self.save_to_database(target, self.results, self.scan_type.get())
            
            if self.scanning:
                self.status_var.set(f"✅ Scan completed. Found {len(self.results)} open ports.")
            else:
                self.status_var.set("⏹️ Scan stopped by user.")
            
        except Exception as e:
            messagebox.showerror("Scan Error", f"An error occurred during scanning: {str(e)}")
        finally:
            self.scan_finished()
    
    def monitor_progress(self):
        """Monitor and update progress"""
        try:
            while not self.progress_queue.empty():
                self.progress_queue.get()
                self.scanned_ports += 1
                if hasattr(self, 'total_ports') and self.total_ports > 0:
                    progress = (self.scanned_ports / self.total_ports) * 100
                    self.progress_var.set(progress)
        except:
            pass
        
        if self.scanning:
            self.root.after(100, self.monitor_progress)
    
    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.scan_finished()
    
    def scan_finished(self):
        """Reset UI state after scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
    
    def clear_results(self):
        """Clear all scan results"""
        self.results = []
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.status_var.set("Ready to scan.")
    
    def save_to_database(self, target, results, scan_type):
        """Save scan results to database"""
        try:
            cursor = self.conn.cursor()
            scan_time = datetime.datetime.now()
            
            for result in results:
                banner = result[3] if len(result) > 3 else ""
                cursor.execute('''
                    INSERT INTO scan_history (target, port, state, service, banner, scan_time, scan_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (target, result[0], result[1], result[2], banner, scan_time, scan_type))
            
            self.conn.commit()
        except Exception as e:
            print(f"Database save error: {e}")
    
    def save_results(self):
        """Save scan results to CSV file"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to save.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile="scan_results.csv"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Port", "State", "Service", "Banner", "Timestamp"])
                    
                    for result in self.results:
                        writer.writerow(result)
                
                messagebox.showinfo("Success", f"Results saved to {filename}")
                
                # Also save to default results.csv in the same directory
                default_path = "results.csv"
                with open(default_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Port", "State", "Service", "Banner", "Timestamp"])
                    for result in self.results:
                        writer.writerow(result)
                
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save file: {str(e)}")
    
    def export_to_json(self):
        """Export results to JSON format"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            initialfile="scan_results.json"
        )
        
        if filename:
            try:
                export_data = {
                    "scan_info": {
                        "target": self.target_var.get(),
                        "scan_time": datetime.datetime.now().isoformat(),
                        "scan_type": self.scan_type.get(),
                        "total_ports": len(self.results),
                        "banner_grabbing": self.banner_grab_var.get(),
                        "stealth_mode": self.stealth_mode_var.get()
                    },
                    "results": [
                        {
                            "port": r[0], 
                            "state": r[1], 
                            "service": r[2], 
                            "banner": r[3] if len(r) > 3 else "", 
                            "timestamp": r[4] if len(r) > 4 else r[3]
                        }
                        for r in self.results
                    ]
                }
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not export file: {str(e)}")
    
    def generate_html_report(self):
        """Generate HTML report"""
        if not self.results:
            messagebox.showwarning("No Results", "No scan results to generate report.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialfile="scan_report.html"
        )
        
        if filename:
            try:
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>🔍 Advanced Port Scan Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                   color: white; padding: 25px; border-radius: 15px; margin-bottom: 20px; 
                   box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .summary {{ background: white; padding: 20px; border-radius: 10px; margin-bottom: 20px; 
                   box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        table {{ border-collapse: collapse; width: 100%; background: white; border-radius: 10px; 
                overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        th, td {{ padding: 15px; text-align: left; border-bottom: 1px solid #eee; }}
        th {{ background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); color: white; font-weight: 600; }}
        .open {{ background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); }}
        .filtered {{ background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); }}
        .banner {{ font-family: 'Courier New', monospace; font-size: 0.9em; max-width: 300px; 
                  overflow: hidden; background: #f8f9fa; padding: 5px; border-radius: 3px; }}
        .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
        .stat-box {{ background: white; padding: 20px; border-radius: 10px; text-align: center; 
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }}
        .stat-number {{ font-size: 2em; font-weight: bold; color: #667eea; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Advanced Port Scan Report</h1>
        <p><strong>🎯 Target:</strong> {self.target_var.get()}</p>
        <p><strong>📅 Scan Date:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>🔧 Scan Type:</strong> {self.scan_type.get().upper()}</p>
    </div>
    
    <div class="stats">
        <div class="stat-box">
            <div class="stat-number">{len(self.results)}</div>
            <div>Open Ports</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{'✅' if self.banner_grab_var.get() else '❌'}</div>
            <div>Banner Grabbing</div>
        </div>
        <div class="stat-box">
            <div class="stat-number">{'🥷' if self.stealth_mode_var.get() else '🚀'}</div>
            <div>Scan Mode</div>
        </div>
    </div>
    
    <div class="summary">
        <h2>📊 Scan Summary</h2>
        <p><strong>Total Open Ports:</strong> {len(self.results)}</p>
        <p><strong>Banner Grabbing:</strong> {'Enabled' if self.banner_grab_var.get() else 'Disabled'}</p>
        <p><strong>Stealth Mode:</strong> {'Enabled' if self.stealth_mode_var.get() else 'Disabled'}</p>
    </div>
    
    <h2>🚪 Port Details</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>State</th>
            <th>Service</th>
            <th>Banner</th>
            <th>Timestamp</th>
        </tr>
"""
                
                for result in self.results:
                    row_class = "open" if result[1] == "Open" else "filtered"
                    banner = result[3] if len(result) > 3 else ""
                    timestamp = result[4] if len(result) > 4 else result[3]
                    
                    html_content += f"""
        <tr class="{row_class}">
            <td><strong>{result[0]}</strong></td>
            <td>{"🟢" if result[1] == "Open" else "🟡"} {result[1]}</td>
            <td>{result[2]}</td>
            <td class="banner">{banner}</td>
            <td>{timestamp}</td>
        </tr>"""
                
                html_content += """
    </table>
    
    <div style="margin-top: 30px; text-align: center; color: #666; padding: 20px;">
        <p>📊 Report generated by Advanced Port Scanner Tool</p>
        <p>🛡️ Use responsibly and only on authorized systems</p>
    </div>
</body>
</html>
"""
                
                with open(filename, 'w') as f:
                    f.write(html_content)
                    
                messagebox.showinfo("Success", f"HTML report generated: {filename}")
                
            except Exception as e:
                messagebox.showerror("Report Error", f"Could not generate report: {str(e)}")
    
    # Menu action methods
    def show_preferences(self):
        """Show preferences dialog"""
        prefs_window = tk.Toplevel(self.root)
        prefs_window.title("⚙️ Preferences")
        prefs_window.geometry("400x300")
        prefs_window.transient(self.root)
        prefs_window.grab_set()
        
        # Center the window
        prefs_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        notebook = ttk.Notebook(prefs_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # General preferences
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="General")
        
        ttk.Label(general_frame, text="Default Timeout (seconds):").pack(anchor="w", pady=5)
        timeout_var = tk.StringVar(value="3")
        ttk.Entry(general_frame, textvariable=timeout_var).pack(fill="x", pady=5)
        
        ttk.Label(general_frame, text="Default Thread Count:").pack(anchor="w", pady=5)
        thread_var = tk.StringVar(value="100")
        ttk.Entry(general_frame, textvariable=thread_var).pack(fill="x", pady=5)
        
        # Scan preferences
        scan_frame = ttk.Frame(notebook)
        notebook.add(scan_frame, text="Scanning")
        
        enable_banner = tk.BooleanVar(value=True)
        ttk.Checkbutton(scan_frame, text="Enable banner grabbing by default", variable=enable_banner).pack(anchor="w", pady=5)
        
        enable_stealth = tk.BooleanVar(value=False)
        ttk.Checkbutton(scan_frame, text="Enable stealth mode by default", variable=enable_stealth).pack(anchor="w", pady=5)
        
        # Buttons
        button_frame = ttk.Frame(prefs_window)
        button_frame.pack(fill="x", padx=10, pady=10)
        
        ttk.Button(button_frame, text="Save", command=prefs_window.destroy).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Cancel", command=prefs_window.destroy).pack(side="right")
    
    def database_manager(self):
        """Show database manager dialog"""
        db_window = tk.Toplevel(self.root)
        db_window.title("🗄️ Database Manager")
        db_window.geometry("600x400")
        db_window.transient(self.root)
        db_window.grab_set()
        
        # Center the window
        db_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Database info
        info_frame = ttk.LabelFrame(db_window, text="Database Information", padding="10")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            count = cursor.fetchone()[0]
            ttk.Label(info_frame, text=f"Total scan records: {count}").pack(anchor="w")
            
            cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM scan_history")
            min_date, max_date = cursor.fetchone()
            if min_date:
                ttk.Label(info_frame, text=f"Date range: {min_date} to {max_date}").pack(anchor="w")
        except Exception as e:
            ttk.Label(info_frame, text=f"Error accessing database: {str(e)}").pack(anchor="w")
        
        # Actions
        action_frame = ttk.LabelFrame(db_window, text="Actions", padding="10")
        action_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(action_frame, text="🗑️ Clear All History", 
                  command=lambda: self.clear_scan_history(confirm=True)).pack(side="left", padx=5)
        ttk.Button(action_frame, text="💾 Backup Database", 
                  command=self.backup_database).pack(side="left", padx=5)
        ttk.Button(action_frame, text="📊 Export All Data", 
                  command=self.export_all_data).pack(side="left", padx=5)
        
        ttk.Button(db_window, text="Close", command=db_window.destroy).pack(pady=10)
    
    def show_about(self):
        """Show about dialog"""
        about_window = tk.Toplevel(self.root)
        about_window.title("ℹ️ About Port Scanner")
        about_window.geometry("400x300")
        about_window.transient(self.root)
        about_window.grab_set()
        about_window.resizable(False, False)
        
        # Center the window
        about_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 100))
        
        # Create main frame
        main_frame = ttk.Frame(about_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="🔍 Advanced Port Scanner", 
                               font=("Arial", 16, "bold"))
        title_label.pack(pady=10)
        
        # Version info
        version_label = ttk.Label(main_frame, text="Version 2.0", 
                                 font=("Arial", 12))
        version_label.pack(pady=5)
        
        # Description
        desc_text = """A professional network security tool for port scanning, 
network discovery, and security assessment.

Features:
• TCP/UDP Port Scanning
• Banner Grabbing
• Stealth Mode
• Network Discovery
• Scan History & Analytics
• Export to Multiple Formats
• Real-time Visualization"""
        
        desc_label = ttk.Label(main_frame, text=desc_text, 
                              justify=tk.LEFT, wraplength=350)
        desc_label.pack(pady=10)
        
        # Copyright
        copyright_label = ttk.Label(main_frame, text="© 2024 - For Educational Use Only", 
                                   font=("Arial", 9, "italic"))
        copyright_label.pack(pady=10)
        
        # Close button
        ttk.Button(main_frame, text="Close", command=about_window.destroy).pack(pady=10)
    
    def open_network_discovery(self):
        """Open network discovery window"""
        discovery_window = tk.Toplevel(self.root)
        discovery_window.title("🌐 Network Discovery")
        discovery_window.geometry("600x500")
        discovery_window.transient(self.root)
        
        # Center the window
        discovery_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Input frame
        input_frame = ttk.LabelFrame(discovery_window, text="Network Range", padding="10")
        input_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(input_frame, text="Network (e.g., 192.168.1.0/24):").pack(anchor="w")
        network_var = tk.StringVar(value="192.168.1.0/24")
        network_entry = ttk.Entry(input_frame, textvariable=network_var, width=30)
        network_entry.pack(fill="x", pady=5)
        
        # Buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill="x", pady=5)
        
        ttk.Button(button_frame, text="🔍 Discover Hosts", 
                  command=lambda: self.discover_network_hosts(network_var.get(), results_tree)).pack(side="left")
        ttk.Button(button_frame, text="📋 Use Selected Host", 
                  command=lambda: self.select_discovered_host(results_tree, discovery_window)).pack(side="left", padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(discovery_window, text="Discovered Hosts", padding="10")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Treeview for results
        columns = ("IP", "Hostname", "Status", "Response Time")
        results_tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            results_tree.heading(col, text=col)
            results_tree.column(col, width=140)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=results_tree.yview)
        results_tree.configure(yscrollcommand=scrollbar.set)
        
        results_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Status
        self.discovery_status = ttk.Label(discovery_window, text="Ready to discover hosts...")
        self.discovery_status.pack(pady=5)
    
    def show_scan_history(self):
        """Show scan history window"""
        history_window = tk.Toplevel(self.root)
        history_window.title("📋 Scan History")
        history_window.geometry("800x600")
        history_window.transient(self.root)
        
        # Center the window
        history_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Filter frame
        filter_frame = ttk.LabelFrame(history_window, text="Filters", padding="10")
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Target:").grid(row=0, column=0, sticky="w", padx=5)
        target_filter = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=target_filter, width=20).grid(row=0, column=1, padx=5)
        
        ttk.Label(filter_frame, text="Date:").grid(row=0, column=2, sticky="w", padx=5)
        date_filter = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=date_filter, width=15).grid(row=0, column=3, padx=5)
        
        ttk.Button(filter_frame, text="🔍 Filter", 
                  command=lambda: self.filter_history(target_filter.get(), date_filter.get(), history_tree)).grid(row=0, column=4, padx=5)
        ttk.Button(filter_frame, text="🔄 Refresh", 
                  command=lambda: self.load_scan_history(history_tree)).grid(row=0, column=5, padx=5)
        
        # History tree
        history_frame = ttk.Frame(history_window)
        history_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("ID", "Target", "Ports", "Open Ports", "Timestamp", "Duration")
        history_tree = ttk.Treeview(history_frame, columns=columns, show="headings", height=20)
        
        for col in columns:
            history_tree.heading(col, text=col)
            if col == "ID":
                history_tree.column(col, width=50)
            elif col == "Target":
                history_tree.column(col, width=150)
            elif col == "Timestamp":
                history_tree.column(col, width=150)
            else:
                history_tree.column(col, width=100)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(history_frame, orient="vertical", command=history_tree.yview)
        h_scrollbar = ttk.Scrollbar(history_frame, orient="horizontal", command=history_tree.xview)
        history_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        history_tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
        history_frame.grid_rowconfigure(0, weight=1)
        history_frame.grid_columnconfigure(0, weight=1)
        
        # Load initial data
        self.load_scan_history(history_tree)
        
        # Buttons
        button_frame = ttk.Frame(history_window)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="📄 View Details", 
                  command=lambda: self.view_scan_details(history_tree)).pack(side="left", padx=5)
        ttk.Button(button_frame, text="🗑️ Delete Selected", 
                  command=lambda: self.delete_scan_record(history_tree)).pack(side="left", padx=5)
        ttk.Button(button_frame, text="📊 Export History", 
                  command=lambda: self.export_history(history_tree)).pack(side="left", padx=5)
    
    def show_history_stats(self):
        """Show scan history statistics"""
        stats_window = tk.Toplevel(self.root)
        stats_window.title("📊 History Statistics")
        stats_window.geometry("500x400")
        stats_window.transient(self.root)
        
        # Center the window
        stats_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 100))
        
        # Calculate statistics
        try:
            cursor = self.conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scan_history")
            total_scans = cursor.fetchone()[0]
            
            # Total targets
            cursor.execute("SELECT COUNT(DISTINCT target) FROM scan_history")
            total_targets = cursor.fetchone()[0]
            
            # Most scanned target
            cursor.execute("""
                SELECT target, COUNT(*) as count 
                FROM scan_history 
                GROUP BY target 
                ORDER BY count DESC 
                LIMIT 1
            """)
            result = cursor.fetchone()
            most_scanned = f"{result[0]} ({result[1]} times)" if result else "None"
            
            # Average open ports
            cursor.execute("SELECT AVG(CAST(open_ports as INTEGER)) FROM scan_history WHERE open_ports != ''")
            avg_open = cursor.fetchone()[0] or 0
            
            # Recent activity (last 7 days)
            cursor.execute("""
                SELECT COUNT(*) FROM scan_history 
                WHERE datetime(timestamp) > datetime('now', '-7 days')
            """)
            recent_scans = cursor.fetchone()[0]
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to calculate statistics: {str(e)}")
            stats_window.destroy()
            return
        
        # Display statistics
        main_frame = ttk.Frame(stats_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="📊 Scan Statistics", 
                 font=("Arial", 16, "bold")).pack(pady=10)
        
        stats_text = f"""
📈 Total Scans Performed: {total_scans}
🎯 Unique Targets Scanned: {total_targets}
🏆 Most Scanned Target: {most_scanned}
📊 Average Open Ports: {avg_open:.1f}
🕒 Recent Activity (7 days): {recent_scans}
        """
        
        ttk.Label(main_frame, text=stats_text, 
                 justify=tk.LEFT, font=("Consolas", 11)).pack(pady=20)
        
        # Additional charts info
        if self.matplotlib_available:
            ttk.Label(main_frame, text="📈 Charts are available in the main visualization panel", 
                     font=("Arial", 10, "italic")).pack(pady=10)
        
        ttk.Button(main_frame, text="Close", command=stats_window.destroy).pack(pady=20)
    
    def show_user_guide(self):
        """Show user guide window"""
        guide_window = tk.Toplevel(self.root)
        guide_window.title("📖 User Guide")
        guide_window.geometry("700x600")
        guide_window.transient(self.root)
        
        # Center the window
        guide_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 50, self.root.winfo_rooty() + 50))
        
        # Create scrollable text widget
        main_frame = ttk.Frame(guide_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 11))
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        guide_content = """
🔍 ADVANCED PORT SCANNER - USER GUIDE

📋 BASIC USAGE:
1. Enter target IP address or hostname
2. Specify port range (e.g., 1-1000, 80,443,8080)
3. Choose scan type (TCP/UDP)
4. Click 'Start Scan' to begin

⚡ ADVANCED FEATURES:

🛡️ STEALTH MODE:
- Enables slower, less detectable scanning
- Uses SYN scanning techniques
- Reduces chance of detection by IDS/IPS

🏷️ BANNER GRABBING:
- Captures service banners from open ports
- Helps identify running services
- Useful for vulnerability assessment

🌐 NETWORK DISCOVERY:
- Discover live hosts on a network
- Supports CIDR notation (e.g., 192.168.1.0/24)
- Shows response times and hostnames

📊 SCAN HISTORY:
- All scans are automatically saved
- View past scan results
- Export history to various formats
- Generate statistical reports

📈 REAL-TIME VISUALIZATION:
- Live charts showing scan progress
- Open port discovery rate
- Requires matplotlib library

🔧 CUSTOMIZATION:
- Adjust timeout values
- Set thread count for faster scanning
- Configure default options

💾 EXPORT OPTIONS:
- CSV format for spreadsheet analysis
- JSON format for programmatic use
- HTML reports with styling

⚠️ IMPORTANT NOTES:
- Only scan networks you own or have permission to test
- Some features require administrator privileges
- Firewall may block certain scan types
- Use responsibly and ethically

🆘 TROUBLESHOOTING:
- If scans are slow, reduce thread count
- If timeouts occur, increase timeout value
- For permission errors, run as administrator
- Check firewall settings if ports seem blocked

📞 SUPPORT:
For technical support or feature requests,
please refer to the documentation or
contact your system administrator.
        """
        
        text_widget.insert(tk.END, guide_content)
        text_widget.config(state=tk.DISABLED)
        
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Close button
        ttk.Button(guide_window, text="Close", command=guide_window.destroy).pack(pady=10)
    
    def show_security_tips(self):
        """Show security tips window"""
        tips_window = tk.Toplevel(self.root)
        tips_window.title("🛡️ Security Tips")
        tips_window.geometry("600x500")
        tips_window.transient(self.root)
        
        # Center the window
        tips_window.geometry("+%d+%d" % (self.root.winfo_rootx() + 100, self.root.winfo_rooty() + 100))
        
        # Create scrollable text widget
        main_frame = ttk.Frame(tips_window)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        text_widget = tk.Text(main_frame, wrap=tk.WORD, font=("Arial", 11))
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        tips_content = """
🛡️ SECURITY TIPS & BEST PRACTICES

⚖️ LEGAL AND ETHICAL GUIDELINES:

✅ ALWAYS OBTAIN PERMISSION:
- Only scan networks you own
- Get written authorization for client networks
- Respect terms of service and local laws
- Never scan without explicit permission

⚠️ RESPONSIBLE DISCLOSURE:
- Report vulnerabilities responsibly
- Follow coordinated disclosure practices
- Don't exploit found vulnerabilities
- Respect privacy and confidentiality

🔒 OPERATIONAL SECURITY:

🌐 NETWORK SECURITY:
- Use VPN when scanning remote networks
- Monitor your own network traffic
- Be aware of logging and monitoring systems
- Consider using dedicated scanning networks

📋 DOCUMENTATION:
- Keep detailed logs of all scans
- Document scope and authorization
- Maintain chain of custody for findings
- Follow organizational procedures

🚨 DETECTION AVOIDANCE:

⏱️ TIMING AND FREQUENCY:
- Space out scans to avoid detection
- Use random delays between requests
- Avoid scanning during business hours
- Limit concurrent connections

🎭 STEALTH TECHNIQUES:
- Use stealth mode when available
- Randomize source ports
- Fragment packets when possible
- Use decoy IP addresses (advanced)

🛠️ TECHNICAL CONSIDERATIONS:

🔍 SCAN METHODOLOGY:
- Start with less intrusive scans
- Gradually increase scan intensity
- Verify results with multiple methods
- Cross-reference with other tools

📊 RESULT VALIDATION:
- Manually verify critical findings
- Use multiple scanning tools
- Check for false positives
- Validate service versions

⚠️ WARNING SIGNS:

🚫 STOP SCANNING IF:
- You receive legal warnings
- Network performance degrades significantly
- Security teams contact you
- You discover sensitive systems

🆘 INCIDENT RESPONSE:
- Have an emergency contact plan
- Know how to stop all scans immediately
- Prepare incident documentation
- Coordinate with security teams

💡 PROFESSIONAL DEVELOPMENT:

📚 CONTINUOUS LEARNING:
- Stay updated on scanning techniques
- Learn about new security tools
- Understand defensive measures
- Follow security communities

🏆 CERTIFICATIONS:
- Consider ethical hacking certifications
- Learn penetration testing methodologies
- Understand compliance requirements
- Practice in legal lab environments

Remember: With great power comes great responsibility!
        """
        
        text_widget.insert(tk.END, tips_content)
        text_widget.config(state=tk.DISABLED)
        
        text_widget.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Close button
        ttk.Button(tips_window, text="Close", command=tips_window.destroy).pack(pady=10)
    
    # Additional missing methods for full functionality
    def discover_network_hosts(self, network, results_tree):
        """Discover hosts on a network"""
        try:
            self.discovery_status.config(text="🔍 Discovering hosts...")
            
            # Clear previous results
            for item in results_tree.get_children():
                results_tree.delete(item)
            
            # Parse network
            try:
                network_obj = ipaddress.ip_network(network, strict=False)
            except ValueError:
                messagebox.showerror("Error", "Invalid network format")
                return
            
            # Limit to reasonable size
            if network_obj.num_addresses > 256:
                if not messagebox.askyesno("Large Network", 
                                         f"This network has {network_obj.num_addresses} addresses. "
                                         "This might take a long time. Continue?"):
                    return
            
            def ping_host(ip):
                """Ping a single host"""
                import subprocess
                import time
                start_time = time.time()
                
                try:
                    # Use ping command (cross-platform)
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', str(ip)], 
                                          capture_output=True, text=True, timeout=3)
                    response_time = (time.time() - start_time) * 1000
                    
                    if result.returncode == 0:
                        # Try to get hostname
                        try:
                            hostname = socket.gethostbyaddr(str(ip))[0]
                        except:
                            hostname = "Unknown"
                        
                        return (str(ip), hostname, "Up", f"{response_time:.1f}ms")
                except:
                    pass
                return None
            
            # Discover hosts in thread
            def discovery_worker():
                discovered = []
                with ThreadPoolExecutor(max_workers=50) as executor:
                    futures = {executor.submit(ping_host, ip): ip for ip in network_obj.hosts()}
                    
                    for future in futures:
                        result = future.result()
                        if result:
                            discovered.append(result)
                            # Update UI in main thread
                            self.root.after(0, lambda r=result: results_tree.insert("", tk.END, values=r))
                
                self.root.after(0, lambda: self.discovery_status.config(
                    text=f"✅ Discovery complete. Found {len(discovered)} hosts."))
            
            # Start discovery in background
            threading.Thread(target=discovery_worker, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Discovery Error", f"Failed to discover hosts: {str(e)}")
    
    def select_discovered_host(self, results_tree, discovery_window):
        """Select a discovered host and use it as target"""
        selection = results_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a host first.")
            return
        
        item = results_tree.item(selection[0])
        host_ip = item['values'][0]
        
        # Set the target in main window
        self.target_var.set(host_ip)
        
        # Close discovery window
        discovery_window.destroy()
        
        messagebox.showinfo("Host Selected", f"Target set to: {host_ip}")
    
    def load_scan_history(self, history_tree):
        """Load scan history into the tree"""
        try:
            # Clear existing items
            for item in history_tree.get_children():
                history_tree.delete(item)
            
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT target, scan_time, scan_type, COUNT(*) as total_ports,
                       SUM(CASE WHEN state = 'Open' THEN 1 ELSE 0 END) as open_ports
                FROM scan_history 
                GROUP BY target, scan_time, scan_type
                ORDER BY scan_time DESC
                LIMIT 100
            """)
            
            for i, row in enumerate(cursor.fetchall()):
                target, scan_time, scan_type, total_ports, open_ports = row
                duration = "N/A"  # Could calculate if we stored start/end times
                history_tree.insert("", tk.END, values=(i+1, target, total_ports, open_ports, scan_time, duration))
                
        except Exception as e:
            messagebox.showerror("History Error", f"Failed to load history: {str(e)}")
    
    def filter_history(self, target_filter, date_filter, history_tree):
        """Filter scan history"""
        try:
            # Clear existing items
            for item in history_tree.get_children():
                history_tree.delete(item)
            
            cursor = self.conn.cursor()
            query = """
                SELECT target, scan_time, scan_type, COUNT(*) as total_ports,
                       SUM(CASE WHEN state = 'Open' THEN 1 ELSE 0 END) as open_ports
                FROM scan_history 
                WHERE 1=1
            """
            params = []
            
            if target_filter:
                query += " AND target LIKE ?"
                params.append(f"%{target_filter}%")
            
            if date_filter:
                query += " AND DATE(scan_time) = ?"
                params.append(date_filter)
            
            query += " GROUP BY target, scan_time, scan_type ORDER BY scan_time DESC LIMIT 100"
            
            cursor.execute(query, params)
            
            for i, row in enumerate(cursor.fetchall()):
                target, scan_time, scan_type, total_ports, open_ports = row
                duration = "N/A"
                history_tree.insert("", tk.END, values=(i+1, target, total_ports, open_ports, scan_time, duration))
                
        except Exception as e:
            messagebox.showerror("Filter Error", f"Failed to filter history: {str(e)}")
    
    def view_scan_details(self, history_tree):
        """View details of selected scan"""
        selection = history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan record first.")
            return
        
        item = history_tree.item(selection[0])
        target = item['values'][1]
        timestamp = item['values'][4]
        
        # Create details window
        details_window = tk.Toplevel(self.root)
        details_window.title(f"📄 Scan Details - {target}")
        details_window.geometry("600x400")
        details_window.transient(self.root)
        
        # Get detailed scan data
        try:
            cursor = self.conn.cursor()
            cursor.execute("""
                SELECT port, state, service, banner 
                FROM scan_history 
                WHERE target = ? AND scan_time = ?
                ORDER BY port
            """, (target, timestamp))
            
            # Create tree for details
            columns = ("Port", "State", "Service", "Banner")
            details_tree = ttk.Treeview(details_window, columns=columns, show="headings")
            
            for col in columns:
                details_tree.heading(col, text=col)
                if col == "Banner":
                    details_tree.column(col, width=200)
                else:
                    details_tree.column(col, width=100)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(details_window, orient="vertical", command=details_tree.yview)
            details_tree.configure(yscrollcommand=scrollbar.set)
            
            # Load data
            for row in cursor.fetchall():
                details_tree.insert("", tk.END, values=row)
            
            details_tree.pack(side="left", fill="both", expand=True, padx=10, pady=10)
            scrollbar.pack(side="right", fill="y", pady=10)
            
        except Exception as e:
            messagebox.showerror("Details Error", f"Failed to load scan details: {str(e)}")
            details_window.destroy()
    
    def delete_scan_record(self, history_tree):
        """Delete selected scan record"""
        selection = history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan record first.")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this scan record?"):
            item = history_tree.item(selection[0])
            target = item['values'][1]
            timestamp = item['values'][4]
            
            try:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM scan_history WHERE target = ? AND scan_time = ?", 
                             (target, timestamp))
                self.conn.commit()
                
                # Reload history
                self.load_scan_history(history_tree)
                messagebox.showinfo("Success", "Scan record deleted successfully.")
                
            except Exception as e:
                messagebox.showerror("Delete Error", f"Failed to delete record: {str(e)}")
    
    def export_history(self, history_tree):
        """Export scan history"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("JSON files", "*.json")],
            initialfile="scan_history.csv"
        )
        
        if filename:
            try:
                cursor = self.conn.cursor()
                cursor.execute("SELECT * FROM scan_history ORDER BY scan_time DESC")
                
                if filename.endswith('.json'):
                    # Export as JSON
                    data = []
                    for row in cursor.fetchall():
                        data.append({
                            'id': row[0], 'target': row[1], 'port': row[2], 
                            'state': row[3], 'service': row[4], 'banner': row[5],
                            'scan_time': row[6], 'scan_type': row[7]
                        })
                    
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                else:
                    # Export as CSV
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['ID', 'Target', 'Port', 'State', 'Service', 'Banner', 'Scan Time', 'Scan Type'])
                        writer.writerows(cursor.fetchall())
                
                messagebox.showinfo("Success", f"History exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export history: {str(e)}")
    
    def clear_scan_history(self, confirm=False):
        """Clear all scan history"""
        if not confirm:
            confirm = messagebox.askyesno("Confirm Clear", 
                                        "Are you sure you want to clear all scan history? This cannot be undone.")
        
        if confirm:
            try:
                cursor = self.conn.cursor()
                cursor.execute("DELETE FROM scan_history")
                self.conn.commit()
                messagebox.showinfo("Success", "Scan history cleared successfully.")
            except Exception as e:
                messagebox.showerror("Clear Error", f"Failed to clear history: {str(e)}")
    
    def backup_database(self):
        """Backup the database"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".db",
            filetypes=[("SQLite files", "*.db"), ("All files", "*.*")],
            initialfile=f"scan_history_backup_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        )
        
        if filename:
            try:
                import shutil
                shutil.copy2('scan_history.db', filename)
                messagebox.showinfo("Success", f"Database backed up to {filename}")
            except Exception as e:
                messagebox.showerror("Backup Error", f"Failed to backup database: {str(e)}")
    
    def export_all_data(self):
        """Export all data in multiple formats"""
        folder = filedialog.askdirectory(title="Select Export Folder")
        
        if folder:
            try:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                
                cursor = self.conn.cursor()
                cursor.execute("SELECT * FROM scan_history ORDER BY scan_time DESC")
                data = cursor.fetchall()
                
                # Export CSV
                csv_file = f"{folder}/all_scans_{timestamp}.csv"
                with open(csv_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'Target', 'Port', 'State', 'Service', 'Banner', 'Scan Time', 'Scan Type'])
                    writer.writerows(data)
                
                # Export JSON
                json_file = f"{folder}/all_scans_{timestamp}.json"
                json_data = []
                for row in data:
                    json_data.append({
                        'id': row[0], 'target': row[1], 'port': row[2], 
                        'state': row[3], 'service': row[4], 'banner': row[5],
                        'scan_time': row[6], 'scan_type': row[7]
                    })
                
                with open(json_file, 'w') as f:
                    json.dump(json_data, f, indent=2)
                
                # Copy database
                import shutil
                db_file = f"{folder}/scan_history_{timestamp}.db"
                shutil.copy2('scan_history.db', db_file)
                
                messagebox.showinfo("Success", f"All data exported to {folder}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Failed to export data: {str(e)}")
    
    def update_visualization(self, open_ports_count):
        """Update real-time visualization"""
        if self.matplotlib_available:
            try:
                current_time = datetime.datetime.now()
                self.visualization_data['timestamps'].append(current_time)
                self.visualization_data['open_ports'].append(open_ports_count)
                
                # Keep only last 50 data points
                if len(self.visualization_data['timestamps']) > 50:
                    self.visualization_data['timestamps'] = self.visualization_data['timestamps'][-50:]
                    self.visualization_data['open_ports'] = self.visualization_data['open_ports'][-50:]
                
                # Update plot
                self.ax.clear()
                self.ax.plot(self.visualization_data['timestamps'], self.visualization_data['open_ports'], 'b-o', linewidth=2)
                self.ax.set_title("Open Ports Discovery Rate")
                self.ax.set_xlabel("Time")
                self.ax.set_ylabel("Cumulative Open Ports")
                self.ax.grid(True, alpha=0.3)
                
                # Format x-axis
                try:
                    import matplotlib.dates as mdates
                    self.ax.xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
                    self.fig.autofmt_xdate()
                except ImportError:
                    pass  # Skip formatting if matplotlib.dates not available
                
                self.canvas.draw()
            except Exception as e:
                print(f"Visualization update error: {e}")
        else:
            # Update text-based progress
            try:
                self.progress_text.config(state=tk.NORMAL)
                self.progress_text.delete(1.0, tk.END)
                self.progress_text.insert(tk.END, 
                    f"🔍 Scan Progress:\n"
                    f"📊 Open Ports Found: {open_ports_count}\n"
                    f"⏰ Last Update: {datetime.datetime.now().strftime('%H:%M:%S')}\n"
                    f"📈 Status: Scanning in progress...")
                self.progress_text.config(state=tk.DISABLED)
            except:
                pass
    
    def run(self):
        """Start the GUI application"""
        self.status_var.set("🚀 Ready to scan. Enter target IP/hostname and port range.")
        try:
            self.root.mainloop()
        finally:
            # Close database connection when app closes
            try:
                if hasattr(self, 'conn'):
                    self.conn.close()
            except:
                pass


def main():
    """Main function to run the Advanced Port Scanner Tool"""
    try:
        scanner = AdvancedPortScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user.")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
