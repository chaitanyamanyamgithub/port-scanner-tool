#!/usr/bin/env python3
"""
Basic Port Scanner Tool with GUI
A simple and effective port scanning tool.
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


class PortScanner:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Advanced Port Scanner Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Variables
        self.scanning = False
        self.results = []
        self.progress_queue = queue.Queue()
        self.scan_history = []
        
        # Initialize database
        self.setup_database()
        
        # Setup GUI
        self.setup_gui()

    def setup_gui(self):
        """Setup the GUI components"""
        # Main frame with padding
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Target input section
        ttk.Label(main_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky="w", pady=5)
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(main_frame, textvariable=self.target_var, width=30)
        self.target_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=(5, 0))
        
        # Port range section
        port_frame = ttk.Frame(main_frame)
        port_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=10)
        port_frame.columnconfigure(1, weight=1)
        port_frame.columnconfigure(3, weight=1)
        
        ttk.Label(port_frame, text="Start Port:").grid(row=0, column=0, sticky="w")
        self.start_port_var = tk.StringVar(value="1")
        self.start_port_entry = ttk.Entry(port_frame, textvariable=self.start_port_var, width=10)
        self.start_port_entry.grid(row=0, column=1, sticky="w", padx=(5, 10))
        
        ttk.Label(port_frame, text="End Port:").grid(row=0, column=2, sticky="w")
        self.end_port_var = tk.StringVar(value="1000")
        self.end_port_entry = ttk.Entry(port_frame, textvariable=self.end_port_var, width=10)
        self.end_port_entry.grid(row=0, column=3, sticky="w", padx=(5, 0))
        
        # Scan options section
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        ttk.Label(options_frame, text="Timeout (seconds):").grid(row=0, column=0, sticky="w")
        self.timeout_var = tk.StringVar(value="1")
        timeout_entry = ttk.Entry(options_frame, textvariable=self.timeout_var, width=10)
        timeout_entry.grid(row=0, column=1, sticky="w", padx=(5, 0))
        
        ttk.Label(options_frame, text="Max Threads:").grid(row=1, column=0, sticky="w", pady=(5, 0))
        self.threads_var = tk.StringVar(value="100")
        threads_entry = ttk.Entry(options_frame, textvariable=self.threads_var, width=10)
        threads_entry.grid(row=1, column=1, sticky="w", padx=(5, 0), pady=(5, 0))
        
        # Scan type
        ttk.Label(options_frame, text="Scan Type:").grid(row=0, column=2, sticky="w", padx=(20, 0))
        self.scan_type_var = tk.StringVar(value="TCP Connect")
        scan_type_combo = ttk.Combobox(options_frame, textvariable=self.scan_type_var, 
                                      values=["TCP Connect", "TCP SYN", "UDP"], 
                                      state="readonly", width=15)
        scan_type_combo.grid(row=0, column=3, sticky="w", padx=(5, 0))
        
        # Advanced options
        self.banner_var = tk.BooleanVar()
        banner_check = ttk.Checkbutton(options_frame, text="Banner Grabbing", variable=self.banner_var)
        banner_check.grid(row=1, column=2, sticky="w", padx=(20, 0), pady=(5, 0))
        
        self.stealth_var = tk.BooleanVar()
        stealth_check = ttk.Checkbutton(options_frame, text="Stealth Mode", variable=self.stealth_var)
        stealth_check.grid(row=1, column=3, sticky="w", padx=(5, 0), pady=(5, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        self.scan_button = ttk.Button(button_frame, text="Start Scan", command=self.start_scan)
        self.scan_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="Save CSV", command=self.save_results)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        self.export_json_button = ttk.Button(button_frame, text="Export JSON", command=self.export_to_json)
        self.export_json_button.pack(side=tk.LEFT, padx=5)
        
        self.report_button = ttk.Button(button_frame, text="HTML Report", command=self.generate_html_report)
        self.report_button.pack(side=tk.LEFT, padx=5)
        
        self.clear_button = ttk.Button(button_frame, text="Clear Results", command=self.clear_results)
        self.clear_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=4, column=0, columnspan=2, sticky="ew", pady=10)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(progress_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        
        self.status_var = tk.StringVar(value="Ready to scan. Enter target IP/hostname and port range.")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        status_label.grid(row=1, column=0, sticky="w", pady=(5, 0))
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=5, column=0, columnspan=2, sticky="nsew", pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(5, weight=1)
        
        # Treeview for results
        columns = ("Port", "Service", "Status", "Banner")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120)
        
        self.tree.grid(row=0, column=0, sticky="nsew")
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

    def setup_database(self):
        """Setup SQLite database for scan history"""
        try:
            self.conn = sqlite3.connect('scan_history.db')
            cursor = self.conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    target TEXT,
                    start_port INTEGER,
                    end_port INTEGER,
                    open_ports TEXT,
                    scan_duration REAL
                )
            ''')
            self.conn.commit()
        except Exception as e:
            print(f"Database setup error: {e}")

    def validate_inputs(self):
        """Validate user inputs before scanning"""
        try:
            target = self.target_var.get().strip()
            if not target:
                raise ValueError("Target cannot be empty")
            
            start_port = int(self.start_port_var.get())
            end_port = int(self.end_port_var.get())
            timeout = float(self.timeout_var.get())
            max_threads = int(self.threads_var.get())
            
            if start_port < 1 or start_port > 65535:
                raise ValueError("Start port must be between 1 and 65535")
            
            if end_port < 1 or end_port > 65535:
                raise ValueError("End port must be between 1 and 65535")
            
            if start_port > end_port:
                raise ValueError("Start port cannot be greater than end port")
            
            if timeout <= 0:
                raise ValueError("Timeout must be greater than 0")
            
            if max_threads < 1 or max_threads > 1000:
                raise ValueError("Max threads must be between 1 and 1000")
            
            return target, start_port, end_port, timeout, max_threads
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
            return None

    def get_service_name(self, port):
        """Get service name for a given port"""
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 993: "IMAPS",
            995: "POP3S", 3389: "RDP", 5900: "VNC", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return common_ports.get(port, "Unknown")

    def scan_port(self, target, port, timeout):
        """Scan a single port"""
        try:
            scan_type = self.scan_type_var.get()
            
            if scan_type == "UDP":
                # UDP scan
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                try:
                    sock.sendto(b"test", (target, port))
                    sock.recvfrom(1024)
                    result = "Open"
                except socket.timeout:
                    result = "Open|Filtered"
                except socket.error:
                    result = "Closed"
                finally:
                    sock.close()
            else:
                # TCP scan
                if scan_type == "TCP SYN" and self.stealth_var.get():
                    # Simulate stealth scan with random delay
                    time.sleep(random.uniform(0.1, 0.5))
                
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                
                connection_result = sock.connect_ex((target, port))
                
                if connection_result == 0:
                    result = "Open"
                    banner = ""
                    
                    # Banner grabbing if enabled
                    if self.banner_var.get():
                        try:
                            sock.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                            if len(banner) > 100:
                                banner = banner[:100] + "..."
                        except:
                            banner = "No banner"
                    
                    sock.close()
                    return port, self.get_service_name(port), result, banner
                else:
                    result = "Closed"
                    sock.close()
            
            return port, self.get_service_name(port), result, ""
            
        except Exception as e:
            return port, self.get_service_name(port), "Error", str(e)

    def scan_worker(self, target, ports, timeout, results_queue, progress_queue):
        """Worker function for threaded scanning"""
        for port in ports:
            if not self.scanning:
                break
            
            result = self.scan_port(target, port, timeout)
            results_queue.put(result)
            progress_queue.put(1)

    def start_scan(self):
        """Start the port scanning process"""
        inputs = self.validate_inputs()
        if not inputs:
            return
        
        target, start_port, end_port, timeout, max_threads = inputs
        
        # Clear previous results
        self.clear_results()
        
        # Update UI state
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress_var.set(0)
        
        # Start scanning in a separate thread
        scan_thread = threading.Thread(
            target=self.run_scan,
            args=(target, start_port, end_port, timeout, max_threads),
            daemon=True
        )
        scan_thread.start()
        
        # Start progress monitoring
        self.monitor_progress()

    def run_scan(self, target, start_port, end_port, timeout, max_threads):
        """Run the actual port scan"""
        try:
            start_time = time.time()
            
            # Resolve hostname to IP
            try:
                target_ip = socket.gethostbyname(target)
                self.status_var.set(f"Scanning {target} ({target_ip})...")
            except socket.gaierror:
                self.status_var.set(f"Could not resolve hostname: {target}")
                return
            
            ports = list(range(start_port, end_port + 1))
            total_ports = len(ports)
            
            self.progress_queue = queue.Queue()
            results_queue = queue.Queue()
            
            # Calculate chunk size for threading
            chunk_size = max(1, total_ports // max_threads)
            port_chunks = [ports[i:i + chunk_size] for i in range(0, total_ports, chunk_size)]
            
            # Start worker threads
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = []
                for chunk in port_chunks:
                    future = executor.submit(
                        self.scan_worker,
                        target_ip, chunk, timeout, results_queue, self.progress_queue
                    )
                    futures.append(future)
                
                # Wait for all threads to complete
                for future in futures:
                    future.result()
            
            # Collect results
            while not results_queue.empty():
                result = results_queue.get()
                self.results.append(result)
                
                # Update tree view
                self.root.after(0, self.update_tree_view, result)
            
            # Save scan to database
            scan_duration = time.time() - start_time
            open_ports = [str(r[0]) for r in self.results if r[2] == "Open"]
            
            try:
                cursor = self.conn.cursor()
                cursor.execute('''
                    INSERT INTO scans (timestamp, target, start_port, end_port, open_ports, scan_duration)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    datetime.datetime.now().isoformat(),
                    target,
                    start_port,
                    end_port,
                    ','.join(open_ports),
                    scan_duration
                ))
                self.conn.commit()
            except Exception as e:
                print(f"Database error: {e}")
            
            self.root.after(0, self.scan_finished)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", f"Scan failed: {str(e)}"))
            self.root.after(0, self.scan_finished)

    def update_tree_view(self, result):
        """Update the tree view with new result"""
        self.tree.insert("", "end", values=result)

    def monitor_progress(self):
        """Monitor scan progress and update progress bar"""
        try:
            progress_count = 0
            while not self.progress_queue.empty():
                self.progress_queue.get()
                progress_count += 1
            
            if progress_count > 0:
                total_ports = int(self.end_port_var.get()) - int(self.start_port_var.get()) + 1
                current_progress = (len(self.results) / total_ports) * 100
                self.progress_var.set(min(current_progress, 100))
            
            if self.scanning:
                self.root.after(100, self.monitor_progress)
                
        except Exception as e:
            print(f"Progress monitoring error: {e}")

    def stop_scan(self):
        """Stop the current scan"""
        self.scanning = False
        self.scan_finished()

    def scan_finished(self):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress_var.set(100)
        
        open_ports = len([r for r in self.results if r[2] == "Open"])
        total_ports = len(self.results)
        self.status_var.set(f"Scan completed. Found {open_ports} open ports out of {total_ports} scanned.")

    def clear_results(self):
        """Clear scan results"""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results = []
        self.progress_var.set(0)
        self.status_var.set("Results cleared. Ready for new scan.")

    def save_results(self):
        """Save results to CSV file"""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to save!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Scan Results"
        )
        
        if filename:
            try:
                with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    
                    # Write header
                    writer.writerow(["Port", "Service", "Status", "Banner", "Timestamp", "Target"])
                    
                    # Write data
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    target = self.target_var.get()
                    
                    for result in self.results:
                        row = list(result) + [timestamp, target]
                        writer.writerow(row)
                
                messagebox.showinfo("Save Complete", f"Results saved to {filename}")
                
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save file: {str(e)}")

    def export_to_json(self):
        """Export scan results to JSON format"""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to export!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save JSON Report"
        )
        
        if filename:
            try:
                export_data = {
                    "scan_info": {
                        "target": self.target_var.get(),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "total_ports_scanned": len(self.results),
                        "open_ports_found": len([r for r in self.results if r[2] == "Open"])
                    },
                    "results": []
                }
                
                for result in self.results:
                    export_data["results"].append({
                        "port": result[0],
                        "service": result[1],
                        "status": result[2],
                        "banner": result[3] if len(result) > 3 else ""
                    })
                
                with open(filename, 'w') as f:
                    json.dump(export_data, f, indent=2)
                
                messagebox.showinfo("Export Complete", f"Results exported to {filename}")
                
            except Exception as e:
                messagebox.showerror("Export Error", f"Could not export file: {str(e)}")

    def generate_html_report(self):
        """Generate HTML report of scan results"""
        if not self.results:
            messagebox.showwarning("No Data", "No scan results to generate report!")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            title="Save HTML Report"
        )
        
        if filename:
            try:
                html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Port Scanner Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #f0f0f0; padding: 15px; border-radius: 5px; }}
        .stats {{ margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        .open {{ color: green; font-weight: bold; }}
        .closed {{ color: red; }}
        .filtered {{ color: orange; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Port Scanner Report</h1>
        <p><strong>Target:</strong> {self.target_var.get()}</p>
        <p><strong>Scan Date:</strong> {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="stats">
        <h2>Scan Statistics</h2>
        <p><strong>Total Ports Scanned:</strong> {len(self.results)}</p>
        <p><strong>Open Ports Found:</strong> {len([r for r in self.results if r[2] == "Open"])}</p>
        <p><strong>Closed Ports:</strong> {len([r for r in self.results if r[2] == "Closed"])}</p>
    </div>
    
    <h2>Detailed Results</h2>
    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Status</th>
            <th>Banner</th>
        </tr>
"""
                
                for result in self.results:
                    status_class = result[2].lower()
                    banner = result[3] if len(result) > 3 else "N/A"
                    html_content += f"""
        <tr>
            <td>{result[0]}</td>
            <td>{result[1]}</td>
            <td class="{status_class}">{result[2]}</td>
            <td>{banner}</td>
        </tr>"""
                
                html_content += """
    </table>
</body>
</html>"""
                
                with open(filename, 'w') as f:
                    f.write(html_content)
                
                messagebox.showinfo("Report Generated", f"HTML report saved to {filename}")
                
            except Exception as e:
                messagebox.showerror("Report Error", f"Could not generate report: {str(e)}")

    def run(self):
        """Start the GUI application"""
        self.status_var.set("Ready to scan. Enter target IP/hostname and port range.")
        self.root.mainloop()
        
        # Close database connection when app closes
        try:
            if hasattr(self, 'conn'):
                self.conn.close()
        except:
            pass


def main():
    """Main function to run the Port Scanner Tool"""
    try:
        scanner = PortScanner()
        scanner.run()
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
