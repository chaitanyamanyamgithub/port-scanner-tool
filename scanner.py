#!/usr/bin/env python3
"""
Port Scanner Tool with GUI
A simple and effective port scanning tool with a graphical user interface.
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
        """Create and setup the GUI components"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Target input
        ttk.Label(main_frame, text="Target Host/IP:").grid(row=0, column=0, sticky="w", pady=5)
        self.target_var = tk.StringVar(value="127.0.0.1")
        self.target_entry = ttk.Entry(main_frame, textvariable=self.target_var, width=30)
        self.target_entry.grid(row=0, column=1, sticky="ew", pady=5, padx=(5, 0))
        
        # Port range input
        ttk.Label(main_frame, text="Port Range:").grid(row=1, column=0, sticky="w", pady=5)
        port_frame = ttk.Frame(main_frame)
        port_frame.grid(row=1, column=1, sticky="ew", pady=5, padx=(5, 0))
        
        self.start_port_var = tk.StringVar(value="1")
        self.end_port_var = tk.StringVar(value="1000")
        
        ttk.Entry(port_frame, textvariable=self.start_port_var, width=10).pack(side=tk.LEFT)
        ttk.Label(port_frame, text=" to ").pack(side=tk.LEFT)
        ttk.Entry(port_frame, textvariable=self.end_port_var, width=10).pack(side=tk.LEFT)
        
        # Timeout setting
        ttk.Label(main_frame, text="Timeout (seconds):").grid(row=2, column=0, sticky="w", pady=5)
        self.timeout_var = tk.StringVar(value="1")
        ttk.Entry(main_frame, textvariable=self.timeout_var, width=10).grid(row=2, column=1, sticky="w", pady=5, padx=(5, 0))
        
        # Thread count
        ttk.Label(main_frame, text="Thread Count:").grid(row=3, column=0, sticky="w", pady=5)
        self.threads_var = tk.StringVar(value="100")
        ttk.Entry(main_frame, textvariable=self.threads_var, width=10).grid(row=3, column=1, sticky="w", pady=5, padx=(5, 0))
        
        # Advanced scanning options
        advanced_frame = ttk.LabelFrame(main_frame, text="Advanced Options", padding="5")
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
        ttk.Checkbutton(options_frame, text="Banner Grabbing", variable=self.banner_grab_var).pack(side=tk.LEFT, padx=5)
        
        self.stealth_mode_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Stealth Mode", variable=self.stealth_mode_var).pack(side=tk.LEFT, padx=5)
        
        self.host_discovery_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Host Discovery", variable=self.host_discovery_var).pack(side=tk.LEFT, padx=5)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=10)
        
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
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(main_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.grid(row=6, column=0, columnspan=2, sticky="ew", pady=5)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready to scan")
        self.status_label = ttk.Label(main_frame, textvariable=self.status_var)
        self.status_label.grid(row=7, column=0, columnspan=2, pady=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding="5")
        results_frame.grid(row=8, column=0, columnspan=2, sticky="nsew", pady=10)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(8, weight=1)
        
        # Treeview for results with additional columns
        columns = ("Port", "State", "Service", "Banner", "Timestamp")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings", height=15)
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        # Scrollbars
        v_scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(results_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        # Grid layout for tree and scrollbars
        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")
        
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
            1433: "MSSQL", 6379: "Redis", 27017: "MongoDB", 5672: "RabbitMQ"
        }
        return services.get(port, "Unknown")
    
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
        self.status_var.set(f"Scanning {target}...")
        
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
                    self.status_var.set(f"Scanning {target} ({target_ip})...")
            except socket.gaierror:
                messagebox.showerror("Error", f"Could not resolve hostname: {target}")
                self.scan_finished()
                return
            
            total_ports = end_port - start_port + 1
            self.total_ports = total_ports
            self.scanned_ports = 0
            
            # Create port list
            ports = list(range(start_port, end_port + 1))
            
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
                self.status_var.set(f"Scan completed. Found {len(self.results)} open ports.")
            else:
                self.status_var.set("Scan stopped by user.")
            
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
        self.status_var.set("Results cleared. Ready to scan.")
    
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
                        # Handle different result formats
                        if len(result) == 5:
                            writer.writerow(result)
                        elif len(result) == 4:
                            # Old format without banner
                            writer.writerow([result[0], result[1], result[2], "", result[3]])
                        else:
                            writer.writerow(result)
                
                messagebox.showinfo("Success", f"Results saved to {filename}")
                
                # Also save to default results.csv in the same directory
                default_path = "results.csv"
                with open(default_path, 'w', newline='', encoding='utf-8') as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Port", "State", "Service", "Banner", "Timestamp"])
                    for result in self.results:
                        if len(result) == 5:
                            writer.writerow(result)
                        elif len(result) == 4:
                            writer.writerow([result[0], result[1], result[2], "", result[3]])
                        else:
                            writer.writerow(result)
                
            except Exception as e:
                messagebox.showerror("Save Error", f"Could not save file: {str(e)}")
    
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

    # ...existing code...
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
