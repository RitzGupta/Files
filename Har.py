import json
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import tkinter as tk
from tkinter import filedialog, ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import webbrowser
import os
from datetime import datetime
from urllib.parse import urlparse
import networkx as nx
from collections import defaultdict, Counter

from visualizers import render_overview, render_timeline, render_domains, render_content, render_waterfall, render_network, render_details
from utils import categorize_content_type

class HARAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("HAR File Analyzer")
        self.root.geometry("1200x800")
        self.data = None
        self.df = None
        self.current_tab = None
        
        # Style configuration
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TButton', font=('Arial', 10), background='#4a7abc')
        self.style.configure('TLabel', font=('Arial', 11), background='#f0f0f0')
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'), background='#f0f0f0')
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create header
        self.header_frame = ttk.Frame(self.main_frame)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.title_label = ttk.Label(self.header_frame, text="HAR File Analyzer", style='Header.TLabel')
        self.title_label.pack(side=tk.LEFT, padx=5)
        
        self.load_button = ttk.Button(self.header_frame, text="Load HAR File", command=self.load_har_file)
        self.load_button.pack(side=tk.RIGHT, padx=5)
        
        self.export_button = ttk.Button(self.header_frame, text="Export Analysis", command=self.export_analysis, state=tk.DISABLED)
        self.export_button.pack(side=tk.RIGHT, padx=5)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create tabs
        self.overview_tab = ttk.Frame(self.notebook)
        self.timeline_tab = ttk.Frame(self.notebook)
        self.domains_tab = ttk.Frame(self.notebook)
        self.content_tab = ttk.Frame(self.notebook)
        self.waterfall_tab = ttk.Frame(self.notebook)
        self.network_tab = ttk.Frame(self.notebook)
        self.details_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.timeline_tab, text="Timeline")
        self.notebook.add(self.domains_tab, text="Domains")
        self.notebook.add(self.content_tab, text="Content Types")
        self.notebook.add(self.waterfall_tab, text="Waterfall")
        self.notebook.add(self.network_tab, text="Network Map")
        self.notebook.add(self.details_tab, text="Request Details")
        
        # Status bar
        self.status_bar = ttk.Label(self.root, text="Ready. Load a HAR file to begin analysis.", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Bind tab change event
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
        
    def load_har_file(self):
        file_path = filedialog.askopenfilename(
            title="Select HAR File",
            filetypes=[("HAR Files", "*.har"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return
            
        try:
            self.status_bar.config(text=f"Loading {file_path}...")
            self.root.update()
            
            with open(file_path, 'r', encoding='utf-8') as f:
                self.data = json.load(f)
                
            self.process_har_data()
            self.export_button.config(state=tk.NORMAL)
            self.status_bar.config(text=f"Successfully loaded HAR file: {os.path.basename(file_path)}")
            
            # Show overview tab by default
            self.notebook.select(0)
            self.render_overview_tab()
            
        except Exception as e:
            self.status_bar.config(text=f"Error loading HAR file: {str(e)}")
            
    def process_har_data(self):
        # Extract entries from HAR file
        entries = self.data.get('log', {}).get('entries', [])
        
        if not entries:
            raise ValueError("No entries found in HAR file")
            
        # Process entries into a DataFrame
        processed_data = []
        
        for entry in entries:
            request = entry.get('request', {})
            response = entry.get('response', {})
            timings = entry.get('timings', {})
            
            url = request.get('url', '')
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            
            # Get method and status
            method = request.get('method', '')
            status = response.get('status', 0)
            
            # Get content type
            content_type = ''
            for header in response.get('headers', []):
                if header.get('name', '').lower() == 'content-type':
                    content_type = header.get('value', '').split(';')[0]
                    break
                    
            # Get size information
            request_size = request.get('bodySize', 0)
            if request_size < 0:
                request_size = 0
                
            response_size = response.get('bodySize', 0)
            if response_size < 0:
                response_size = 0
                
            total_size = request_size + response_size
            
            # Get timing information
            start_time = entry.get('startedDateTime', '')
            time_ms = entry.get('time', 0)  # Total time in milliseconds
            
            # Convert ISO string to datetime
            if start_time:
                start_time = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
            
            # Detailed timings
            blocked = timings.get('blocked', -1)
            dns = timings.get('dns', -1)
            connect = timings.get('connect', -1)
            ssl = timings.get('ssl', -1)
            send = timings.get('send', -1)
            wait = timings.get('wait', -1)
            receive = timings.get('receive', -1)
            
            # Process request headers
            req_headers = {}
            for header in request.get('headers', []):
                req_headers[header.get('name', '')] = header.get('value', '')
                
            # Process response headers
            resp_headers = {}
            for header in response.get('headers', []):
                resp_headers[header.get('name', '')] = header.get('value', '')
            
            processed_data.append({
                'url': url,
                'domain': domain,
                'path': path,
                'method': method,
                'status': status,
                'content_type': content_type,
                'request_size': request_size,
                'response_size': response_size,
                'total_size': total_size,
                'start_time': start_time,
                'time_ms': time_ms,
                'blocked': blocked if blocked >= 0 else 0,
                'dns': dns if dns >= 0 else 0,
                'connect': connect if connect >= 0 else 0,
                'ssl': ssl if ssl >= 0 else 0,
                'send': send if send >= 0 else 0,
                'wait': wait if wait >= 0 else 0,
                'receive': receive if receive >= 0 else 0,
                'request_headers': req_headers,
                'response_headers': resp_headers,
                'entry': entry  # Store the full entry for detailed view
            })
            
        # Create DataFrame
        self.df = pd.DataFrame(processed_data)
        
        # Add time from start
        if not self.df.empty and 'start_time' in self.df.columns:
            first_request_time = self.df['start_time'].min()
            self.df['time_from_start'] = (self.df['start_time'] - first_request_time).dt.total_seconds() * 1000
            
        # Categorize content types
        self.df['content_type_category'] = self.df['content_type'].apply(categorize_content_type)
            
    def on_tab_changed(self, event):
        tab_id = self.notebook.select()
        tab_name = self.notebook.tab(tab_id, "text")
        
        self.current_tab = tab_name
        
        if self.df is None:
            return
            
        if tab_name == "Overview":
            self.render_overview_tab()
        elif tab_name == "Timeline":
            self.render_timeline_tab()
        elif tab_name == "Domains":
            self.render_domains_tab()
        elif tab_name == "Content Types":
            self.render_content_tab()
        elif tab_name == "Waterfall":
            self.render_waterfall_tab()
        elif tab_name == "Network Map":
            self.render_network_tab()
        elif tab_name == "Request Details":
            self.render_details_tab()
    
    def render_overview_tab(self):
        render_overview(self)
    
    def render_timeline_tab(self):
        render_timeline(self)
    
    def render_domains_tab(self):
        render_domains(self)
    
    def render_content_tab(self):
        render_content(self)
    
    def render_waterfall_tab(self):
        render_waterfall(self)
    
    def render_network_tab(self):
        render_network(self)
    
    def render_details_tab(self):
        render_details(self)
    
    def show_domain_details(self, event, tree):
        # Get selected domain
        selected_item = tree.selection()[0]
        domain = tree.item(selected_item, 'values')[0]
        
        # Create top level window for domain details
        domain_window = tk.Toplevel(self.root)
        domain_window.title(f"Details for {domain}")
        domain_window.geometry("800x600")
        
        # Create notebook for domain details
        domain_notebook = ttk.Notebook(domain_window)
        domain_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Filter data for this domain
        domain_data = self.df[self.df['domain'] == domain]
        
        # Requests tab
        requests_tab = ttk.Frame(domain_notebook)
        domain_notebook.add(requests_tab, text="Requests")
        
        # Create treeview for requests
        req_columns = ('URL', 'Method', 'Status', 'Content Type', 'Size (KB)', 'Time (ms)')
        req_tree = ttk.Treeview(requests_tab, columns=req_columns, show='headings')
        
        for col in req_columns:
            req_tree.heading(col, text=col)
            if col == 'URL':
                req_tree.column(col, width=300, anchor=tk.W)
            else:
                req_tree.column(col, width=80, anchor=tk.CENTER)
        
        # Add scrollbar
        req_scrollbar = ttk.Scrollbar(requests_tab, orient=tk.VERTICAL, command=req_tree.yview)
        req_tree.configure(yscrollcommand=req_scrollbar.set)
        req_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        req_tree.pack(fill=tk.BOTH, expand=True)
        
        # Populate treeview
        for _, row in domain_data.iterrows():
            req_tree.insert('', tk.END, values=(
                row['path'],
                row['method'],
                row['status'],
                row['content_type_category'],
                f"{row['total_size']/1024:.2f}",
                f"{row['time_ms']:.2f}"
            ))
            
        # Performance tab
        perf_tab = ttk.Frame(domain_notebook)
        domain_notebook.add(perf_tab, text="Performance")
        
        # Create figure for performance
        perf_fig = plt.Figure(figsize=(7, 5), dpi=100)
        perf_ax = perf_fig.add_subplot(111)
        
        # Timings breakdown
        timing_data = domain_data[['blocked', 'dns', 'connect', 'ssl', 'send', 'wait', 'receive']].mean()
        
        timing_colors = {
            'blocked': '#E0E0E0',
            'dns': '#FFEB3B',
            'connect': '#FF9800',
            'ssl': '#CDDC39',
            'send': '#4CAF50',
            'wait': '#2196F3',
            'receive': '#9C27B0'
        }
        
        bars = perf_ax.barh(timing_data.index, timing_data.values, color=[timing_colors[phase] for phase in timing_data.index])
        perf_ax.set_title('Average Request Timing Breakdown')
        perf_ax.set_xlabel('Time (ms)')
        
        # Add timing values
        for bar in bars:
            width = bar.get_width()
            if width > 0:
                label_x_pos = width + 0.5
                perf_ax.text(label_x_pos, bar.get_y() + bar.get_height()/2, s=f'{width:.1f} ms',
                        va='center', fontsize=8)
        
        perf_fig.tight_layout()
        
        # Add the figure to the frame
        perf_canvas = FigureCanvasTkAgg(perf_fig, perf_tab)
        perf_canvas.draw()
        perf_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def show_content_details(self, event, tree):
        # Get selected content type
        selected_item = tree.selection()[0]
        content_type = tree.item(selected_item, 'values')[0]
        
        # Create top level window for content details
        content_window = tk.Toplevel(self.root)
        content_window.title(f"Details for {content_type} Content")
        content_window.geometry("800x600")
        
        # Filter data for this content type
        content_data = self.df[self.df['content_type_category'] == content_type]
        
        # Create treeview for content items
        columns = ('URL', 'Domain', 'Status', 'Size (KB)', 'Time (ms)')
        content_detail_tree = ttk.Treeview(content_window, columns=columns, show='headings')
        
        for col in columns:
            content_detail_tree.heading(col, text=col)
            if col == 'URL':
                content_detail_tree.column(col, width=300, anchor=tk.W)
            elif col == 'Domain':
                content_detail_tree.column(col, width=150, anchor=tk.W)
            else:
                content_detail_tree.column(col, width=80, anchor=tk.CENTER)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(content_window, orient=tk.VERTICAL, command=content_detail_tree.yview)
        content_detail_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        content_detail_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Populate treeview
        for _, row in content_data.iterrows():
            content_detail_tree.insert('', tk.END, values=(
                row['path'],
                row['domain'],
                row['status'],
                f"{row['total_size']/1024:.2f}",
                f"{row['time_ms']:.2f}"
            ))
    
    def export_analysis(self):
        # Create a directory for export
        export_dir = filedialog.askdirectory(title="Select Directory for Export")
        
        if not export_dir:
            return
            
        # Create HTML report
        report_path = os.path.join(export_dir, "har_analysis_report.html")
        
        try:
            self.status_bar.config(text="Exporting analysis report...")
            self.root.update()
            
            # Generate summary statistics
            total_requests = len(self.df)
            total_size = self.df['total_size'].sum() / (1024 * 1024)  # MB
            avg_response_time = self.df['time_ms'].mean()
            total_load_time = self.df['time_from_start'].max() + self.df.iloc[-1]['time_ms']
            
            # Status code distribution
            status_counts = self.df['status'].value_counts()
            success_rate = (status_counts.get(200, 0) / total_requests) * 100 if total_requests > 0 else 0
            
            # Create HTML content
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>HAR Analysis Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #2196F3; }}
                    h2 {{ color: #0D47A1; margin-top: 30px; }}
                    table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                    tr:nth-child(even) {{ background-color: #f9f9f9; }}
                </style>
            </head>
            <body>
                <h1>HAR Analysis Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <h2>Summary</h2>
                <table>
                    <tr><th>Metric</th><th>Value</th></tr>
                    <tr><td>Total Requests</td><td>{total_requests}</td></tr>
                    <tr><td>Total Size</td><td>{total_size:.2f} MB</td></tr>
                    <tr><td>Average Response Time</td><td>{avg_response_time:.2f} ms</td></tr>
                    <tr><td>Total Page Load Time</td><td>{total_load_time:.2f} ms</td></tr>
                    <tr><td>Success Rate (200)</td><td>{success_rate:.1f}%</td></tr>
                </table>
                
                <h2>Status Code Distribution</h2>
                <table>
                    <tr><th>Status Code</th><th>Count</th><th>Percentage</th></tr>
            """
            
            # Add status code rows
            for status, count in status_counts.items():
                percentage = (count / total_requests) * 100
                html_content += f"<tr><td>{status}</td><td>{count}</td><td>{percentage:.1f}%</td></tr>"
                
            html_content += """
                </table>
                
                <h2>Content Type Distribution</h2>
                <table>
                    <tr><th>Content Type</th><th>Count</th><th>Total Size (KB)</th><th>Avg Size (KB)</th><th>Avg Time (ms)</th></tr>
            """
            
            # Add content type rows
            content_stats = self.df.groupby('content_type_category').agg({
                'url': 'count',
                'total_size': ['sum', 'mean'],
                'time_ms': 'mean'
            }).reset_index()
            
            content_stats.columns = ['Content Type', 'Count', 'Total Size', 'Avg Size', 'Avg Time']
            
            for _, row in content_stats.iterrows():
                html_content += f"""
                <tr>
                    <td>{row['Content Type']}</td>
                    <td>{row['Count']}</td>
                    <td>{row['Total Size']/1024:.2f}</td>
                    <td>{row['Avg Size']/1024:.2f}</td>
                    <td>{row['Avg Time']:.2f}</td>
                </tr>
                """
                
            html_content += """
                </table>
                
                <h2>Top Domains</h2>
                <table>
                    <tr><th>Domain</th><th>Requests</th><th>Size (KB)</th><th>Avg Time (ms)</th></tr>
            """
            
            # Add domain rows
            domain_stats = self.df.groupby('domain').agg({
                'url': 'count',
                'total_size': 'sum',
                'time_ms': 'mean'
            }).reset_index()
            
            domain_stats.columns = ['Domain', 'Requests', 'Size', 'Avg Time']
            domain_stats = domain_stats.sort_values('Requests', ascending=False)
            
            for _, row in domain_stats.nlargest(10, 'Requests').iterrows():
                html_content += f"""
                <tr>
                    <td>{row['Domain']}</td>
                    <td>{row['Requests']}</td>
                    <td>{row['Size']/1024:.2f}</td>
                    <td>{row['Avg Time']:.2f}</td>
                </tr>
                """
                
            html_content += """
                </table>
                
                <h2>Slowest Requests</h2>
                <table>
                    <tr><th>URL</th><th>Domain</th><th>Status</th><th>Content Type</th><th>Size (KB)</th><th>Time (ms)</th></tr>
            """
            
            # Add slowest requests rows
            for _, row in self.df.nlargest(10, 'time_ms').iterrows():
                html_content += f"""
                <tr>
                    <td>{row['url']}</td>
                    <td>{row['domain']}</td>
                    <td>{row['status']}</td>
                    <td>{row['content_type_category']}</td>
                    <td>{row['total_size']/1024:.2f}</td>
                    <td>{row['time_ms']:.2f}</td>
                </tr>
                """
                
            html_content += """
                </table>
            </body>
            </html>
            """
            
            # Write HTML to file
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            # Also export raw data as CSV
            csv_path = os.path.join(export_dir, "har_data.csv")
            export_df = self.df.drop(['entry', 'request_headers', 'response_headers'], axis=1)
            export_df.to_csv(csv_path, index=False)
            
            self.status_bar.config(text=f"Analysis exported to {export_dir}")
            
            # Open the report in browser
            webbrowser.open('file://' + os.path.realpath(report_path))
            
        except Exception as e:
            self.status_bar.config(text=f"Error exporting analysis: {str(e)}")
