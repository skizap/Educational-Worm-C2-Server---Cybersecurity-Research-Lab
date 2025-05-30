# Educational Worm & C2 Server - Cybersecurity Research Lab

**ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.**

This repository contains advanced educational tools for studying worm behavior and command & control (C2) operations in controlled cybersecurity lab environments.

## ⚠️ IMPORTANT WARNINGS

- **AUTHORIZED USE ONLY**: Only use in controlled lab environments with proper authorization
- **EDUCATIONAL PURPOSE**: Designed for cybersecurity education and research
- **ISOLATED ENVIRONMENT**: Must be used in air-gapped or isolated lab networks
- **LEGAL COMPLIANCE**: Ensure compliance with all applicable laws and regulations

## 🎯 Educational Objectives

This lab demonstrates:
- Advanced persistent threat (APT) techniques
- Worm propagation mechanisms
- Command & control infrastructure
- Network security vulnerabilities
- Incident response procedures
- Digital forensics analysis

## 📁 Repository Contents

```
red/
├── worm_analysis_educational.py    # Advanced educational worm (900+ lines)
├── c2_server_educational.py        # C2 server with telnet interface
├── run_lab.bat                     # Windows lab management script
├── requirements.txt                # Python dependencies
└── README.md                       # This documentation
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (for full compatibility)
- Isolated lab network environment
- Administrative privileges (for some features)

### Installation Steps

1. **Clone or download this repository**
   ```bash
   git clone <repository-url>
   cd red
   ```

2. **Install Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify lab environment**
   - Ensure you're in an isolated network
   - Confirm proper authorization
   - Set up multiple VMs for testing (recommended)

## 🚀 Quick Start Guide

### Method 1: Using the Lab Management Script (Recommended)

1. **Run the lab script**
   ```cmd
   run_lab.bat
   ```

2. **Follow the menu options:**
   - Option 1: Start C2 Server
   - Option 2: Run Worm (in separate terminal)
   - Option 3: Connect via Telnet to control worms

### Method 2: Manual Execution

1. **Start the C2 Server**
   ```bash
   python c2_server_educational.py
   ```
   - Default HTTP port: 8080 (for worm communications)
   - Default Telnet port: 9999 (for operator interface)
   - Default credentials: admin/lab123

2. **Run the Educational Worm** (in separate terminal)
   ```bash
   python worm_analysis_educational.py
   ```

3. **Connect to C2 via Telnet**
   ```bash
   telnet localhost 9999
   ```

## 🎮 C2 Server Commands

Once connected to the telnet interface, use these commands:

### Basic Commands
- `help` - Show command help
- `status` - Show C2 server status
- `hosts` - List all infected hosts
- `stats` - Show infection statistics
- `logs` - View recent activity logs

### Host Management
- `host <worm_id>` - Show detailed host information
- `cmd <worm_id> <command>` - Execute command on specific host
- `broadcast <command>` - Send command to all active hosts

### Control Commands
- `kill <worm_id>` - Send self-destruct to specific host
- `killall` - Send self-destruct to ALL hosts (requires confirmation)
- `exit` - Disconnect from C2 server

### Example Usage
```
C2> hosts                           # List infected machines
C2> host abc123                     # Show details for worm ID abc123
C2> cmd abc123 whoami               # Execute 'whoami' on specific host
C2> broadcast systeminfo            # Get system info from all hosts
C2> kill abc123                     # Self-destruct specific worm
```

## 🔬 Educational Features

### Worm Capabilities
- **Network Discovery**: ARP scanning, ping sweeps, NetBIOS enumeration
- **Multi-Vector Propagation**: SMB, SSH, web vulnerabilities
- **Polymorphic Payloads**: Dynamic code generation with encryption
- **Persistence Mechanisms**: Registry, scheduled tasks, startup folders
- **Anti-Analysis**: VM detection, debugger detection, sandbox evasion
- **Data Collection**: System enumeration, credential harvesting simulation
- **Self-Destruct**: 30-minute timer with comprehensive cleanup

### C2 Server Features
- **HTTP API**: RESTful interface for worm communications
- **Telnet Interface**: Real-time command and control
- **SQLite Database**: Persistent storage of infected hosts and commands
- **Real-time Monitoring**: Live status updates and alerts
- **Command Queuing**: Reliable command delivery to worms
- **Data Exfiltration**: Secure collection of harvested data

## 🛡️ Safety Features

### Built-in Safeguards
- **Lab Environment Detection**: Verifies controlled environment
- **Time Limits**: Maximum 2-hour runtime with 30-minute self-destruct
- **Propagation Limits**: Maximum 50 infection attempts
- **Multiple Confirmations**: Required for destructive operations
- **Comprehensive Logging**: Full audit trail of all activities
- **Automatic Cleanup**: Removes persistence and traces on exit

### Safety Confirmations Required
1. Controlled lab environment confirmation
2. Proper authorization verification
3. Educational purpose acknowledgment

## 📊 Monitoring & Analysis

### Generated Files
- `c2_server.log` - C2 server activity log
- `advanced_worm.log` - Worm execution log
- `c2_database.db` - SQLite database with host/command data
- `collected_data_*.json` - Simulated data collection results
- `exfil_*.json` - Data exfiltration files

### Analysis Capabilities
- Real-time infection monitoring
- Command execution tracking
- Network propagation analysis
- Persistence mechanism evaluation
- Anti-analysis technique assessment

## 🔧 Customization

### Worm Configuration
Edit `worm_analysis_educational.py`:
- Modify target ports in `self.target_ports`
- Adjust propagation limits in `self.max_propagation`
- Change self-destruct timer in `self.self_destruct_time`
- Update C2 servers in `self.c2_servers`

### C2 Server Configuration
Edit `c2_server_educational.py`:
- Change default ports in `main()` function
- Modify authentication in `authenticate()` method
- Adjust host activity timeout in `is_host_active()`

## 🚨 Troubleshooting

### Common Issues

1. **"Permission Denied" Errors**
   - Run as Administrator
   - Check Windows Defender exclusions
   - Verify firewall settings

2. **Network Connection Issues**
   - Ensure C2 server is running first
   - Check port availability (8080, 9999)
   - Verify network connectivity

3. **Python Import Errors**
   - Install missing dependencies: `pip install -r requirements.txt`
   - Check Python version (3.8+ required)

4. **Telnet Connection Failed**
   - Enable Windows Telnet client: `dism /online /Enable-Feature /FeatureName:TelnetClient`
   - Use alternative: `nc localhost 9999` or PuTTY

### Debug Mode
Enable verbose logging by modifying the logging level:
```python
logging.basicConfig(level=logging.DEBUG)
```

## 📚 Educational Resources

### Recommended Reading
- "The Art of Memory Forensics" by Volatility Foundation
- "Practical Malware Analysis" by Sikorski & Honig
- "Advanced Penetration Testing" by Wil Allsopp

### Related Topics
- Network security fundamentals
- Malware analysis techniques
- Incident response procedures
- Digital forensics methodology
- Threat hunting strategies

## ⚖️ Legal & Ethical Considerations

### Authorized Use Only
- Obtain explicit written permission before use
- Use only in controlled, isolated environments
- Comply with all applicable laws and regulations
- Follow responsible disclosure practices

### Educational Ethics
- Use for learning and defensive purposes only
- Do not modify for malicious purposes
- Respect privacy and confidentiality
- Report vulnerabilities responsibly

## 🤝 Contributing

This is an educational tool. Contributions should focus on:
- Enhanced educational value
- Improved safety mechanisms
- Better documentation
- Additional analysis capabilities

## 📞 Support

For educational use questions:
- Review the documentation thoroughly
- Check troubleshooting section
- Ensure proper lab environment setup

## 📄 License

This educational tool is provided for authorized cybersecurity research and education only. Users are responsible for compliance with all applicable laws and regulations.

---

**Remember: With great power comes great responsibility. Use these tools ethically and legally.** 