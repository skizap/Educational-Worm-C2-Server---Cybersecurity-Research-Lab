# Red Team Educational Tools

**ETHICAL DISCLAIMER: These tools are for authorized testing only. Misuse is prohibited.**

This repository contains advanced educational tools for cybersecurity research and penetration testing in controlled lab environments.

## Tools Overview

### 1. Advanced Educational Worm (Python)
- **File**: `worm_analysis_educational.py`
- **Language**: Python 3.x
- **Requirements**: See `requirements.txt`
- **Features**: Advanced worm propagation techniques, C2 communication, data collection

### 2. RedV2 - Advanced Educational Worm (PowerShell Edition)
- **File**: `RedV2_educational.ps1`
- **Language**: PowerShell (Native Windows)
- **Requirements**: Windows PowerShell (pre-installed on Windows)
- **Features**: 
  - Works out-of-the-box on Windows without additional dependencies
  - Advanced network discovery and exploitation simulation
  - Multiple persistence mechanisms
  - Anti-analysis and evasion techniques
  - Polymorphic payload generation
  - Self-destruct capabilities with safety limits

### 3. C2 Server
- **File**: `c2_server_educational.py`
- **Language**: Python 3.x
- **Purpose**: Command and control server for educational worms

## Quick Start

### Running RedV2 (PowerShell Edition) - Recommended for Windows Labs
```batch
# Method 1: Using the launcher (recommended)
run_RedV2.bat

# Method 2: Direct PowerShell execution
powershell.exe -ExecutionPolicy Bypass -File "RedV2_educational.ps1"
```

### Running Python Worm (Requires Python installation)
```bash
# Install dependencies
pip install -r requirements.txt

# Run the worm
python worm_analysis_educational.py

# Run C2 server (in separate terminal)
python c2_server_educational.py
```

## Safety Features

Both worms include comprehensive safety mechanisms:

- **Self-Destruct Timer**: Automatic cleanup after 30 minutes (configurable)
- **Propagation Limits**: Maximum 50 infection attempts (configurable)
- **Runtime Limits**: Maximum 2 hours execution time (configurable)
- **Lab Environment Detection**: Enhanced safety in non-lab environments
- **Multiple Confirmation Prompts**: Requires explicit user confirmation
- **Automatic Cleanup**: Removes persistence mechanisms and traces

## Educational Features

### Network Techniques
- ARP table scanning
- Ping sweep enumeration
- Port scanning with service detection
- NetBIOS enumeration

### Exploitation Simulation
- SMB vulnerability exploitation (EternalBlue-style)
- SSH brute force attacks
- WMI/PowerShell remoting exploitation
- Web application vulnerability scanning
- SQL injection detection
- Remote code execution testing

### Persistence Mechanisms
- Registry Run keys
- Scheduled tasks
- Startup folder placement
- Service installation (Python version)

### Anti-Analysis Techniques
- VM detection
- Debugger detection
- Sandbox evasion
- Resource limitation detection

### Data Collection
- System information gathering
- Network configuration enumeration
- Browser credential simulation
- Interesting file discovery

## Configuration Options

### RedV2 PowerShell Parameters
```powershell
# Custom configuration example
.\RedV2_educational.ps1 -MaxRuntime 60 -SelfDestructTimer 15 -MaxPropagation 25
```

### Python Worm Configuration
Edit the configuration variables in the script:
- `max_runtime`: Maximum execution time
- `self_destruct_time`: Self-destruct timer
- `max_propagation`: Maximum propagation attempts

## Lab Environment Setup

### Recommended Lab Configuration
1. **Isolated Network**: Use air-gapped or VLAN-isolated environment
2. **Virtual Machines**: VMware, VirtualBox, or Hyper-V
3. **Multiple OS**: Windows, Linux targets for comprehensive testing
4. **Vulnerable Services**: Intentionally vulnerable applications
5. **Monitoring**: Network and host-based monitoring tools

### Lab Indicators
The tools look for these lab environment indicators:
- VM hypervisor detection
- Lab environment marker files
- Specific hostname patterns
- Limited system resources

## Legal and Ethical Considerations

### ⚠️ IMPORTANT WARNINGS ⚠️

1. **Authorization Required**: Only use in environments you own or have explicit written permission to test
2. **Controlled Environment**: Use only in isolated lab environments
3. **Educational Purpose**: Intended for cybersecurity education and research only
4. **No Malicious Use**: Do not use for unauthorized access or malicious activities
5. **Compliance**: Ensure compliance with local laws and regulations

### Recommended Use Cases
- Cybersecurity training and education
- Red team exercises in controlled environments
- Security research and development
- Penetration testing methodology development
- Academic research in cybersecurity

## Technical Requirements

### RedV2 (PowerShell Edition)
- **OS**: Windows 7/8/10/11, Windows Server 2008+
- **PowerShell**: Version 3.0+ (pre-installed on modern Windows)
- **Privileges**: User-level (Administrator recommended for full features)
- **Dependencies**: None (uses built-in Windows components)

### Python Edition
- **OS**: Windows, Linux, macOS
- **Python**: 3.6+
- **Dependencies**: See `requirements.txt`
- **Privileges**: User-level (root/admin for some features)

## Troubleshooting

### Common Issues

1. **Execution Policy Errors (PowerShell)**
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
   ```

2. **Permission Denied**
   - Run as Administrator (Windows)
   - Use sudo for elevated privileges (Linux)

3. **Network Discovery Issues**
   - Check firewall settings
   - Verify network connectivity
   - Ensure proper lab network configuration

4. **C2 Communication Failures**
   - Start C2 server before running worm
   - Check port availability (8080, 9999)
   - Verify firewall rules

## Contributing

This is an educational project. Contributions should focus on:
- Enhanced safety mechanisms
- Additional educational features
- Better documentation
- Bug fixes and improvements

## Disclaimer

These tools are provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by these tools. Users are solely responsible for ensuring they have proper authorization and are complying with applicable laws and regulations.

## License

This project is intended for educational use only. See the individual files for specific licensing terms. 