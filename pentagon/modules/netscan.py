"""
Comprehensive Nmap Scanner Module for Pentagon IoT Security Framework
Includes all major nmap features and scanning capabilities
"""

import nmap
import sys
import subprocess
import re
import shlex
from pathlib import Path

# Get local IP address to exclude from scans
res = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
ipaddr = res.stdout.split()[0] if res.stdout.strip() else ""

# Initialize PortScanner lazily to allow import without nmap binary
nm = None

def get_scanner():
    """Get or initialize the nmap PortScanner instance"""
    global nm
    if nm is None:
        nm = nmap.PortScanner()
    return nm

# Global variables for file output
fpath = None
fname = None


# =============================================================================
# INPUT VALIDATION AND SECURITY HELPERS
# =============================================================================

def validate_target(target):
    """
    Validate target IP address, hostname, or CIDR notation.
    Returns True if valid, False otherwise.
    """
    if not target or not isinstance(target, str):
        return False
    
    # Remove any dangerous shell characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in target:
            return False
    
    # Patterns for valid targets
    # IPv4 address (with optional CIDR)
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    # IPv6 address
    ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/\d{1,3})?$'
    # Hostname (basic validation)
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$'
    # IP range (e.g., 192.168.1.1-100)
    ip_range_pattern = r'^(\d{1,3}\.){3}\d{1,3}-\d{1,3}$'
    
    if (re.match(ipv4_pattern, target) or 
        re.match(ipv6_pattern, target) or 
        re.match(hostname_pattern, target) or
        re.match(ip_range_pattern, target)):
        return True
    
    return False


def validate_filename(filename):
    """
    Validate filename for output files.
    Returns True if valid, False otherwise.
    """
    if not filename or not isinstance(filename, str):
        return False
    
    # Only allow alphanumeric characters, underscores, hyphens, and dots
    filename_pattern = r'^[a-zA-Z0-9_.-]+$'
    return bool(re.match(filename_pattern, filename))


def run_nmap_secure(nmap_args_list, target):
    """
    Execute nmap scan securely using argument list instead of shell=True.
    Returns the result object.
    """
    if not validate_target(target):
        print("\033[31mError: Invalid target format. Please use valid IP address, hostname, or CIDR notation.\033[0m")
        return None
    
    try:
        cmd = ['nmap'] + nmap_args_list + [target]
        print(f"\n\033[33mScanning in progress...\033[0m")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print("\n\033[32mScan Complete!\033[0m")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"\033[31mErrors:\033[0m {result.stderr}")
        return result
    except Exception as e:
        print(f"\033[31mAn error occurred: {e}\033[0m")
        return None

# =============================================================================
# HOST DISCOVERY FUNCTIONS
# =============================================================================

def discover_hosts(target_ip, ch):
    """
    Basic host discovery using ICMP ping scan (-sn)
    """
    scanner = get_scanner()
    if ch == 'Y' or ch == 'y':
        nmap_args = f'-sn -n --exclude {ipaddr} -oN {fpath}'
        print(f"Output file: {fpath}")
    else:
        nmap_args = f'-sn -n --exclude {ipaddr}'
    
    print("\n Scanning network for available hosts...")
    scanner.scan(hosts=target_ip, arguments=nmap_args)
    
    print(f"Scan results for {target_ip}:\n")
    for host in scanner.all_hosts():
        if scanner[host].state() == "up":
            print(f"Host {host} is up")


def advanced_host_discovery(target_ip, ch):
    """
    Advanced host discovery with multiple probe types
    """
    print("\n\033[34m=== Advanced Host Discovery Options ===\033[0m")
    print("1.  TCP SYN Discovery (-PS)")
    print("2.  TCP ACK Discovery (-PA)")
    print("3.  UDP Discovery (-PU)")
    print("4.  SCTP Discovery (-PY)")
    print("5.  ICMP Echo Discovery (-PE)")
    print("6.  ICMP Timestamp Discovery (-PP)")
    print("7.  ICMP Netmask Discovery (-PM)")
    print("8.  ARP Discovery (-PR) - Local network only")
    print("9.  List Scan (-sL) - No packets sent")
    print("10. No Ping (-Pn) - Treat all hosts as online")
    print("11. Traceroute (--traceroute)")
    print("12. Combined Discovery (PE + PS + PA)")
    print("13. Back to main menu")
    
    discovery_choice = input("\nSelect discovery type: ")
    
    base_args = f'-n --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    discovery_options = {
        '1': f'-sn -PS {base_args}',
        '2': f'-sn -PA {base_args}',
        '3': f'-sn -PU {base_args}',
        '4': f'-sn -PY {base_args}',
        '5': f'-sn -PE {base_args}',
        '6': f'-sn -PP {base_args}',
        '7': f'-sn -PM {base_args}',
        '8': f'-sn -PR {base_args}',
        '9': f'-sL {base_args}',
        '10': f'-sn -Pn {base_args}',
        '11': f'-sn --traceroute {base_args}',
        '12': f'-sn -PE -PS22,80,443 -PA80,443 {base_args}',
    }
    
    if discovery_choice == '13':
        return
    
    if discovery_choice in discovery_options:
        nmap_args = discovery_options[discovery_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# PORT SCANNING FUNCTIONS
# =============================================================================

def port_scans(target_ip, ch):
    """
    Basic port scan on all ports
    """
    scanner = get_scanner()
    if ch == 'Y' or ch == 'y':
        nmap_args = f'-n -p- --exclude {ipaddr} -oN {fpath}'
    else:
        nmap_args = f'-n -p- --exclude {ipaddr}'
    
    print(f"Running Nmap port scans...")
    
    try:
        scanner.scan(hosts=target_ip, arguments=nmap_args)
        if scanner.all_hosts():
            print(f"Scan results for {target_ip}:\n")
            for host in scanner.all_hosts():
                print(f"Host: {host} ({scanner[host].hostname()})")
                print(f"State: {scanner[host].state()}")
                for protocol in scanner[host].all_protocols():
                    print(f"\nProtocol: {protocol}")
                    ports = scanner[host][protocol].keys()
                    for port in ports:
                        print(f"Port: {port}\tState: {scanner[host][protocol][port]['state']}")
                print("-" * 51)
        else:
            print(f"No hosts found for {target_ip}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def advanced_port_scan(target_ip, ch):
    """
    Advanced port scanning with multiple scan techniques
    """
    print("\n\033[34m=== Advanced Port Scan Types ===\033[0m")
    print("1.  TCP SYN Scan (-sS) - Stealth/Half-open scan [Root required]")
    print("2.  TCP Connect Scan (-sT) - Full TCP connection")
    print("3.  UDP Scan (-sU) - UDP port scanning")
    print("4.  TCP ACK Scan (-sA) - Firewall rule mapping")
    print("5.  TCP Window Scan (-sW) - Similar to ACK but examines window field")
    print("6.  TCP Maimon Scan (-sM) - FIN/ACK scan")
    print("7.  TCP FIN Scan (-sF) - Stealth scan")
    print("8.  TCP Xmas Scan (-sX) - FIN+PSH+URG flags")
    print("9.  TCP Null Scan (-sN) - No flags set")
    print("10. IP Protocol Scan (-sO) - Determine supported IP protocols")
    print("11. SCTP INIT Scan (-sY) - SCTP protocol scan")
    print("12. SCTP COOKIE-ECHO Scan (-sZ)")
    print("13. Custom Port Range")
    print("14. Top Ports Scan (--top-ports)")
    print("15. Fast Scan (-F) - Top 100 ports")
    print("16. Combined SYN + UDP Scan")
    print("17. Back to main menu")
    
    scan_choice = input("\nSelect scan type: ")
    
    if scan_choice == '17':
        return
    
    timing = select_timing_template()
    base_args = f'-n {timing} --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    scan_options = {
        '1': f'-sS {base_args}',
        '2': f'-sT {base_args}',
        '3': f'-sU {base_args}',
        '4': f'-sA {base_args}',
        '5': f'-sW {base_args}',
        '6': f'-sM {base_args}',
        '7': f'-sF {base_args}',
        '8': f'-sX {base_args}',
        '9': f'-sN {base_args}',
        '10': f'-sO {base_args}',
        '11': f'-sY {base_args}',
        '12': f'-sZ {base_args}',
        '15': f'-sS -F {base_args}',
        '16': f'-sS -sU {base_args}',
    }
    
    if scan_choice == '13':
        port_range = input("Enter port range (e.g., 1-1000, 22,80,443): ")
        nmap_args = f'-sS -p {port_range} {base_args}'
        run_nmap_scan(target_ip, nmap_args)
    elif scan_choice == '14':
        num_ports = input("Enter number of top ports to scan (default 1000): ") or "1000"
        nmap_args = f'-sS --top-ports {num_ports} {base_args}'
        run_nmap_scan(target_ip, nmap_args)
    elif scan_choice in scan_options:
        nmap_args = scan_options[scan_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# SERVICE AND VERSION DETECTION
# =============================================================================

def serv_scan(target_ip, ch):
    """
    OS and service version detection scan
    """
    # Build base arguments as a list for secure execution
    base_args = ['-A', '-n', '-T4', '--exclude', ipaddr]
    if ch == 'Y' or ch == 'y':
        base_args.extend(['-oN', fpath])
    
    print(f"\nRunning OS version and Service Detection Scans...")
    print("Scanning options: \n1. Detailed/Verbose Scan \n2. Quiet Scan")
    vb = input("Choose: ")
    
    if vb == '1':
        # Insert -vv after -A for verbose output
        args = ['-A', '-vv', '-n', '-T4', '--exclude', ipaddr]
        if ch == 'Y' or ch == 'y':
            args.extend(['-oN', fpath])
        nmap_args = ' '.join(args)
        print(f"Running: nmap {nmap_args} {target_ip}")
        run_nmap_secure(args, target_ip)
    elif vb == '2':
        nmap_args = ' '.join(base_args)
        print(f"Running: nmap {nmap_args} {target_ip}")
        run_nmap_secure(base_args, target_ip)
    else:
        print("\033[31mInvalid Input!!\033[0m")


def advanced_service_scan(target_ip, ch):
    """
    Advanced service and version detection options
    """
    print("\n\033[34m=== Advanced Service/Version Detection ===\033[0m")
    print("1.  Service Version Detection (-sV)")
    print("2.  Aggressive Version Detection (-sV --version-intensity 9)")
    print("3.  Light Version Detection (-sV --version-light)")
    print("4.  OS Detection (-O)")
    print("5.  Aggressive OS Detection (-O --osscan-guess)")
    print("6.  Combined Version + OS (-sV -O)")
    print("7.  Aggressive Scan (-A) - Version, OS, Scripts, Traceroute")
    print("8.  Script + Version Scan (-sC -sV)")
    print("9.  Back to main menu")
    
    scan_choice = input("\nSelect scan type: ")
    
    if scan_choice == '9':
        return
    
    timing = select_timing_template()
    base_args = f'-n {timing} --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    scan_options = {
        '1': f'-sV {base_args}',
        '2': f'-sV --version-intensity 9 {base_args}',
        '3': f'-sV --version-light {base_args}',
        '4': f'-O {base_args}',
        '5': f'-O --osscan-guess {base_args}',
        '6': f'-sV -O {base_args}',
        '7': f'-A {base_args}',
        '8': f'-sC -sV {base_args}',
    }
    
    if scan_choice in scan_options:
        nmap_args = scan_options[scan_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# VULNERABILITY AND NSE SCRIPT SCANNING
# =============================================================================

def vuln_scan(target_ip, ch):
    """
    Basic vulnerability scan using NSE scripts
    """
    if ch == 'Y' or ch == 'y':
        args = ['--script=vuln', '-n', '-vv', '--exclude', ipaddr, '-oN', fpath]
    else:
        args = ['-sV', '-vv', '-n', '--script=vuln', '--exclude', ipaddr]
    
    print(f"\nRunning Vulnerability Scan")
    run_nmap_secure(args, target_ip)


def nse_script_scan(target_ip, ch):
    """
    NSE (Nmap Scripting Engine) script categories and custom scripts
    """
    print("\n\033[34m=== NSE Script Categories ===\033[0m")
    print("1.  Auth - Authentication bypass/testing scripts")
    print("2.  Broadcast - Network broadcast discovery")
    print("3.  Brute - Brute force password auditing")
    print("4.  Default - Default scripts (-sC equivalent)")
    print("5.  Discovery - Service/host discovery")
    print("6.  DOS - Denial of Service testing")
    print("7.  Exploit - Active exploitation scripts")
    print("8.  External - External service queries")
    print("9.  Fuzzer - Fuzz testing scripts")
    print("10. Intrusive - Potentially disruptive scripts")
    print("11. Malware - Malware detection scripts")
    print("12. Safe - Non-intrusive scripts")
    print("13. Version - Enhanced version detection")
    print("14. Vuln - Vulnerability detection")
    print("15. All Scripts (safe,vuln,discovery)")
    print("16. Custom Script Name")
    print("17. HTTP Scripts (http-*)")
    print("18. SMB Scripts (smb-*)")
    print("19. SSH Scripts (ssh-*)")
    print("20. SSL/TLS Scripts (ssl-*)")
    print("21. DNS Scripts (dns-*)")
    print("22. FTP Scripts (ftp-*)")
    print("23. MySQL Scripts (mysql-*)")
    print("24. Back to main menu")
    
    script_choice = input("\nSelect script category: ")
    
    if script_choice == '24':
        return
    
    timing = select_timing_template()
    base_args = f'-sV -n {timing} --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    script_options = {
        '1': f'--script=auth {base_args}',
        '2': f'--script=broadcast {base_args}',
        '3': f'--script=brute {base_args}',
        '4': f'-sC {base_args}',
        '5': f'--script=discovery {base_args}',
        '6': f'--script=dos {base_args}',
        '7': f'--script=exploit {base_args}',
        '8': f'--script=external {base_args}',
        '9': f'--script=fuzzer {base_args}',
        '10': f'--script=intrusive {base_args}',
        '11': f'--script=malware {base_args}',
        '12': f'--script=safe {base_args}',
        '13': f'--script=version {base_args}',
        '14': f'--script=vuln {base_args}',
        '15': f'--script="safe,vuln,discovery" {base_args}',
        '17': f'--script="http-*" {base_args}',
        '18': f'--script="smb-*" {base_args}',
        '19': f'--script="ssh-*" {base_args}',
        '20': f'--script="ssl-*" {base_args}',
        '21': f'--script="dns-*" {base_args}',
        '22': f'--script="ftp-*" {base_args}',
        '23': f'--script="mysql-*" {base_args}',
    }
    
    if script_choice == '16':
        script_name = input("Enter script name(s) (comma-separated): ")
        nmap_args = f'--script={script_name} {base_args}'
        run_nmap_scan(target_ip, nmap_args)
    elif script_choice in script_options:
        nmap_args = script_options[script_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# FIREWALL AND IDS EVASION
# =============================================================================

def evasion_scan(target_ip, ch):
    """
    Firewall/IDS evasion and spoofing techniques
    """
    print("\n\033[34m=== Firewall/IDS Evasion Options ===\033[0m")
    print("1.  Fragment Packets (-f)")
    print("2.  Custom MTU (--mtu)")
    print("3.  Decoy Scan (-D)")
    print("4.  Idle/Zombie Scan (-sI)")
    print("5.  Source Port Spoofing (--source-port)")
    print("6.  Append Random Data (--data-length)")
    print("7.  Randomize Target Order (--randomize-hosts)")
    print("8.  MAC Address Spoofing (--spoof-mac)")
    print("9.  Set TTL (--ttl)")
    print("10. Bad Checksum (--badsum)")
    print("11. Combined Evasion (Fragment + Random Data + Custom TTL)")
    print("12. Slow Scan (T0) for IDS Evasion")
    print("13. Back to main menu")
    
    evasion_choice = input("\nSelect evasion technique: ")
    
    if evasion_choice == '13':
        return
    
    base_args = f'-sS -n --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    if evasion_choice == '1':
        nmap_args = f'-f {base_args}'
    elif evasion_choice == '2':
        mtu = input("Enter MTU value (must be multiple of 8): ")
        nmap_args = f'--mtu {mtu} {base_args}'
    elif evasion_choice == '3':
        decoys = input("Enter decoy IPs (comma-separated, use ME for your position): ")
        nmap_args = f'-D {decoys} {base_args}'
    elif evasion_choice == '4':
        zombie = input("Enter zombie host IP: ")
        nmap_args = f'-sI {zombie} {base_args}'
    elif evasion_choice == '5':
        src_port = input("Enter source port (common: 53, 80, 443): ")
        nmap_args = f'--source-port {src_port} {base_args}'
    elif evasion_choice == '6':
        data_len = input("Enter random data length to append: ")
        nmap_args = f'--data-length {data_len} {base_args}'
    elif evasion_choice == '7':
        nmap_args = f'--randomize-hosts {base_args}'
    elif evasion_choice == '8':
        print("MAC options: 0 (random), Vendor name, or specific MAC")
        mac = input("Enter MAC address option: ")
        nmap_args = f'--spoof-mac {mac} {base_args}'
    elif evasion_choice == '9':
        ttl = input("Enter TTL value: ")
        nmap_args = f'--ttl {ttl} {base_args}'
    elif evasion_choice == '10':
        nmap_args = f'--badsum {base_args}'
    elif evasion_choice == '11':
        nmap_args = f'-f --data-length 25 --ttl 64 {base_args}'
    elif evasion_choice == '12':
        nmap_args = f'-T0 {base_args}'
    else:
        print("\033[31mInvalid choice!\033[0m")
        return
    
    print(f"\nRunning: nmap {nmap_args} {target_ip}")
    run_nmap_scan(target_ip, nmap_args)


# =============================================================================
# OUTPUT OPTIONS
# =============================================================================

def output_format_scan(target_ip, ch):
    """
    Configure output formats for scan results
    """
    print("\n\033[34m=== Output Format Options ===\033[0m")
    print("1.  Normal Output (-oN)")
    print("2.  XML Output (-oX)")
    print("3.  Grepable Output (-oG)")
    print("4.  All Formats (-oA)")
    print("5.  Script Kiddie Output (-oS)")
    print("6.  Append to existing file (--append-output)")
    print("7.  Back to main menu")
    
    output_choice = input("\nSelect output format: ")
    
    if output_choice == '7':
        return
    
    filename = input("Enter output filename (without extension): ")
    timing = select_timing_template()
    base_args = f'-sS -sV -n {timing} --exclude {ipaddr}'
    
    output_options = {
        '1': f'{base_args} -oN {filename}.nmap',
        '2': f'{base_args} -oX {filename}.xml',
        '3': f'{base_args} -oG {filename}.gnmap',
        '4': f'{base_args} -oA {filename}',
        '5': f'{base_args} -oS {filename}.txt',
        '6': f'{base_args} --append-output -oN {filename}.nmap',
    }
    
    if output_choice in output_options:
        nmap_args = output_options[output_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# IPv6 SCANNING
# =============================================================================

def ipv6_scan(target_ip, ch):
    """
    IPv6 scanning options
    """
    print("\n\033[34m=== IPv6 Scanning Options ===\033[0m")
    print("1.  IPv6 Ping Scan (-6 -sn)")
    print("2.  IPv6 Port Scan (-6 -sS)")
    print("3.  IPv6 Service Detection (-6 -sV)")
    print("4.  IPv6 Full Scan (-6 -A)")
    print("5.  Back to main menu")
    
    ipv6_choice = input("\nSelect IPv6 scan type: ")
    
    if ipv6_choice == '5':
        return
    
    ipv6_target = input("Enter IPv6 address or hostname: ")
    timing = select_timing_template()
    base_args = f'-6 -n {timing}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    ipv6_options = {
        '1': f'-sn {base_args}',
        '2': f'-sS {base_args}',
        '3': f'-sV {base_args}',
        '4': f'-A {base_args}',
    }
    
    if ipv6_choice in ipv6_options:
        nmap_args = ipv6_options[ipv6_choice]
        print(f"\nRunning: nmap {nmap_args} {ipv6_target}")
        run_nmap_scan(ipv6_target, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# PERFORMANCE AND TIMING
# =============================================================================

def select_timing_template():
    """
    Select timing template for scans
    """
    print("\n\033[34m=== Timing Templates ===\033[0m")
    print("0. T0 - Paranoid (IDS evasion, very slow)")
    print("1. T1 - Sneaky (IDS evasion)")
    print("2. T2 - Polite (Less bandwidth, slower)")
    print("3. T3 - Normal (Default)")
    print("4. T4 - Aggressive (Fast, reliable networks)")
    print("5. T5 - Insane (Very fast, may miss ports)")
    
    timing_choice = input("\nSelect timing (default 3): ") or '3'
    
    timing_map = {
        '0': '-T0',
        '1': '-T1',
        '2': '-T2',
        '3': '-T3',
        '4': '-T4',
        '5': '-T5',
    }
    
    return timing_map.get(timing_choice, '-T3')


def performance_options(target_ip, ch):
    """
    Advanced performance tuning options
    """
    print("\n\033[34m=== Performance Tuning ===\033[0m")
    print("1.  Set Minimum Rate (--min-rate)")
    print("2.  Set Maximum Rate (--max-rate)")
    print("3.  Set Parallelism (--min-parallelism/--max-parallelism)")
    print("4.  Set Host Timeout (--host-timeout)")
    print("5.  Set Scan Delay (--scan-delay)")
    print("6.  Set Max Retries (--max-retries)")
    print("7.  Disable DNS Resolution (-n)")
    print("8.  Always DNS Resolve (-R)")
    print("9.  Custom Performance Scan")
    print("10. Back to main menu")
    
    perf_choice = input("\nSelect option: ")
    
    if perf_choice == '10':
        return
    
    base_args = f'-sS -n --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    if perf_choice == '1':
        rate = input("Enter minimum packets per second: ")
        nmap_args = f'--min-rate {rate} {base_args}'
    elif perf_choice == '2':
        rate = input("Enter maximum packets per second: ")
        nmap_args = f'--max-rate {rate} {base_args}'
    elif perf_choice == '3':
        min_p = input("Enter min parallelism: ")
        max_p = input("Enter max parallelism: ")
        nmap_args = f'--min-parallelism {min_p} --max-parallelism {max_p} {base_args}'
    elif perf_choice == '4':
        timeout = input("Enter host timeout (e.g., 30m, 1h): ")
        nmap_args = f'--host-timeout {timeout} {base_args}'
    elif perf_choice == '5':
        delay = input("Enter scan delay in ms: ")
        nmap_args = f'--scan-delay {delay}ms {base_args}'
    elif perf_choice == '6':
        retries = input("Enter max retries: ")
        nmap_args = f'--max-retries {retries} {base_args}'
    elif perf_choice == '7':
        nmap_args = f'-n {base_args}'
    elif perf_choice == '8':
        nmap_args = f'-R {base_args}'
    elif perf_choice == '9':
        print("Custom performance options (space-separated):")
        custom = input("Enter options: ")
        nmap_args = f'{custom} {base_args}'
    else:
        print("\033[31mInvalid choice!\033[0m")
        return
    
    print(f"\nRunning: nmap {nmap_args} {target_ip}")
    run_nmap_scan(target_ip, nmap_args)


# =============================================================================
# QUICK SCAN PROFILES
# =============================================================================

def quick_scan_profiles(target_ip, ch):
    """
    Pre-configured scan profiles for common use cases
    """
    print("\n\033[34m=== Quick Scan Profiles ===\033[0m")
    print("1.  Quick Scan (Top 100 ports, fast)")
    print("2.  Quick Scan Plus (Top 100 + version)")
    print("3.  Ping Sweep (Host discovery only)")
    print("4.  Regular Scan (Top 1000 ports)")
    print("5.  Intense Scan (All ports, version, scripts)")
    print("6.  Intense + UDP (TCP + UDP scanning)")
    print("7.  Stealth Scan (SYN scan, slow timing)")
    print("8.  Comprehensive Scan (All options)")
    print("9.  IoT Device Scan (Common IoT ports)")
    print("10. Web Server Scan (HTTP/HTTPS focused)")
    print("11. Database Scan (Common DB ports)")
    print("12. Back to main menu")
    
    profile_choice = input("\nSelect profile: ")
    
    if profile_choice == '12':
        return
    
    base_args = f'-n --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    profiles = {
        '1': f'-sS -F -T4 {base_args}',
        '2': f'-sS -sV -F -T4 {base_args}',
        '3': f'-sn -PE -PA21,23,80,3389 {base_args}',
        '4': f'-sS -sV -T3 {base_args}',
        '5': f'-sS -sV -sC -A -p- -T4 {base_args}',
        '6': f'-sS -sU -sV -sC -A -T4 {base_args}',
        '7': f'-sS -T1 -f {base_args}',
        '8': f'-sS -sU -sV -sC -A -O -p- --script="vuln,safe" -T4 {base_args}',
        '9': f'-sS -sV -p 23,80,81,443,554,8080,8443,8883,1883,5683,502,102 -T4 {base_args}',
        '10': f'-sS -sV -p 80,443,8080,8443 --script="http-*" -T4 {base_args}',
        '11': f'-sS -sV -p 1433,1521,3306,5432,27017,6379,9200,5984 --script="*-brute,*-info" -T4 {base_args}',
    }
    
    if profile_choice in profiles:
        nmap_args = profiles[profile_choice]
        print(f"\nRunning: nmap {nmap_args} {target_ip}")
        run_nmap_scan(target_ip, nmap_args)
    else:
        print("\033[31mInvalid choice!\033[0m")


# =============================================================================
# CUSTOM SCAN
# =============================================================================

def custom_scan(target_ip, ch):
    """
    Build a custom nmap scan with user-specified options
    """
    print("\n\033[34m=== Custom Scan Builder ===\033[0m")
    
    # Scan type
    print("\nSelect scan type:")
    print("1. SYN (-sS)  2. Connect (-sT)  3. UDP (-sU)  4. ACK (-sA)")
    print("5. FIN (-sF)  6. Xmas (-sX)  7. Null (-sN)  8. None")
    scan_type = input("Choice: ")
    
    scan_map = {
        '1': '-sS', '2': '-sT', '3': '-sU', '4': '-sA',
        '5': '-sF', '6': '-sX', '7': '-sN', '8': ''
    }
    scan_arg = scan_map.get(scan_type, '')
    
    # Port specification
    print("\nPort specification:")
    print("1. All ports (-p-)  2. Top ports  3. Custom range  4. Default")
    port_choice = input("Choice: ")
    
    if port_choice == '1':
        port_arg = '-p-'
    elif port_choice == '2':
        num = input("Number of top ports: ")
        port_arg = f'--top-ports {num}'
    elif port_choice == '3':
        ports = input("Enter ports (e.g., 22,80,443 or 1-1000): ")
        port_arg = f'-p {ports}'
    else:
        port_arg = ''
    
    # Version detection
    version = input("\nEnable version detection? (y/n): ")
    version_arg = '-sV' if version.lower() == 'y' else ''
    
    # OS detection
    os_detect = input("Enable OS detection? (y/n): ")
    os_arg = '-O' if os_detect.lower() == 'y' else ''
    
    # Script scanning
    script = input("Enable default scripts? (y/n): ")
    script_arg = '-sC' if script.lower() == 'y' else ''
    
    # Custom scripts
    custom_script = input("Custom script name (or press Enter to skip): ")
    custom_script_arg = f'--script={custom_script}' if custom_script else ''
    
    # Timing
    timing = select_timing_template()
    
    # Verbosity
    verbose = input("Verbose output? (y/n): ")
    verbose_arg = '-vv' if verbose.lower() == 'y' else ''
    
    # Build command
    base_args = f'-n --exclude {ipaddr}'
    if ch == 'Y' or ch == 'y':
        base_args += f' -oN {fpath}'
    
    nmap_args = f'{scan_arg} {port_arg} {version_arg} {os_arg} {script_arg} {custom_script_arg} {timing} {verbose_arg} {base_args}'
    nmap_args = ' '.join(nmap_args.split())  # Clean up extra spaces
    
    print(f"\nBuilt command: nmap {nmap_args} {target_ip}")
    confirm = input("Execute this scan? (y/n): ")
    
    if confirm.lower() == 'y':
        run_nmap_scan(target_ip, nmap_args)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def run_nmap_scan(target_ip, nmap_args):
    """
    Execute nmap scan and display results.
    This function parses the nmap_args string and uses secure execution.
    """
    if not validate_target(target_ip):
        print("\033[31mError: Invalid target format. Please use valid IP address, hostname, or CIDR notation.\033[0m")
        return
    
    try:
        print(f"\n\033[33mScanning in progress...\033[0m")
        # Parse the nmap_args string into a list, handling quoted arguments properly
        args_list = shlex.split(nmap_args)
        cmd = ['nmap'] + args_list + [target_ip]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        print("\n\033[32mScan Complete!\033[0m")
        if result.stdout:
            print(result.stdout)
        if result.stderr:
            print(f"\033[31mErrors:\033[0m {result.stderr}")
    except Exception as e:
        print(f"\033[31mAn error occurred: {e}\033[0m")


def show_nmap_help():
    """
    Display nmap help and common options
    """
    print("\n\033[34m=== Nmap Quick Reference ===\033[0m")
    print("""
SCAN TYPES:
  -sS    TCP SYN (Stealth)      -sT    TCP Connect
  -sU    UDP Scan               -sA    TCP ACK
  -sF    TCP FIN                -sX    TCP Xmas
  -sN    TCP Null               -sO    IP Protocol
  -sI    Idle Scan              -sY    SCTP INIT

HOST DISCOVERY:
  -sn    Ping scan (no ports)   -Pn    No ping
  -PS    TCP SYN discovery      -PA    TCP ACK discovery
  -PU    UDP discovery          -PE    ICMP echo
  -PR    ARP scan

PORT SPECIFICATION:
  -p-    All 65535 ports        -F     Fast (100 ports)
  -p     Custom ports           --top-ports N

SERVICE/VERSION:
  -sV    Version detection      -O     OS detection
  -A     Aggressive (all)       -sC    Default scripts

TIMING:
  -T0    Paranoid               -T1    Sneaky
  -T2    Polite                 -T3    Normal
  -T4    Aggressive             -T5    Insane

OUTPUT:
  -oN    Normal                 -oX    XML
  -oG    Grepable               -oA    All formats
  -v     Verbose                -vv    Very verbose
    """)
    input("\nPress Enter to continue...")


# =============================================================================
# MENU SYSTEM
# =============================================================================

def show_menu():
    """
    Display main menu options
    """
    print("\n\033[34m" + "=" * 50)
    print("         NMAP SCANNER - MAIN MENU")
    print("=" * 50 + "\033[0m")
    print("\033[34m")
    print("  HOST DISCOVERY")
    print("    1.  Basic Host Discovery")
    print("    2.  Advanced Host Discovery")
    print("")
    print("  PORT SCANNING")
    print("    3.  Basic Port Scan")
    print("    4.  Advanced Port Scan")
    print("")
    print("  SERVICE DETECTION")
    print("    5.  OS and Service Scan")
    print("    6.  Advanced Service Detection")
    print("")
    print("  VULNERABILITY & SCRIPTS")
    print("    7.  Vulnerability Scan")
    print("    8.  NSE Script Scan")
    print("")
    print("  ADVANCED OPTIONS")
    print("    9.  Firewall/IDS Evasion")
    print("    10. Output Format Options")
    print("    11. IPv6 Scanning")
    print("    12. Performance Tuning")
    print("")
    print("  QUICK OPTIONS")
    print("    13. Quick Scan Profiles")
    print("    14. Custom Scan Builder")
    print("    15. Nmap Help/Reference")
    print("")
    print("    16. Exit")
    print("\033[0m")



def start():
    """
    Main entry point for the network scanner module
    """
    global fpath
    global fname
    
    art = '''
    '##::: ##:'########:'########::'######:::'######:::::'###::::'##::: ##:
     ###:: ##: ##.....::... ##..::'##... ##:'##... ##:::'## ##::: ###:: ##:
     ####: ##: ##:::::::::: ##:::: ##:::..:: ##:::..:::'##:. ##:: ####: ##:
     ## ## ##: ######:::::: ##::::. ######:: ##:::::::'##:::. ##: ## ## ##:
     ##. ####: ##...::::::: ##:::::..... ##: ##::::::: #########: ##. ####:
     ##:. ###: ##:::::::::: ##::::'##::: ##: ##::: ##: ##.... ##: ##:. ###:
     ##::. ##: ########:::: ##::::. ######::. ######:: ##:::: ##: ##::. ##:
     ..::::..::........:::::..::::::......::::......:::..:::::..::..::::..::

    '''
    print(f"\033[31m{art}\033[0m")
    
    # Get and validate target IP
    while True:
        target_ip = input("\n  \033[34mEnter target host or IP Address or Network Subnet (example.com/x.x.x.x): \033[0m")
        if validate_target(target_ip):
            break
        print("\033[31m  Invalid target format! Please enter a valid IP address, hostname, or CIDR notation.\033[0m")

    # Get current directory using secure method
    current_dir_result = subprocess.run(['pwd'], capture_output=True, text=True)
    current_directory = current_dir_result.stdout.strip()
    output_dir = current_directory + "/scan_result"

    dir_path = Path(output_dir)
    
    ch = input("\n  \033[34mDo you want to save the scan results? (Y/N): \033[0m")
    
    # Create output directory if it doesn't exist
    if not dir_path.is_dir():
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # Convert to string for path concatenation
    dir_path_str = str(dir_path)
    
    if ch == 'Y' or ch == 'y':
        while True:
            fname = input("\n  Enter filename: ")
            if validate_filename(fname):
                fpath = f"{dir_path_str}/{fname}"
                break
            print("\033[31m  Invalid filename! Please use only alphanumeric characters, underscores, hyphens, and dots.\033[0m")
    elif ch == 'N' or ch == 'n':
        pass
    else:
        print("\n  \033[31mInvalid Choice! Proceeding without saving.\033[0m")
        ch = 'n'

    while True:
        show_menu()
        try:
            choice = int(input("\n\033[34mEnter your choice: \033[0m"))
            
            # Host Discovery
            if choice == 1:
                discover_hosts(target_ip, ch)
            elif choice == 2:
                advanced_host_discovery(target_ip, ch)
            
            # Port Scanning
            elif choice == 3:
                port_scans(target_ip, ch)
            elif choice == 4:
                advanced_port_scan(target_ip, ch)
            
            # Service Detection
            elif choice == 5:
                serv_scan(target_ip, ch)
            elif choice == 6:
                advanced_service_scan(target_ip, ch)
            
            # Vulnerability & Scripts
            elif choice == 7:
                vuln_scan(target_ip, ch)
            elif choice == 8:
                nse_script_scan(target_ip, ch)
            
            # Advanced Options
            elif choice == 9:
                evasion_scan(target_ip, ch)
            elif choice == 10:
                output_format_scan(target_ip, ch)
            elif choice == 11:
                ipv6_scan(target_ip, ch)
            elif choice == 12:
                performance_options(target_ip, ch)
            
            # Quick Options
            elif choice == 13:
                quick_scan_profiles(target_ip, ch)
            elif choice == 14:
                custom_scan(target_ip, ch)
            elif choice == 15:
                show_nmap_help()
            
            # Exit
            elif choice == 16:
                print("\033[33mExiting the network scanner.\033[0m")
                break
            else:
                print("\033[31mInvalid choice! Please select a valid option (1-16).\033[0m")
                
        except ValueError as e:
            print(f"\n\033[31mError: Please enter a valid number.\033[0m")
        except KeyboardInterrupt:
            print("\n\033[31mScan interrupted by user.\033[0m")
            break
    
    return 0





if __name__ == "___main__":
    start()
