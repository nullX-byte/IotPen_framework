import subprocess
import time
import pyshark
from scapy.all import sniff
from scapy.utils import wrpcap
from scapy.utils import PcapWriter
import getpass
import shlex
from pathlib import Path
import re

# list to store captured packets
packet_list = []

# =============================================================================
# INPUT VALIDATION HELPERS
# =============================================================================

def validate_filename(filename):
    """
    Validate filename format - only allow safe characters.
    Returns True if valid, False otherwise.
    """
    if not filename or not isinstance(filename, str):
        return False
    # Only allow alphanumeric, underscores, hyphens
    filename_pattern = r'^[a-zA-Z0-9_-]+$'
    return bool(re.match(filename_pattern, filename))


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


# Define the packet capture callback function

def packet_callback(packet):
    # Append the captured packet to the list
    packet_list.append(packet)


# This function captures the packet on specific interface, saves in a file and opens it in wireshark

def capture_and_open():
    """
    Main function to capture packets on specified interface and open in Wireshark.
    """
    art ='''
    :::       :::     ::: ::::::::::: ::::::::  :::    ::: :::::::::: :::::::::
    :+:       :+:   :+: :+:   :+:    :+:    :+: :+:    :+: :+:        :+:    :+:
    +:+       +:+  +:+   +:+  +:+    +:+        +:+    +:+ +:+        +:+    +:+
    +#+  +:+  +#+ +#++:++#++: +#+    +#+        +#++:++#++ +#++:++#   +#++:++#:
    +#+ +#+#+ +#+ +#+     +#+ +#+    +#+        +#+    +#+ +#+        +#+    +#+
     #+#+# #+#+#  #+#     #+# #+#    #+#    #+# #+#    #+# #+#        #+#    #+#
      ###   ###   ###     ### ###     ########  ###    ### ########## ###    ###
'''

    print(f"\n\033[34m{art}\033[0m\n\n\033[36m1. Bluetooth \n2. Wireless(Wifi)")
    choice = input("\n\033[36mChoose interface:")
    
    if choice not in ['1', '2']:
        print("\033[31mInvalid choice! Please select 1 or 2.\033[0m")
        return
    
    interface = enable_device(choice)
    if not interface:
        print("\033[31mFailed to enable interface.\033[0m")
        return
    
    # defining file name and path
    file_ext = ".pcap"

    # Directory where the captured packets are stored - using subprocess securely
    current_directory = subprocess.run(['pwd'], capture_output=True, text=True).stdout.strip()
    output_dir = current_directory + "/captures"

    dir_path = Path(f'{output_dir}')
    # Check if the directory exists

    if dir_path.is_dir():
        pass
    else:
        # Create directory securely using pathlib
        dir_path.mkdir(parents=True, exist_ok=True)
    
    # Get and validate filename
    while True:
        fname = input("\n  Enter filename:")
        if validate_filename(fname):
            break
        print("\033[31mInvalid filename! Use only alphanumeric characters, underscores, and hyphens.\033[0m")
    
    file = f"{dir_path}/{fname}{file_ext}"
    
    # Get and validate capture duration
    while True:
        duration_str = input("\n\033[36m[*] How long do you want to capture?(in seconds):")
        if validate_positive_integer(duration_str, max_val=3600):
            capture_duration = int(duration_str)
            break
        print("\033[31mInvalid duration! Please enter a positive integer (max 3600 seconds).\033[0m")
    
    # Starting Live capture on specified interface
    
    print(f"\n\033[36mStarting Live Packet Capture on {interface} interface for {capture_duration} seconds...\n ")  

    # Capturing bluetooth packets
    if interface =='bluetooth0':
        pyshark.LiveCapture(interface=interface, output_file=file).sniff(timeout=capture_duration)
    else:
        # Capturing wifi packets
        sniff(iface=interface, prn=packet_callback, timeout=capture_duration)
        if len(packet_list) > 0:   
            pktdump =PcapWriter(file, append="True", sync=True)
            pktdump.write(packet_list)
        else:
            print("\033[33mNo packets captured.")

    print(f"\033[36mNumber of packets captured: {len(packet_list)}")
    
    print(f"\n\033[36mCaptured packets. Opening Wireshark...")
    time.sleep(2)
   
    # Running wireshark
    wireshark_path = "/usr/bin/wireshark"

    # Captures status code of the wireshark
    exit_stat = subprocess.run([wireshark_path, file])
    ret_code = exit_stat.returncode
    time.sleep(1)

    # Checks for successfull exit of the wireshark and disables the monitor mode
    if ret_code == 0 and interface:
        # Use argument list instead of shell=True for security
        try:
            man_mode = subprocess.run(['sudo', 'airmon-ng', 'stop', interface], capture_output=True, text=True)
            print(man_mode.stdout)
            restart_nm = subprocess.run(['sudo', 'systemctl', 'restart', 'NetworkManager'], capture_output=True, text=True)
            print(restart_nm.stdout)
        except Exception as e:
            print(f"\033[31mError stopping monitor mode: {e}\033[0m")
        return 0
    else:
        print("\n\033[31m\033[5mError while closing wireshark !!!\033[0m")


# Enabling monitor mode of the wifi card or enables bluetooth
def enable_mon(ch, iface):
    """
    Enable monitor mode on wifi interface or enable wifi.
    """
    if ch == 1:
        try:
            # Run the `nmcli radio wifi` command to check Wi-Fi status
            result = subprocess.run(['nmcli', 'radio', 'wifi'], capture_output=True, text=True)

            # Check the output for status
            if result.returncode == 0:
                if 'enabled' in result.stdout.lower():
                    # Printing blinking text using ANSI escape codes
                    print("\033[5m\033[33m\033[1mWi-Fi is On!\033[0m")

                elif 'disabled' in result.stdout.lower():
                    print("\n\033[35mTurning on Wi-Fi...")
                    subprocess.run(['nmcli', 'radio', 'wifi', 'on'])
                else:
                    return "\033[33mCould not determine Wi-Fi status"
            else:
                return "\033[31mError: Unable to check Wi-Fi status"

        except FileNotFoundError:
            return "\033[31mError: nmcli command not found. Make sure NetworkManager is installed."
        except Exception as e:
            return f"\033[31mAn error occurred: {e}"
       
    elif ch == 2:
        print("\nCurrent interface:", iface) 
        print(f"\n\033[36m\033[5mEnabling Monitor mode !!!\033[0m")
        
        # Prompt for sudo password
        password = getpass.getpass(prompt="Enter your password: ")
        
        # Use argument list instead of shell=True for security
        res_kill = subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], capture_output=True, text=True)
        print(res_kill.stdout)
        
        res_mon = subprocess.run(['sudo', 'airmon-ng', 'start', iface], capture_output=True, text=True)
        del password
        print(res_mon.stdout)

        # Display new name for the interface after enabling monitor mode
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[1]
                    break
        print("\n\033[36mAfter airmon-ng, new interface:", iface) 
    else:
        print(f"\033[31m Invalid Choice !!")
        return None
    return iface



# Turn on wireless devices like bluetooth or wifi
def enable_device(choice):
    """
    Enable wireless devices (Bluetooth or WiFi).
    """
    try:
        # Use argument list instead of shell=True for security
        result = subprocess.run(['iw', 'dev'], capture_output=True, text=True)
        iface = None
        for line in result.stdout.split('\n'):
            if 'Interface' in line:
                parts = line.split()
                if len(parts) >= 2:
                    iface = parts[1]
                    break
        
        if not iface:
            iface = ''
        
    except subprocess.CalledProcessError as e:
        print(f"\033[31mCommand failed with error: {e}")
        return None
    except Exception as e:
        print(f"\033[31mError detecting interface: {e}")
        return None
    
    if choice == '1':
        # using rfkill command to turn on bluetooth
        try:
            print(f"\n\033[5m\033[35mEnabling bluetooth...\033[0m")
            res = subprocess.run(['rfkill', 'unblock', 'bluetooth'], capture_output=True, text=True, check=True)
        
        # If success returns empty string
            if res.stdout == '':
                iface = 'bluetooth0'
        
        # Handles error while turning on bluetooth
        
        except subprocess.CalledProcessError as e:
            print(f"\033[31mCommand failed with error: {e}")
            return None
        except FileNotFoundError:
            print("\033[31mError: rfkill not found. Please install rfkill.\033[0m")
            return None
                
    elif choice == '2':
        print("\033[H\033[J")  # Moves the cursor to the top-left and clears the screen
        try:
            ch = int(input(f"\033[36m1. Managed Mode(Default)\n2. Monitor Mode\nChoose: "))
            if ch not in [1, 2]:
                print("\033[31mInvalid choice! Please select 1 or 2.\033[0m")
                return None
        except ValueError:
            print("\033[31mInvalid input! Please enter a number.\033[0m")
            return None
        iface = enable_mon(ch, iface)
        if iface:
            print(f"\n\033[35m Current interface: {iface}")                                
    return iface


if __name__ == "__main__":
    capture_and_open()
