import subprocess
import time
import pyshark
from scapy.all import sniff
from scapy.utils import wrpcap
from scapy.utils import PcapWriter
import getpass
import shlex
from pathlib import Path

# list to store captured packets
packet_list = []

# Define the packet capture callback function

def packet_callback(packet):
    # Append the captured packet to the list
    packet_list.append(packet)


# Captures the packet on specific interface, saves in a file and opens it in wireshark

def capture_and_open():
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
    interface = enable_device(choice)
    
    # defining file name and path
    file_ext = ".pcap"
    current_directory = subprocess.getoutput('pwd')
    output_dir = current_directory + "/captures"

    dir_path = Path(f'{output_dir}')
    # Check if the directory exists

    if dir_path.is_dir():
        pass
    else:
        cm = "mkdir -p captures && pwd "
        d = subprocess.run(f"{cm}", shell=True, capture_output=True, text=True)
        dir_path = d.stdout()
    
    if ch == 'Y' or ch =='y':
        fname = input("\n  Enter filename:")
        file = f"{dir_path}/{fname}{file_ext}"
    elif ch =='N' or ch == 'n':
        pass
    else:
        print("\n  \033[31mInvalid Choice !!\033[0m")
    capture_duration = int(input("\n\033[36m[*] How long do you want to capture?(in seconds):"))
    
    # Starting Live capture on specified interface
    
    print(f"\n\033[36mStarting Live Packet Capture on {interface} interface for {capture_duration} seconds...\n ")  
    if interface =='bluetooth0':
        pyshark.LiveCapture(interface=interface, output_file=file).sniff(timeout=capture_duration)
    else:
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
    exit_stat = subprocess.run([wireshark_path, file])
    ret_code = exit_stat.returncode
    #print(ret_code)
    time.sleep(1)
    if ret_code == 0 and interface:
        man_mode = subprocess.run(f"sudo airmon-ng stop {interface} && sudo systemctl restart NetworkManager", shell=True, capture_output=True, text=True)
        print(man_mode.stdout)
        return 0
    else:
        print("\n\033[31m\033[5mError while closing wireshark !!![0m")
    

def enable_mon(ch, iface):
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
        print("\nCurrent interface:",iface) 
        print(f"\n\033[36m\033[5mEnabling Monitor mode !!!\033[0m")
        # Prompt for sudo password
        password = getpass.getpass(prompt="Enter your password: ")
        kill_cmd = "sudo airmon-ng check kill" 
        res_kill = subprocess.run(kill_cmd, env={"PASSWORD": password}, shell=True, text=True, capture_output=True)
        print(res_kill.stdout)
        mon_cmd = f"sudo airmon-ng start {iface}"
        res_mon = subprocess.run(mon_cmd, env={"PASSWORD": password}, shell=True, text=True)
        del password
        print(res_mon.stdout)

        res = subprocess.run('iw dev | grep Interface | cut -f 2 -d " "', shell=True, capture_output=True, text=True)
        iface = res.stdout.strip('\n')
        print("\n\033[36mAfter airmon-ng, new interface: ",iface) 
    else:
        print(f"\033[31m Invalid Choice !!")
        exit(1)
    return iface



# Turn on wireless devices like bluetooth
def enable_device(choice):
    try:
        result = subprocess.run('iw dev | grep Interface | cut -f 2 -d " "', shell=True, capture_output=True, text=True)
        iface = result.stdout.strip('\n')
        
        # Handles error when finding grepping interface name
        
    except subprocess.CalledProcessError as e:
        print(f"\033[31mCommand failed with error: {e}")
        exit(1)
    
    if choice == '1':
        # using rfkill command to turn on bluetooth
        try:
            print(f"\n\033[5m\033[35mEnabling bluetooth...\033[0m")
            res = subprocess.run(['rfkill', 'unblock', 'bluetooth'], capture_output=True, text=True, check=True)
        
        # If success returns empty string
            if(res.stdout) == '':
                iface = 'bluetooth0'
        
        # Handles error while turning on bluetooth
        
        except subprocess.CalledProcessError as e:
            print(f"\033[31mCommand failed with error: {e}")
            exit(1)
                
    elif choice == '2':
        print("\033[H\033[J")  # Moves the cursor to the top-left and clears the screen
        ch = int(input(f"\033[36m1. Managed Mode(Default)\n2. Monitor Mode\nChoose: "))
        iface = enable_mon(ch, iface)
        print(f"\n\033[35m Current interface: {iface}")                                
    return iface


if __name__ == "__main__":
    capture_and_open()
