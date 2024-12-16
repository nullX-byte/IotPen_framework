import nmap
import sys
import subprocess
from pathlib import Path

res = subprocess.run('hostname -I', capture_output=True, shell=True, text=True)
ipaddr =res.stdout.split()[0]
nm = nmap.PortScanner()

def port_scans(target_ip, ch):
    if ch == 'Y' or ch == 'y':
        nmap_args=f' -n -p- --exclude {ipaddr} -oN {fpath}'
    else:
        nmap_args=f'-n  -p- --exclude {ipaddr}'
        
    print(f"Running Nmap port scans...")

     
    try:
        nm.scan(hosts=target_ip, arguments=nmap_args)
        if nm.all_hosts():
            print(f"Scan results for {target_ip}:\n")

            for host in nm.all_hosts():
                print(f"Host: {host} ({nm[host].hostname()})")
                print(f"State: {nm[host].state()}")

                for protocol in nm[host].all_protocols():
                    print(f"\nProtocol: {protocol}")
                    ports = nm[host][protocol].keys()

                    for port in ports:
                        print(f"Port: {port}\tState: {nm[host][protocol][port]['state']}")
                print("-" *51)
        else:
            print(f"No hosts found for {target_ip}.")
    except Exception as e:
        print(f"An error occurred: {e}")


def discover_hosts(target_ip, ch):
    # Perform a Ping Scan (ICMP Echo Request) on the network
    # The '-sn' flag means "Ping Scan" which is for host discovery (no port scan)
    if ch == 'Y' or ch == 'y':
        nmap_args=f'-sn -n --exclude {ipaddr} -oN {fpath} '
        print(fpath)
    else:
        nmap_args=f' -sn -n --exclude {ipaddr}'
    nm.scan(hosts=target_ip, arguments = nmap_args)
    print("\n Scanning network for available hosts...")
     
    # Retrieve and display the results
    print(f"Scan results for {target_ip}:\n")

    # Loop through all hosts discovered
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            print(f"Host {host} is up")


def serv_scan(target_ip, ch):
    if ch == 'Y' or ch == 'y':
        nmap_args=f'-A -n -T4 --exclude {ipaddr} -oN {fpath} '
    else:
        nmap_args=f' -A -n -T4 --exclude {ipaddr} '
    print(f"\nRunning OS version and Service Detection Scans...")
    print("Scanning options: \n1. Detailed/Verbose Scan \n2. Quiet Scan")
    vb=input("Choose : ")
    print('value of vb:',vb)      
    # ch = input("\033[34mDo you want the save the scan results?(Y/N): ") 
    if vb == '1':
        # Concatenating -vv option on third index 
        nmap_args = nmap_args[:3] + ' -vv ' + nmap_args[3]
        print(nmap_args)
        result = subprocess.run(f"nmap {nmap_args} {target_ip}", shell=True, capture_output=True, text=True)
        print("\nScan Complete!!!")
        print(result.stdout)
    
    elif vb == '2':
        result = subprocess.run(f"nmap {nmap_args} {target_ip}", shell=True, capture_output=True, text=True)
        print(f"\nNmap Scan Complete.")
        print(result.stdout)
    else:
        print("\n033[34mInvalid Input!!")

  
def vuln_scan(target_ip, ch):
    if ch == 'Y' or ch == 'y':
        nmap_args=f'--script=vuln -n -vv --exclude {ipaddr} -oN {fpath}'
    else:
        nmap_args=' -sV -vv -n --script=vuln --exclude {ipaddr}'
    print(f"\nRunning Vulnerability Scan")
    result = subprocess.run(f"nmap {nmap_args} {target_ip} ", shell=True, capture_output=True, text=True)
    print(f"\nNmap Scan Complete.")
    print(result.stdout)
    

def show_menu():
    print("\033[34m1. Host Discovery")
    print("2. Port Scan")
    print("3. OS and Service Scan")
    print("4. Vulnerability Scan")
    print("5. Exit\033[0m")





def start():
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
    target_ip = input("\n  \033[34mEnter target host or IP Address or Network Subnet:(example.com/x.x.x.x): ")

    current_directory = subprocess.getoutput('pwd')
    output_dir = current_directory + "/scan_result"

    dir_path = Path(f'{output_dir}')
    # Check if the directory exists

    ch = input("\n  \033[34mDo you want the save the scan results?(Y/N): ")
    if dir_path.is_dir():
        pass
    else:
        cm = "mkdir -p scan_result && pwd "
        d = subprocess.run(f"{cm}", shell=True, capture_output=True, text=True)
        dir_path = d.stdout()
    
    if ch == 'Y' or ch =='y':
        fname = input("\n  Enter filename:")
        fpath = f"{dir_path}/{fname}"
    elif ch =='N' or ch == 'n':
        pass
    else:
        print("\n  \033[31mInvalid Choice !!\033[0m")

    
    while True:
        show_menu()
        try:
            choice = int(input("\nEnter your choice: "))  # Accept input from the user
            if choice == 1:
                discover_hosts(target_ip, ch)
            elif choice == 2:
                port_scans(target_ip, ch)  # Execute the action for option 2
            elif choice == 3:
                serv_scan(target_ip, ch)  # Execute the action for option 3
            elif choice == 4:
                vuln_scan(target_ip, ch)
            elif choice == 5:
                print("Exiting the program.")
                break
                # Exit the loop and terminate the program
            else:
                print("Invalid choice! Please select a valid option (1-4).")
        except ValueError as e:
            print(f"\nError:{e}")
    return 0





if __name__ == "___main__":
    start()
