import subprocess 
from pentagon.modules import netscan as nt 
from pentagon.modules import watcher as w
from pentagon.modules import spoof as s
from pentagon.modules import swamp as sw
banner = '''

██████╗ ███████╗███╗   ██╗████████╗ █████╗  ██████╗  ██████╗ ███╗   ██╗
██╔══██╗██╔════╝████╗  ██║╚══██╔══╝██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║
██████╔╝█████╗  ██╔██╗ ██║   ██║   ███████║██║  ███╗██║   ██║██╔██╗ ██║
██╔═══╝ ██╔══╝  ██║╚██╗██║   ██║   ██╔══██║██║   ██║██║   ██║██║╚██╗██║
██║     ███████╗██║ ╚████║   ██║   ██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║
╚═╝     ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝
                                                            


                                         ╔═╗┬ ┬┌┐ ┌─┐┬─┐  ╔╗╔┌─┐┌─┐┌─┐┬  
                                     __  ║  └┬┘├┴┐├┤ ├┬┘  ║║║├┤ ├─┘├─┤│  
                                         ╚═╝ ┴ └─┘└─┘┴└─  ╝╚╝└─┘┴  ┴ ┴┴─┘


'''

def run():
    print(f"\033[1:31m{banner}\033[0m")
    print("\033[1:34m1. Network Scan\n2. Sniffing\n3. ARP Spoofing\n4. Flooding\n5 Exit \033[0m")
    try:
        option = input("\n\033[1:34mYour choice: \033[0m")
        if option == '1':
            print("\033[H\033[J")
            nt.start()
            print("\033[H\033[J")
            run()
        elif option == '2':
            print("\033[H\033[J")
            w.capture_and_open()
            print("\033[H\033[J")
            run()
        elif option == '3':
            print("\033[H\033[J")
            s.initialize()
            print("\033[H\033[J")
            run()
        elif option == '4':
            print("\033[H\033[J")
            sw.collect()
            print("\033[H\033[J")
            run()
        #elif option == '5':
        #    pass
        elif option == '5':
            print("\n\033[38m Exiting the program\033[0m \U0001F972")
            exit(0)
        else:
            print("\nInvalid Input")
    except KeyboardInterrupt:
        print("\n\033[31mForcefull termination !!\033[0m \U0001F622 ")

'''def netscan():
    try:
        print("\033[H\033[J")
        nt.start()
        print("\033[H\033[J")
        start() 
    except Exception as e:
        print(e)
        start()

def iotcap():
    w.capture_and_open()
    start()

def spoof():
    s.initialize()
def ddos():
    return "Invalid option"

def vulscan():
    pass
def default_case():
    pass
'''

if __name__=="__main__":
   run()

