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
    """Main entry point for Pentagon IoT Security Framework."""
    print(f"\033[1;31m{banner}\033[0m")
    print("\033[1;34m1. Network Scan")
    print("2. Sniffing")
    print("3. ARP Spoofing")
    print("4. Flooding")
    print("5. Web Dashboard")
    print("6. Exit \033[0m")
    try:
        option = input("\n\033[1;34mYour choice: \033[0m")
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
        elif option == '5':
            print("\033[H\033[J")
            start_dashboard_menu()
            print("\033[H\033[J")
            run()
        elif option == '6':
            print("\n\033[38mExiting the program\033[0m \U0001F972")
            exit(0)
        else:
            print("\n\033[31mInvalid Input\033[0m")
            run()
    except KeyboardInterrupt:
        print("\n\033[31mForceful termination !!\033[0m \U0001F622 ")


def start_dashboard_menu():
    """Show dashboard launch options."""
    print("\n\033[34m=== Pentagon Web Dashboard ===\033[0m")
    print("\n1. Start Dashboard (Local Only)")
    print("2. Start Dashboard (Remote Access)")
    print("3. Back to Main Menu")
    
    choice = input("\n\033[34mYour choice: \033[0m")
    
    if choice == '1':
        try:
            from pentagon.dashboard.app import run_dashboard
            print("\n\033[32mStarting dashboard at http://127.0.0.1:5000\033[0m")
            print("\033[33mDefault credentials: admin / pentagon_secure_2024\033[0m")
            print("\033[33mPress Ctrl+C to stop the server.\033[0m\n")
            run_dashboard(host='127.0.0.1', port=5000)
        except ImportError:
            print("\033[31mError: Flask not installed. Run: pip install Flask\033[0m")
        except Exception as e:
            print(f"\033[31mError starting dashboard: {e}\033[0m")
    
    elif choice == '2':
        try:
            from pentagon.dashboard.app import run_dashboard
            port = input("\n\033[34mEnter port number (default 5000): \033[0m") or "5000"
            if not port.isdigit() or int(port) < 1 or int(port) > 65535:
                print("\033[31mInvalid port number.\033[0m")
                return
            print(f"\n\033[32mStarting dashboard at http://0.0.0.0:{port}\033[0m")
            print("\033[33mWarning: Accessible from network. Ensure firewall is configured.\033[0m")
            print("\033[33mDefault credentials: admin / pentagon_secure_2024\033[0m")
            print("\033[33mPress Ctrl+C to stop the server.\033[0m\n")
            run_dashboard(host='0.0.0.0', port=int(port))
        except ImportError:
            print("\033[31mError: Flask not installed. Run: pip install Flask\033[0m")
        except Exception as e:
            print(f"\033[31mError starting dashboard: {e}\033[0m")
    
    elif choice == '3':
        return
    else:
        print("\033[31mInvalid choice.\033[0m")


if __name__ == "__main__":
    run()

