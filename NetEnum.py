# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
#
# This is a Network scanning tool currently built for windows.
# It offers who network Ping Scan, ARP Scan, and DNS Lookup.
# With the results of either Ping or ARP Scan, Port scan and Traceroute are available as secondary scans.
#
# --------------------- VERSION 1.0 ------------------- VERSION 1.0 ------------------- VERSION 1.0 -----------------
#
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

import subprocess
import socket
import ipaddress
import threading
import re


# ------------------------------------------NIC_Scan ~-~Ω<(-.-)>Ω~-~ NIC_Scan----------------------------------------
def NIC_Scanner():

    NIC = subprocess.run(["cmd", "/c", "ipconfig"], capture_output=True, text=True, shell=False)

    NIC_info = {}
    Current_NIC = None
    Subnet_Mask = None

    for line in NIC.stdout.split("\n"):
        line = line.strip()

        if "Ethernet" in line or "Wireless" in line:
            Current_NIC = line
        elif "IPv4 Address" in line and Current_NIC:
            IP_Address = line.split(":")[-1].strip()    
        elif "Subnet Mask" in line:
            Subnet_Mask = line.split(":")[-1].strip()
            NIC_info[Current_NIC] = (IP_Address, Subnet_Mask)
            Current_NIC = None
            Subnet_Mask = None

    return NIC_info

# -----------------------------------Select_Your_NIC ~-~Ω<(-.-)>Ω~-~ Select_Your_NIC---------------------------------
def Choose_NIC(NIC_info):
     if not NIC_info:
          print("No NIC's No Scans - Better Luck Next Time")
          return None
     print("\nEnumerating NICs")
     NIC_List = list(NIC_info.keys())
     for i, NIC in enumerate(NIC_List, start=1):
          IP, Subnet =NIC_info[NIC]
          print(f"{i}. {NIC} - IP:{IP}, Subnet:{Subnet}")

     while True:
          choice = input("\nArm you NIC: ")
          if choice.isdigit():
               choice = int(choice)
               if 1 <= choice <= len(NIC_List):
                    selected_NIC = NIC_List[choice - 1]
                    selected_IP, selected_Subnet = NIC_info[selected_NIC]
                    return selected_NIC, selected_IP, selected_Subnet
          print("Invalid input - Select with numbers only")

NICs = NIC_Scanner()
selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)

if selected_NIC:
    print(f"\n{selected_NIC} - {selected_IP} / {selected_Subnet} = Armed for execution")

# -------------------------------------Scan_for_IP's ~-~Ω<(-.-)>Ω~-~ Scan_for_IP's-----------------------------------
def Initial_Scan_Options():
    print("\nScan for IP's")
    print("1. Ping Scan")
    print("2. Arp Scan")
    print("3. DNS Lookup (Requires Internet)")

    while True:
        choice = input("\nSelect a Scan option: ").strip()
        if choice in ["1", "2", "3"]:
            return choice
        print("❌ Invalid selection. Try again.")

# -----------------------------------------Ping_Scan ~-~Ω<(-.-)>Ω~-~ Ping_Scan---------------------------------------

online_ips = []

def ping(ip):
    """Pings a single IP and prints if it's online."""
    result = subprocess.run(["cmd", "/c", "ping", "-n", "2", ip], capture_output=True, text=True, shell=False)
    if f"Reply from {ip}" in result.stdout:
        online_ips.append(ip)

def subnet_to_cidr(subnet):
    """Convert subnet mask (e.g., 255.255.255.0) to CIDR notation (/24)."""
    return sum(bin(int(octet)).count('1') for octet in subnet.split('.'))

def Ping_Scan(ip, subnet):
    cidr = subnet_to_cidr(subnet)
    Active_network = f"{ip}/{cidr}"
    print(f"\nPinging all IP's on subnet {subnet}... ")

    try:
        network = ipaddress.IPv4Network(Active_network, strict=False)
    except ValueError:
        print("❌ Invalid Subnet Range.")
        return

    threads = []

    for ip in network.hosts():
        ip = str(ip)
        thread = threading.Thread(target=ping, args=(ip,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Sort the online IPs numerically before printing
    global online_ips
    online_ips = sorted(set(online_ips), key=lambda ip: tuple(map(int, ip.split("."))))

    if online_ips:
        print("\nOnline Hosts:")
        for ip in online_ips:
            print(f"✔ {ip}")
    else:
        print("\n❌ No hosts responded to Ping.")
        return False
    return True

# ------------------------------------------Arp_Scan ~-~Ω<(-.-)>Ω~-~ Arp_Scan----------------------------------------

def ARP_Scan():

    global online_ips

    print("\nRunning Arp Scan... ")
    result =subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=False)

    arp_entries = []

    for line in result.stdout.split("\n"):
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line.strip())
        if match:
            ip, mac, arp_type = match.groups()

            first_octet = int(ip.split('.')[0])
            if ip == "255.255.255.255" or (224 <= first_octet <= 239):
                continue

            arp_entries.append((ip, mac, arp_type.upper()))
            online_ips.append(ip)
    
    online_ips = sorted(set(online_ips), key=lambda ip: tuple(map(int, ip.split("."))))

    if arp_entries:
        print("\n✔ ARP Scan Results:\n")
        print(f"{'IP Address':<20}{'MAC Address':<20}{'Type'}")
        print("=" * 50)
        for ip, mac, arp_type in arp_entries:
            print(f"{ip:<20}{mac:<20}{arp_type}")
    else:
        print("❌ No ARP entries found.")

    return bool(arp_entries)

# ----------------------------------------DNS_Lookup ~-~Ω<(-.-)>Ω~-~ DNS_Lookup--------------------------------------

def DNS_Lookup():

    global Init_Scan

    dns_search = input("\nPlease enter a website (Example.com) or IP for DNS Lookup: ").strip()
    if not dns_search:
        print("❌ No DNS Search found. Cannot proceed with DNS Lookup.")
        return []
    
    print(f"\nRunning DNS Lookup on {dns_search}...\n")
    result = subprocess.run(["nslookup", dns_search], capture_output=True, text=True, shell=False)
    if "can't find" in result.stdout.lower() or "non-existent" in result.stdout.lower():
        print("❌ DNS Lookup failed. Check if the domain or IP is valid.")
    else:
        print(result.stdout)

    new_scan = input("\nWould you like to run another DNS lookup? (y/n): ")
    if new_scan == "y":
        DNS_Lookup()
    else:
        quit_program = input("\nwould you like to quit? (y/n): ")
        if quit_program == "y":
            exit()
        else:
            NIC_Scanner()
            Init_Scan = None

# -------------------------------------Scan_for_More ~-~Ω<(-.-)>Ω~-~ Scan_for_More-----------------------------------

def Secondary_Scan_Options():
    print("\n Secondary Scan Types: ")
    print("1. Port Scan ")
    print("2. Traceroute ")

    while True:
        choice =input("\nSelect scan types separated by comma or -A for All scans ").strip()
        if choice == "-A":
            return ["1", "2",]
        selected_scans = [s.strip() for s in choice.split(",") if s.strip() in ["1", "2"]]
        if selected_scans:
            return selected_scans    
        print("❌ Invalid selection. Try again.")

if online_ips:
    selected_scans = Secondary_Scan_Options()

# -----------------------------------------Port_Scan ~-~Ω<(-.-)>Ω~-~ Port_Scan---------------------------------------

def Port_Scanner():
    selected_ips = None
    selected_ports = None
    def grab_banner(target_ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, port))

            #different banner grabbing methods
            if port == 22:  # SSH probe
                sock.send(b"\n")  # Sending a newline often triggers an SSH response
            elif port == 21:  # FTP probe
                sock.send(b"USER anonymous\r\n")
            elif port in [25, 110, 143]:  # SMTP, POP3, IMAP
                sock.send(b"EHLO test\r\n")
            elif port in [80, 443]:  # HTTP/HTTPS
                sock.send(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
            else:  # Generic probe for unknown services
                sock.send(b"\n")

            banner = sock.recv(1024).decode().strip()
            sock.close()
            return banner if banner else "unknown Service"
        except:
            return "Unkown Service"

    def Port_Process(target_ip, port, open_ports):
        # Checking if a port is open and stores if true
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            service = grab_banner(target_ip, port)
            open_ports.append((port, service))

    def Port_Scan(target_ip, ports):
        print(f"\nScanning {target_ip}...")

        open_ports = []
        threads = []

        for port in ports:
            thread = threading.Thread(target=Port_Process, args=(target_ip, port, open_ports))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if open_ports:
            print(f"\n✔ Open Ports on {target_ip}:")
            for port, service in sorted(open_ports):
                print(f" - Port {port}: {service}")
        else:
            print(f"✖ No open ports found on {target_ip}.")

    def get_ports():
        choice = input("\nEnter port numbers separated by comma (80,443) or -A for scan All ports: ")

        if choice == "-A":
            return range(1, 65536) #scans all 65,535 ports
        else:
            try:
                return [int(port) for port in choice.split(",") if port.isdigit()]
            
            except ValueError:
                print("❌ Invalid port selection.")
                return get_ports()


    def select_target_ips(online_ips):
        if not online_ips:
            print("❌ No online devices found. Cannot proceed with port scan.")
            return []
        
        print("\nAvailable IP's: ")
        for index, ip in enumerate(online_ips, start=1):
            print(f"{index}. {ip}")

        while True:
            choice = input("\nSelect one or more IP's separated by a comma or -A for All to scan All IP's for open ports: ").strip()

            if choice == "-A":
                return online_ips
            
            selected_indexes = [c.strip() for c in choice.split(",") if c.strip().isdigit()]
            selected_ips = [online_ips[int(i) - 1] for i in selected_indexes if 1 <= int(i) <= len(online_ips)]

            if selected_ips:
                return selected_ips
            print("❌ Invalid selection. Enter numbers from the list or '-A' for all.")

    # Selecting PI's from Init scan 
    if not online_ips:  
        print("\n❌ No online IPs found. Run a Ping Scan first.")  
    else:
        selected_ips = select_target_ips(online_ips)
    if selected_ips:
        selected_ports = get_ports()
        for ip in selected_ips:
            Port_Scan(ip, selected_ports)

# ----------------------------------------Traceroute ~-~Ω<(-.-)>Ω~-~ Traceroute--------------------------------------

def Traceroute():
    def select_target_ips(online_ips):
        if not online_ips:
            print("❌ No online devices found. Cannot proceed with traceroute.")
            return []
        
        print("\nAvailable IP's: ")
        for index, ip in enumerate(online_ips, start=1):
            print(f"{index}. {ip}")

        while True:
            choice = input("\nSelect one or more IP's separated by a comma or -A for All to scan All IP's for traceroute: ").strip()

            if choice == "-A":
                return online_ips
            
            selected_indexes = [c.strip() for c in choice.split(",") if c.strip().isdigit()]
            selected_ips = [online_ips[int(i) - 1] for i in selected_indexes if 1 <= int(i) <= len(online_ips)]

            if selected_ips:
                return selected_ips
            print("❌ Invalid selection. Enter numbers from the list or '-A' for all.")

    # Ensure online IPs exist before proceeding
    if not online_ips:  
        print("\n❌ No online IPs found. Run a Ping Scan first.")  
        return

    selected_ips = select_target_ips(online_ips)  # Now user must pick IPs before traceroute

    for ip in selected_ips:
        print(f"\nRunning Traceroute on {ip}...\n")
        result = subprocess.run(["tracert", ip], capture_output=True, text=True, shell=False)
        print(result.stdout)

# -----------------------Scan_Option_Selection_Logic ~-~Ω<(-.-)>Ω~-~ Scan_Option_Selection_Logic---------------------

while True: 
    # ✅ Ensure the user can always pick a scan type
    if 'Init_Scan' not in locals() or Init_Scan is None:
        Init_Scan = Initial_Scan_Options()

    # ✅ Handle Ping Scan Selection
    if Init_Scan == "1":  
        Ping_Success = Ping_Scan(selected_IP, selected_Subnet)
        if not Ping_Success:
            retry_arp = input("\n❓ No devices found. ICMP may be blocked. Try an ARP Scan instead? (y/n): ").strip()
            if retry_arp.lower() == "y":
                ARP_Scan()

    # ✅ Handle ARP Scan Selection
    elif Init_Scan == "2":  
        ARP_Scan()

    # ✅ Handle DNS Lookup Selection (Standalone)
    elif Init_Scan == "3":  
        DNS_Lookup()
        Init_Scan = None  # ✅ Reset scan type after DNS lookup to prevent auto-repeating
        continue  # ✅ Go back to the scan selection menu

    # ✅ After initial scans, allow secondary scan options if online IPs exist
    if online_ips:
        selected_scans = Secondary_Scan_Options()  

        if "1" in selected_scans:  # Port Scan Selected
            Port_Scanner()

        if "2" in selected_scans:  # Traceroute Selected
            Traceroute()

    # ✅ After running secondary scans, return to **initial scan menu**
    select_a_different_scan = input("\nWould you like to pick another scan type? (y/n): ").strip().lower()

    if select_a_different_scan == "y":
        Init_Scan = None  # ✅ Reset Initial Scan selection before looping
        continue  # ✅ Restart the loop and go back to Initial Scan Selection
    else:
        quit_program = input("\nDo you wish to quit? (y/n): ").strip().lower()
        if quit_program == "y":
            exit()
        else:
            selected_scans.clear()
            selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)  # Restart NIC selection

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------