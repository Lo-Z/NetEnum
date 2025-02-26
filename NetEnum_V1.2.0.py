# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
#
# This is a Network scanning tool currently built for windows.
# It offers who network Ping Scan, ARP Scan, and DNS Lookup.
# With the results of either Ping or ARP Scan, Port scan and Traceroute are available as secondary scans.
#
# ---------------------- VERSION 1.2 ------------------ VERSION 1.2 ------------------ VERSION 1.2 ------------------
#
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

import subprocess
import socket
import ipaddress
import threading
import re
# import colorama << for Color Scheme have't decided on colors yet >>

# ----------------------------------------Banner ~ - ~ Ω <(-.-)> Ω ~ - ~ Banner--------------------------------------

def Banner():
    banner = """
███╗   ██╗███████╗████████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║   ██║████╗ ████║
██╔██╗ ██║█████╗     ██║   █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
██║ ╚████║███████╗   ██║   ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
-----------------------------------------------------------------
                    Advanced Network Scanner   
-----------------------------------------------------------------
  ~-~-~-~-~- Network -~-~Ω <(-.-)> Ω~-~- Enumeration -~-~-~-~-~
-----------------------  Version 1.2  -------------------------
-----------------------------------------------------------------
"""
    print(banner)
Banner()
# ------------------------------------------NIC_Scan ~-~Ω<(-.-)>Ω~-~ NIC_Scan----------------------------------------

def NIC_Scanner(): # Scans for active Network Interface Cards on computer along with Local DNS servers for hostname resolution

    NIC = subprocess.run(["cmd", "/c", "ipconfig /all"], capture_output=True, text=True, shell=False)

    NIC_info = {}
    Current_NIC = None
    Subnet_Mask = None
    local_dns_servers = []

    for line in NIC.stdout.split("\n"):
        line = line.strip()

        if "Ethernet" in line or "Wireless" in line:
            Current_NIC = line
        elif "IPv4 Address" in line and Current_NIC:
            IP_Address = line.split(":")[-1].strip()
            IP_Address = re.sub(r"\(.*?\)", "", IP_Address).strip()   
        elif "Subnet Mask" in line:
            Subnet_Mask = line.split(":")[-1].strip()
            NIC_info[Current_NIC] = (IP_Address, Subnet_Mask)
            Current_NIC = None
            Subnet_Mask = None
        elif "DNS Servers" in line:
            dns_ip = line.split(":")[-1].strip()
            if dns_ip:
                local_dns_servers.append(dns_ip)
        elif line and local_dns_servers:
            local_dns_servers.append(line.strip())

    return NIC_info, local_dns_servers

# ----------------------------------------DNS_Server ~-~Ω<(-.-)>Ω~-~ DNS_Server--------------------------------------

def reverse_dns_lookup(ip, local_dns_servers): # Looks for the Local DNS Server for host name resolution

    if not local_dns_servers:
        return "Unknown"

    for dns_server in local_dns_servers:
        try:
            result = subprocess.run(
                ["nslookup", ip, dns_server],
                capture_output=True,
                text=True,
                shell=False
            )

            match = re.search(r"Name:\s+(.+)", result.stdout)
            if match:
                return match.group(1).strip()

        except subprocess.SubprocessError:
            continue

    return "Unknown"

# -----------------------------------Select_Your_NIC ~-~Ω<(-.-)>Ω~-~ Select_Your_NIC---------------------------------

def Choose_NIC(NIC_info): # Lists NICs found on Computer
     if not NIC_info:
          print("No NIC's No Scans - Better Luck Next Time")
          return None

     print("=" * 50)
     print("Enumerated NICs")
     print("-" * 50)

     NIC_List = list(NIC_info.keys())
     for i, NIC in enumerate(NIC_List, start=1):
          IP, Subnet =NIC_info[NIC]
          print(f"{i}. {NIC} | IP:{IP} | Subnet:{Subnet}")
     print("=" * 50)

     while True:
          choice = input("\n>> Arm a NIC by selecting a number: ")
          
          if choice.isdigit():
               choice = int(choice)
               if 1 <= choice <= len(NIC_List):
                    selected_NIC = NIC_List[choice - 1]
                    selected_IP, selected_Subnet = NIC_info[selected_NIC]
                    return selected_NIC, selected_IP, selected_Subnet
          print("X Invalid input - Select with numbers only")

NICs, local_dns_servers = NIC_Scanner()
selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)

if selected_NIC: # Displays Selected NIC
    print("\n")
    print("=" * 50)
    print(f"{selected_NIC} | {selected_IP} | {selected_Subnet} = Armed for execution")
    
# -------------------------------------Scan_for_IP's ~-~Ω<(-.-)>Ω~-~ Scan_for_IP's-----------------------------------

def Initial_Scan_Options(): # Initial Scan Options to Enumerate IPs or DNS Lookup
    print("=" * 50)
    print("Enumerate IP's On the Network")
    print("-" * 50)
    print("1. Ping Scan")
    print("2. Arp Scan")
    print("3. DNS Lookup (Requires Internet or Local DNS Server)")
    print("=" * 50)

    while True:
        choice = input("\n>> Select a Scan option: ").strip()
        if choice in ["1", "2", "3"]:
            return choice
        print("X Invalid selection. Try again.")

# -----------------------------------------Ping_Scan ~-~Ω<(-.-)>Ω~-~ Ping_Scan---------------------------------------
online_ips = [] # All collected IPs get added to this list

def ping(ip): # Ping -a will collect IPs and Hostnames 

    result = subprocess.run(["cmd", "/c", f"ping -a -n 3 {ip}"], capture_output=True, text=True, shell=False)

    hostname = "Unknown"

    if f"Reply from {ip}" in result.stdout:
        match = re.search(r'Pinging\s+([^\[\]]+)\s+\[.*\]', result.stdout)

        if match:
            extracted_hostname = match.group(1).strip()
            if extracted_hostname and extracted_hostname != ip:  # Avoid redundant hostname = IP case
                hostname = extracted_hostname

        if hostname == "Unknown":
            hostname = reverse_dns_lookup(ip, local_dns_servers)

        if hostname == "Unknown":
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = "Unknown"

        online_ips.append((ip, hostname))

def subnet_to_cidr(subnet): # Converts a Subnet Mask to Cider Notation
    try:
        cidr_value = sum(bin(int(octet)).count('1') for octet in subnet.split('.'))
        return cidr_value
    except Exception as e:
        return None

def Ping_Scan(ip, subnet): # Uses CIDR and Ping operations and sorts the multithreaded output in numerical order
    cidr = subnet_to_cidr(subnet)
    if cidr is None:
        print("ERROR: Failed to Convert to Cider Notation")
        return


    Active_network = f"{ip}/{cidr}"
    print("\n")
    print(f"\nPinging all IP's on subnet {subnet}... ")
    
    try:
        network = ipaddress.IPv4Network(Active_network, strict=False)
    except ValueError as e:
        print(f"X Invalid Subnet Range. ERROR {e}")
        return

    threads = []

    for host in network.hosts():
        thread = threading.Thread(target=ping, args=(str(host),))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Sort the online IPs numerically before printing
    global online_ips
    online_ips = list({(ip, hostname) for ip, hostname in online_ips})
    online_ips.sort(key=lambda x: tuple(map(int, x[0].split("."))))

    if online_ips:
        print("\n\n")
        print("=" * 50)
        print("Online Hosts:")
        print("-" * 50)
        print(f"{'IP Address':<20}{'Host Name':<30}")
        print("=" * 50)
        for ip, hostname in online_ips:
            print(f"{ip:<20}{hostname:<30}")
        print("=" * 50)

    if not online_ips:
        print("\nX No hosts responded to Ping.")
        return False
    return True

# ------------------------------------------Arp_Scan ~-~Ω<(-.-)>Ω~-~ Arp_Scan----------------------------------------

def ARP_Scan(): # Runs ARP -a and organizes the data numerically. Stores findings in online_ips

    global online_ips
    
    print("\n")
    print("\nRunning Arp Scan... ")
    result =subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=False)

    arp_entries = []
    arp_ips = []

    for line in result.stdout.split("\n"):
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line.strip())
        if match:
            ip, mac, arp_type = match.groups()

            first_octet = int(ip.split('.')[0])
            if ip == "255.255.255.255" or (224 <= first_octet <= 239):
                continue

            arp_entries.append((ip, mac, arp_type.upper()))
            arp_ips.append((ip, "Unknown"))

                # Add only unique IPs from ARP scan
        unique_arp_ips = {ip for ip, _ in online_ips}  # Extract existing IPs
        for ip_tuple in arp_ips:
            if ip_tuple[0] not in unique_arp_ips:
                online_ips.append(ip_tuple)

        
        online_ips = list({(ip, hostname) for ip, hostname in online_ips})
        online_ips.sort(key=lambda x: tuple(map(int, x[0].split(".")))) 
        

    if arp_entries:
        print("\n\n")
        print("=" * 50)
        print("ARP Scan Results:")
        print("-" * 50)
        print(f"{'IP Address':<20}{'MAC Address':<20}{'Type'}")
        print("=" * 50)
        for ip, mac, arp_type in arp_entries:
            print(f"{ip:<20}{mac:<20}{arp_type}")
        print("=" * 50)

    else:
        print("X No ARP entries found.")

    return bool(arp_entries)

# ----------------------------------------DNS_Lookup ~-~Ω<(-.-)>Ω~-~ DNS_Lookup--------------------------------------

def DNS_Lookup(): # General DNS lookup, Internet needed for domain searches unless host names are registered in a local DNS server.

    global Init_Scan

    print("\n\n")
    print("=" * 50)
    print("DNS Lookup")
    print("=" * 50)
    print("\n")
    dns_search = input(">> Please enter a website (Example.com) or IP for DNS Lookup: ").strip()
    if not dns_search:
        print("X No DNS Search found. Cannot proceed with DNS Lookup.")
        return []
    
    print("\n")
    print("=" * 50)
    print(f"Running DNS Lookup on {dns_search}...")
    print("-" * 50)
    result = subprocess.run(["nslookup", dns_search], capture_output=True, text=True, shell=False)
    if "can't find" in result.stdout.lower() or "non-existent" in result.stdout.lower():
        print("X DNS Lookup failed. Check if the domain or IP is valid.")
    else:
        print(result.stdout)
        print("=" * 50)

    new_scan = input("\n>> Would you like to run another DNS lookup? (y/n): ").strip().lower()
    if new_scan == "y":
        DNS_Lookup()
    else:
        print("=" * 50)
        quit_program = input("\n>> would you like to quit? (y/n): ").strip().lower()
        print("=" * 50)
        if quit_program == "y":
            exit()
        else:
            print("\n\n\n")
            NIC_Scanner()
            Init_Scan = None

# -------------------------------------Scan_for_More ~-~Ω<(-.-)>Ω~-~ Scan_for_More-----------------------------------

def Secondary_Scan_Options(): # Secondary Scan options for Port Scan and Traceroute
    print("\n\n")
    print("=" * 50)
    print("Secondary Scan Types: ")
    print("-" * 50)
    print("1. Port Scan ")
    print("2. Traceroute ")
    print("=" * 50)

    while True:
        choice =input("\n>> Select scan types separated by comma or -A for All scans: ").strip()
        if choice == "-A":
            return ["3"]
        selected_scans = [s.strip() for s in choice.split(",") if s.strip() in ["1", "2"]]
        if selected_scans:
            return selected_scans    
        print("X Invalid selection. Try again.")

if online_ips:
    selected_scans = Secondary_Scan_Options()

# --------------------------------------Port_Scanner ~-~Ω<(-.-)>Ω~-~ Port_Scanner------------------------------------

def Port_Scanner(selected_ips, selected_ports): # Checks for selected IPs and Ports from Scan Option Selection Logic

    if not selected_ips:
        print("X No IPs selected for Port Scan.")
        return
    
    for ip in selected_ips:  
        Port_Scan(ip, selected_ports)

# ---------------------------------------Port_Banner ~-~Ω<(-.-)>Ω~-~ Port_Banner-------------------------------------

def grab_banner(target_ip, port): # Attemps to find port protocols with probes, if no connection or service response, common port announced along unknown service.
    
    known_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        587: "SMTP (SSL)",
        993: "IMAP (SSL)",
        995: "POP3 (SSL)",
        3306: "MySQL",
        3389: "RDP",
        5900: "VNC",
        8080: "HTTP Proxy",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip, port))

        # Send minimal probes based on port type
        probe_data = b"\n"  # Default probe
        if port in [21]:  # FTP
            probe_data = b"USER anonymous\r\n"
        elif port in [22, 23]:  # SSH, Telnet
            probe_data = b"\n"
        elif port in [25, 110, 143]:  # SMTP, POP3, IMAP
            probe_data = b"EHLO test\r\n"
        elif port in [80, 443, 8080]:  # HTTP/HTTPS
            probe_data = b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n"

        sock.send(probe_data)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        # If we get a meaningful banner, return it directly
        if banner:
            return f"{banner}"
        print("=" * 50)
        # If no banner, fall back to known services **without assuming correctness**
        return f"Unknown Service (Common: {known_services.get(port, 'N/A')})"

    except:
        return f"Unknown Service (Common: {known_services.get(port, 'N/A')})"

# --------------------------------------Port_Process ~-~Ω<(-.-)>Ω~-~ Port_Process------------------------------------

def Port_Process(target_ip, port, open_ports): # TCP socket connection 
# Checking if a port is open and stores if true
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target_ip, port))
    sock.close()

    if result == 0:
        service = grab_banner(target_ip, port)
        open_ports.append((port, service))

# -----------------------------------------Port_Scan ~-~Ω<(-.-)>Ω~-~ Port_Scan---------------------------------------

def Port_Scan(target_ip, ports): # Runs Multithreaded port scan using selection data
    print("\n")
    print("=" * 50)
    print(f"Scanning {target_ip}...")

    open_ports = []
    threads = []

    for port in ports:
        thread = threading.Thread(target=Port_Process, args=(target_ip, port, open_ports))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if open_ports:
        print("-" * 50)
        print(f"✔ Open Ports on {target_ip}:")
        for port, service in sorted(open_ports):
            print(f" - Port {port}: {service}")
        print("=" * 50)
    else:
        print("-" * 50)
        print(f"X No open ports found on {target_ip}.")
        print("=" * 50)
# ----------------------------------------Traceroute ~-~Ω<(-.-)>Ω~-~ Traceroute--------------------------------------

def Traceroute(selected_ips): # Baisc Traceroute Scan
    
    if not selected_ips:  
        print("\nX No online IPs found. Run a Ping Scan first.")  
        return

    for ip in selected_ips:
        print("\n\n")
        print("=" * 50)
        print(f"Running Traceroute on {ip}...")
        print("-" * 50)
        result = subprocess.run(["tracert", ip], capture_output=True, text=True, shell=False)
        print(result.stdout)
        print("=" * 50)

# --------------------------------------Target_Ports ~-~Ω<(-.-)>Ω~-~ Target_Ports------------------------------------

def get_ports(): # User selects port numbers or all ports 1 - 65,535.
        choice = input("\n>> Enter port numbers separated by comma (80,443) or -A for scan All ports: ")
        print("\n")

        if choice == "-A":
            return range(1, 65536)
        else:
            try:
                return [int(port) for port in choice.split(",") if port.isdigit()]
            
            except ValueError:
                print("X Invalid port selection.")
                return get_ports()

# -----------------------------------------Target_IP ~-~Ω<(-.-)>Ω~-~ Target_IP---------------------------------------

def select_target_ips(online_ips): # User input to select IPs found in Ping or Arp scan
    if not online_ips:
        print("X No online devices found. Cannot proceed with scan.")
        return []
    
    online_ips = list({(ip, hostname) for ip, hostname in online_ips})
    online_ips.sort(key=lambda x: tuple(map(int, x[0].split(".")))) 

    print("\n")
    print("=" * 50)
    print("Available IPs:")
    print("-" * 50)
    print(f"{'Index':<8}{'IP Address':<20}{'Host Name'}")
    print("=" * 50)

    for index, (ip, hostname) in enumerate(online_ips, start=1):
        print(f"{index:<8}{ip:<20}{hostname}")
    print("=" * 50)

    while True:
        choice = input("\n>> Select one or more IPs separated by a comma or -A for All: ").strip()
       
        if choice == "-A":
            return [ip for ip, _ in online_ips]

        selected_indexes = [c.strip() for c in choice.split(",") if c.strip().isdigit()]
        selected_ips = [online_ips[int(i) - 1][0] for i in selected_indexes if i.isdigit() and 1 <= int(i) <= len(online_ips)]
        
        if selected_ips:
            return selected_ips 
        print("X Invalid selection. Enter numbers from the list or '-A' for all.")

# -----------------------Scan_Option_Selection_Logic ~-~Ω<(-.-)>Ω~-~ Scan_Option_Selection_Logic---------------------

while True: # Initial and secondary Scan Selection logic 
    
    if 'Init_Scan' not in locals() or Init_Scan is None:
        Init_Scan = Initial_Scan_Options()

    #  Handle Ping Scan Selection
    if Init_Scan == "1":  
        Ping_Success = Ping_Scan(selected_IP, selected_Subnet)
        if not Ping_Success:
            retry_arp = input("\n?!? >> No devices found. ICMP may be blocked. Try an ARP Scan instead? (y/n): ").strip().lower()
            if retry_arp == "y":
                ARP_Scan()

    #  Handle ARP Scan Selection
    elif Init_Scan == "2":  
        ARP_Scan()

    #  Handle DNS Lookup Selection (Standalone)
    elif Init_Scan == "3":  
        DNS_Lookup()
        Init_Scan = None
        continue

    selected_scans = []

    #  After initial scans, allow secondary scan options if online IPs exist
    if online_ips:
        proceed_to_secondary = input("\n\n>> Would you like to run a secondary scan (Port Scan / Traceroute)? (y/n): ").strip().lower()
        if proceed_to_secondary == "y":
            selected_scans = Secondary_Scan_Options()
        else:
            quit_program = input("\n>> Do you wish to quit? (y/n): ").strip().lower()
            if quit_program == "y":
                exit()
            else:
                selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)  # Restart NIC selection
                
        selected_ips = None  #  Initializes selected_ips as None

        if "1" in selected_scans:  # If only Port Scan is selected
            selected_ips = select_target_ips(online_ips)
            selected_ports = get_ports()
            Port_Scanner(selected_ips, selected_ports)

        elif "2" in selected_scans:  # If only Traceroute is selected
            selected_ips = select_target_ips(online_ips)
            Traceroute(selected_ips)

        elif "3" in selected_scans: # If the user selects -A (both scans)
            selected_ips = select_target_ips(online_ips)
            selected_ports = get_ports()
            Port_Scanner(selected_ips, selected_ports)
            Traceroute(selected_ips)

    #  After running secondary scans, return to **initial scan menu**
    select_a_different_scan = input("\n\n>> Would you like to pick another scan type? (y/n): ").strip().lower()
    print("\n\n")

    if select_a_different_scan == "y":
        Init_Scan = None  #  Reset Initial Scan selection before looping
        continue
    else:
        quit_program = input("\n>> Do you wish to quit? (y/n): ").strip().lower()
        if quit_program == "y":
            exit()
        else:
            selected_scans.clear()
            selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)  # Restart NIC selection

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------