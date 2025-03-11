# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
#
# This is a Network scanning tool currently built for windows.
# It offers IP Enumeration, Port Scanning, Traceroute, and DNS Lookup.
# You can save the results or your scans in a text file and nothing is cached, always fresh.
#
# -------------------- VERSION 1.3.1 ---------------- VERSION 1.3.1 ---------------- VERSION 1.3.1 ------------------
#
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

import os
import subprocess
import socket
import ipaddress
import threading
import re
import time
import sys
import datetime
import tkinter as tk
from tkinter import filedialog
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
-----------------------  Version 1.3.1  -------------------------
-----------------------------------------------------------------
"""
    print(banner)
Banner()
# ------------------------------------------NIC_Scan ~-~Ω<(-.-)>Ω~-~ NIC_Scan----------------------------------------

def NIC_Scanner(): # Scans for active Network Interface Cards on computer along with Local DNS servers for hostname resolution

    NIC = subprocess.run(["cmd", "/c", "ipconfig /all"], capture_output=True, text=True, shell=False)

    NIC_info = {}
    local_dns_servers = []

    Current_NIC = None
    Subnet_Mask = None

    for line in NIC.stdout.split("\n"):
        line = line.strip()
        
        if "Ethernet adapter Ethernet" in line or "Wireless LAN adapter" in line:
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
            result = subprocess.run(["nslookup", ip, dns_server], capture_output=True, text=True, shell=False)
            match = re.search(r"Name:\s+(.+)", result.stdout)
            
            if match:
                return match.group(1).strip()

        except subprocess.SubprocessError:
            continue

    return "Unknown"

# -----------------------------------Select_Your_NIC ~-~Ω<(-.-)>Ω~-~ Select_Your_NIC---------------------------------

def Choose_NIC(NIC_info): # Lists NICs found on Computer
     global online_ips
     online_ips = []

     if not NIC_info:
          print("No NIC's No Scans - Better Luck Next Time")
          return None

     print("=" * 70)
     print("Enumerated NICs")
     print("-" * 70)

     NIC_List = list(NIC_info.keys())
     for i, NIC in enumerate(NIC_List, start=1):
          IP, Subnet =NIC_info[NIC]
          print(f"{i}. {NIC} | IP:{IP} | Subnet:{Subnet}")
     print("=" * 70)

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
    print("=" * 70)
    print(f"{selected_NIC} | {selected_IP} | {selected_Subnet} = Armed for execution")
    
# -------------------------------------Scan_for_IP's ~-~Ω<(-.-)>Ω~-~ Scan_for_IP's-----------------------------------

def Initial_Scan_Options(): # Initial Scan Options to Enumerate IPs or DNS Lookup
    print("=" * 70)
    print("Enumerate IP's On the Network")
    print("-" * 70)
    print("1. Scan for Active IP's on the Network")
    print("2. DNS Lookup (Requires Internet or Local DNS Server)")
    print("=" * 70)

    while True:
        choice = input("\n>> Select a Scan option: ").strip()
        if choice in ["1", "2"]:
            return choice
        print("X Invalid selection. Try again.")

# -----------------------------------------Ping_Scan ~-~Ω<(-.-)>Ω~-~ Ping_Scan---------------------------------------
online_ips = [] # All collected IPs get added to this list
scanning_done = False

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
    global online_ips, scanning_done
    scanning_done = False

    def Progress_indicator():
        #spinner = ['|', '/', '-', '\\']
        spinner = ['<(^O^)>  .<(^-^)>', '<(^o^)> . <(^o^)>', '<(^-^)>.  <(^O^)>', '<(^o^)> . <(^o^)>']
        idx = 0
        while not scanning_done:
            sys.stdout.write(f"\rScanning in progress... please wait {spinner[idx % len(spinner)]}")
            sys.stdout.flush()
            idx += 1
            time.sleep(0.15)
        # Clear the line after done:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()

    cidr = subnet_to_cidr(subnet)
    if cidr is None:
        scanning_done = True
        progress_thread.join()
        return

    Active_network = f"{ip}/{cidr}"
    print("\n")
    print(f"\nUsing {ip} to build a list of all active IP's on subnet {subnet} ")
    progress_thread = threading.Thread(target=Progress_indicator)
    progress_thread.start()
    
    try:
        network = ipaddress.IPv4Network(Active_network, strict=False)
    except ValueError as e:
        print(f"X Invalid Subnet Range. ERROR {e}")
        scanning_done = True
        progress_thread.join()
        return

    threads = []
    for host in network.hosts():
        thread = threading.Thread(target=ping, args=(str(host),))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Ensure every online_ips tuple has three elements by adding a default MAC value
    online_ips = [(entry[0], entry[1], "Unknown") if len(entry) == 2 else entry for entry in online_ips]
    
    # Deduplicate while preserving MAC info
    deduped = {}
    for ip, hostname, mac in online_ips:
        deduped[ip] = (ip, hostname, mac)
    online_ips = list(deduped.values())

    # Sort the online IPs numerically before printing
    online_ips.sort(key=lambda x: tuple(map(int, x[0].split("."))))

    scanning_done = True
    progress_thread.join()

# ------------------------------------------Arp_Scan ~-~Ω<(-.-)>Ω~-~ Arp_Scan----------------------------------------

def ARP_Scan(selected_IP, selected_Subnet): # Runs ARP -a and organizes the data numerically. Stores findings in online_ips

    global online_ips
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=False)

    arp_entries = []
    try:
        cidr = sum(bin(int(octet)).count('1') for octet in selected_Subnet.split('.'))
        network = ipaddress.IPv4Network(f"{selected_IP}/{cidr}", strict=False)
    except ValueError:
        print("ERROR: Invalid Subnet Mask or IP Address")
        return

    for line in result.stdout.split("\n"):
        match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line.strip())
        if match:
            ip, mac, arp_type = match.groups()
            if ip.endswith(".255") or mac.lower() in ["ff:ff:ff:ff:ff:ff", "ff-ff-ff-ff-ff-ff"]:
                continue
            first_octet = int(ip.split('.')[0])
            if ip == "255.255.255.255" or (224 <= first_octet <= 239):
                continue
            if ipaddress.IPv4Address(ip) in network:
                arp_entries.append((ip, mac, arp_type.upper()))

    # Build a dictionary mapping IP addresses to MAC addresses from ARP results.
    arp_dict = {ip: mac for ip, mac, _ in arp_entries}

    # update to (ip, hostname, mac) if found in arp_dict; otherwise, leave as is.
    updated_online_ips = []
    seen_ips = set()
    for entry in online_ips:
        ip, hostname = entry[0], entry[1]
        if ip == selected_IP:
            mac = "Localhost"
        else:
            mac = arp_dict.get(ip, "Unknown")
        updated_online_ips.append((ip, hostname, mac))
        seen_ips.add(ip)
    # Also update ARP-only entries:
    for ip, mac, _ in arp_entries:
        if ip not in seen_ips:
            if ip == selected_IP:
                updated_online_ips.append((ip, "Localhost", "Localhost"))
            else:
                updated_online_ips.append((ip, "Unknown", mac))
            seen_ips.add(ip)

    online_ips = updated_online_ips

# ----------------------------------------Ping & Arp ~-~Ω<(-.-)>Ω~-~ Ping & Arp--------------------------------------

def Combined_Scan(selected_IP, selected_Subnet):
    # Run Ping Scan first (this collects (ip, hostname) tuples in online_ips)
    Ping_Scan(selected_IP, selected_Subnet)
    
    # Run ARP Scan to update online_ips with MAC addresses.
    ARP_Scan(selected_IP, selected_Subnet)

    time.sleep(1)

    online_ips.sort(key=lambda x: tuple(map(int, x[0].split("."))))

    # Now print the combined results, which should have real MAC addresses
    if online_ips:
        print("\n\nFinal Online Hosts:")
        print("=" * 70)
        print(f"{'IP Address':<20}{'Host Name':<25}{'MAC Address':<20}")
        print("=" * 70)
        for ip, hostname, mac in online_ips:
            print(f"{ip:<20}{hostname:<25}{mac:<20}")
        print("=" * 70)
    else:
        print("\nX No hosts found.")

# ----------------------------------------DNS_Lookup ~-~Ω<(-.-)>Ω~-~ DNS_Lookup--------------------------------------

def DNS_Lookup(): # General DNS lookup, Internet needed for domain searches unless host names are registered in a local DNS server.

    global Init_Scan

    print("\n\n")
    print("=" * 70)
    print("DNS Lookup")
    print("=" * 70)
    print("\n")
    dns_search = input(">> Please enter a website (Example.com) or IP for DNS Lookup: ").strip()
    if not dns_search:
        print("X No DNS Search found. Cannot proceed with DNS Lookup.")
        return []
    
    print("\n")
    print("=" * 70)
    print(f"Running DNS Lookup on {dns_search}...")
    print("-" * 70)
    result = subprocess.run(["nslookup", dns_search], capture_output=True, text=True, shell=False)
    if "can't find" in result.stdout.lower() or "non-existent" in result.stdout.lower():
        print("X DNS Lookup failed. Check if the domain or IP is valid.")
    else:
        print(result.stdout)
        print("=" * 70)

    new_scan = input("\n>> Would you like to run another DNS lookup? (y/n): ").strip().lower()
    if new_scan == "y":
        DNS_Lookup()
    else:
        print("=" * 70)
        quit_program = input("\n>> would you like to quit? (y/n): ").strip().lower()
        print("=" * 70)
        if quit_program == "y":
            save_findings()
        else:
            print("\n\n\n")
            NICs, local_dns_servers = NIC_Scanner()
            selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)
            Init_Scan = None

# -------------------------------------Scan_for_More ~-~Ω<(-.-)>Ω~-~ Scan_for_More-----------------------------------

def Secondary_Scan_Options(): # Secondary Scan options for Port Scan and Traceroute
    print("\n\n")
    print("=" * 70)
    print("Secondary Scan Types: ")
    print("-" * 70)
    print("1. Port Scan ")
    print("2. Traceroute ")
    print("=" * 70)

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
        20: "FTP Data",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        37: "Time",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        79: "Finger",
        80: "HTTP",
        110: "POP3",
        111: "rpcbind",
        119: "NNTP",
        123: "NTP",
        135: "MS RPC",
        137: "NetBIOS Name",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session",
        143: "IMAP",
        161: "SNMP",
        162: "SNMP Trap",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        515: "LPD",
        520: "RIP",
        587: "SMTP (SSL)",
        631: "IPP",
        993: "IMAP (SSL)",
        995: "POP3 (SSL)",
        1025: "NFS/Windows RPC",
        1026: "Windows RPC",
        1027: "Windows RPC",
        1028: "Windows RPC",
        1433: "MSSQL",
        1521: "Oracle DB",
        1719: "H.323 Gatekeeper",
        1720: "H.323 Call Control",
        5060: "SIP (VoIP)",
        5061: "SIP (VoIP, TLS)",
        # Microsoft Teams & Zoom use STUN/Media ports (shared use)
        3478: "STUN (Teams/Zoom)",
        3479: "STUN (Teams/Zoom)",
        3480: "STUN (Teams/Zoom)",
        3481: "STUN (Teams/Zoom)",
        # Cisco/Poly conferencing media ports (commonly used for RTP)
        5004: "RTP (Cisco WebEx/Polycom)",
        5005: "RTP (Polycom)",
        # Zoom dedicated media ports
        8801: "Zoom Media",
        8802: "Zoom Media",
        8803: "Zoom Media",
        8804: "Zoom Media",
        8805: "Zoom Media",
        8806: "Zoom Media",
        8807: "Zoom Media",
        8808: "Zoom Media",
        8809: "Zoom Media",
        8810: "Zoom Media",
        # Additional conferencing and signaling ports
        9000: "Cisco Conferencing",
        # Generic ports for HTTP proxies / alternate HTTPS
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target_ip, port))

        # Probe calls for port data
        if port == 21:  # FTP
            probe_data = b"USER anonymous\r\nSYST\r\nQUIT\r\n"
        elif port == 22:  # SSH - usually auto-banner
            probe_data = b""
        elif port == 23:  # Telnet
            probe_data = b"\n"
        elif port in [25]:  # SMTP
            probe_data = b"EHLO example.com\r\nQUIT\r\n"
        elif port in [110]:  # POP3
            probe_data = b"CAPA\r\nQUIT\r\n"
        elif port in [143]:  # IMAP
            probe_data = b". CAPABILITY\r\n"
        elif port in [80, 8080, 443]:  # HTTP/HTTPS
            probe_data = b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n"

        if probe_data:
            sock.send(probe_data)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        sock.close()

        if port in [80, 443, 8080] and banner:
            banner = banner.splitlines()[0]

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

port_scan_results = []

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
        port_scan_results.append((target_ip, sorted(open_ports)))
        print("-" * 50)
        print(f"!! Open Ports on {target_ip}:")
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
    
    online_ips = list({(entry[0], entry[1]) for entry in online_ips})
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
        choice = input("\n>> Select one or more IPs by Index separated by a comma (1,2,3) or -A for All: ").strip()
       
        if choice == "-A":
            return [ip for ip, _ in online_ips]

        selected_indexes = [c.strip() for c in choice.split(",") if c.strip().isdigit()]
        selected_ips = [online_ips[int(i) - 1][0] for i in selected_indexes if i.isdigit() and 1 <= int(i) <= len(online_ips)]
        
        if selected_ips:
            return selected_ips 
        print("X Invalid selection. Enter numbers from the list or '-A' for all.")

# --------------------------------------------Ctrl+S ~-~Ω<(-.-)>Ω~-~ Ctrl+S------------------------------------------

def select_save_folder():
    root = tk.Tk()
    root.withdraw()
    root.update()  # Force the window to update
    folder = filedialog.askdirectory(initialdir=os.path.expanduser("~"),
                                     title="Select Folder to Save Scan Results")
    root.destroy()
    return folder

def save_findings():
    save_choice = input("\n>> Would you like to save the scan findings? (y/n): ").strip().lower()
    if save_choice != "y":
        exit()

    # Now ask for a folder location
    save_path = select_save_folder()
    if not save_path:
        print("No folder selected. Scan findings not saved.")
        return

    # Create filename using current date in MM-DD-YYYY format.
    current_date = datetime.datetime.now().strftime("%m-%d-%Y")
    filename = f"NetEnum_Scan_{current_date}.txt"
    full_path = os.path.join(save_path, filename)

    try:
        with open(full_path, "w") as f:
            # Write header matching the display format
            f.write("=" * 70 + "\n")
            f.write("Network Scan Results:\n")
            f.write("-" * 70 + "\n")
            f.write(f"{'IP Address':<20}{'Host Name':<25}{'MAC Address':<20}\n")
            f.write("=" * 70 + "\n")
            # Write each online host entry
            for ip, hostname, mac in online_ips:
                f.write(f"{ip:<20}{hostname:<25}{mac:<20}\n")
            f.write("=" * 70 + "\n")

            if port_scan_results:
                f.write("\n" + "=" * 70 + "\n")
                f.write("Port Scan Results:\n")
                f.write("-" * 70 + "\n")
                for target_ip, open_ports in port_scan_results:
                    f.write(f"Target: {target_ip}\n")
                    for port, service in open_ports:
                        f.write(f"    Port {port}: {service}\n")
                    f.write("-" * 70 + "\n")

        print(f"\nFindings saved to {full_path}")
    except Exception as e:
        print(f"Error saving file: {e}")
        return

    open_file = input(">> Open the results in Notepad? (y/n): ").strip().lower()
    if open_file == "y":
        try:
            subprocess.Popen(["notepad.exe", full_path])
        except Exception as e:
            print(f"Error opening file in Notepad: {e}")
    exit()

# -----------------------Scan_Option_Selection_Logic ~-~Ω<(-.-)>Ω~-~ Scan_Option_Selection_Logic---------------------

while True: # Initial and secondary Scan Selection logic 
    
    if 'Init_Scan' not in locals() or Init_Scan is None:
        Init_Scan = Initial_Scan_Options()

    #  Handle Ping Scan Selection
    if Init_Scan == "1":  
        Combined_Scan(selected_IP, selected_Subnet)

    #  Handle ARP Scan Selection
    elif Init_Scan == "2":  
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
                save_findings()
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
            save_findings()
        else:
            selected_scans.clear()
            selected_NIC, selected_IP, selected_Subnet = Choose_NIC(NICs)  # Restart NIC selection

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------