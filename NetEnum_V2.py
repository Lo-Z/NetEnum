# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
#
# This is a Network scanning tool currently built for windows.
# It offers IP Enumeration, Port Scanning, Traceroute, and DNS Lookup.
# You can save the results or your scans in a text file and nothing is cached, always fresh.
#
# ---------------------- VERSION 2.0 ----------------- VERSION 2.0 ------------------ VERSION 2.0 -------------------
#
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

import os
import sys
if os.name != 'nt':
    import resource #will be ignored by windows
else: #will be ignored by posix
    class DummyResource:
        def __getattr__(self, name):
            def dummy(*args, **kwargs):
                pass
            return dummy
    resource = DummyResource()

import re
from Port_Grabber import grab_banner
import subprocess
import socket
import ipaddress
import dns.resolver
import dns.reversename
import threading
import time
import datetime
from tkinter import *
from tkinter import filedialog
from colorama import init, Fore, Back, Style
init()

global CREATE_NO_WINDOW

# -----------------------------------Color Codes ~ - ~ Ω <(-.-)> Ω ~ - ~ Color Codes---------------------------------

G = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
C = Fore.CYAN
M = Fore.MAGENTA
BLG = Back.LIGHTGREEN_EX
BR = Back.RED
SR = Style.RESET_ALL

# -------------------------------------OS_Finder ~ - ~ Ω <(-.-)> Ω ~ - ~ OS_Finder-----------------------------------

os_posix = None
os_windows = None
Operating_System = os.name
if Operating_System == 'posix':
    os_posix = Operating_System
elif Operating_System == 'nt':
    os_windows = Operating_System

if os_windows:
    CREATE_NO_WINDOW = subprocess.CREATE_NO_WINDOW
else:
    CREATE_NO_WINDOW = 0
# ------------------------------------------NIC_Scan ~-~Ω<(-.-)>Ω~-~ NIC_Scan----------------------------------------

def NIC_Scanner(): # Scans for active Network Interface Cards on computer along with Local DNS servers for hostname resolution

    NIC_info = {}
    local_dns_servers = []

    Current_NIC = None
    Subnet_Mask = None

    if os_windows:
        NIC = subprocess.run(["cmd", "/c", "ipconfig /all"], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)

        for line in NIC.stdout.split("\n"):
            line = line.strip()
            
            if "Ethernet adapter" in line or "Wireless LAN adapter" in line:
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

            elif line:
                ip_match = re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", line.strip())
                if ip_match:
                    local_dns_servers.append(line.strip())

        return NIC_info, local_dns_servers
    
    elif os_posix:
        NIC = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True, shell=False)
        DNS = subprocess.run(["cat", "/etc/resolv.conf"], capture_output=True, text=True, shell=False) 

        for line in NIC.stdout.split("\n"):
            line = line.strip()

            if re.search(r'^\s*(eth|wlan)\d', line):
                Current_NIC = line.split(":")[0]

            elif "inet" in line and Current_NIC:
                Address_match = re.search(r'inet (\d+\.\d+\.\d+\.\d+) \s+netmask (\d+\.\d+\.\d+\.\d+)', line)
                if Address_match:
                    IP_Address = Address_match.group(1).strip()
                    Subnet_Mask = Address_match.group(2).strip()                 

                NIC_info[Current_NIC] = (IP_Address, Subnet_Mask)

                Current_NIC = None
                Subnet_Mask = None

    DNS_info = DNS.stdout

    if DNS_info:
        dns_match = re.search(r'\d+\.\d+\.\d+\.\d+', DNS_info)
        if dns_match:
            dns = dns_match.group(0).strip()
            local_dns_servers.append(dns)

    return NIC_info, local_dns_servers
     
# ----------------------------------------DNS_Server ~-~Ω<(-.-)>Ω~-~ DNS_Server--------------------------------------

def reverse_dns_lookup(ip, local_dns_servers): # Looks for the Local DNS Server for host name resolution
    global CREATE_NO_WINDOW
    if not local_dns_servers:
        return "Unknown"

    
    for dns_server in local_dns_servers:
            try:
                result = subprocess.run(["nslookup", ip, dns_server], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)
                if os_windows:
                    match = re.search(r"Name:\s+(.+)", result.stdout)
                elif os_posix:
                    match = re.search(r"(?im)^Name:\s*(.+)$", result.stdout)
                    if not match:
                        # Try an alternative pattern if the first one fails.
                        match = re.search(r"(?im)^(?:name\s*=\s*)(.+)$", result.stdout)
                if match:
                    hostname = match.group(1).strip()
                    if hostname:
                        return hostname
            except subprocess.SubprocessError:
                continue

        # The following fallback methods are only used on posix systems.
            if os_posix:
                # Fallback 1: Try the 'dig' command.
                try:
                    result = subprocess.run(["dig", "-x", ip, "+short"], capture_output=True, text=True, shell=False)
                    hostname = result.stdout.strip()
                    if hostname:
                        return hostname
                except subprocess.SubprocessError:
                    pass

                # Fallback 2: Try the 'getent hosts' command.
                try:
                    result = subprocess.run(["getent", "hosts", ip],
                                            capture_output=True, text=True, shell=False)
                    parts = result.stdout.split()
                    if len(parts) >= 2:
                        return parts[1]
                except subprocess.SubprocessError:
                    pass

                # Fallback 3: Try using dnspython.
                try:
                    rev_name = dns.reversename.from_address(ip)
                    answer = dns.resolver.resolve(rev_name, 'PTR')
                    hostname = str(answer[0]).strip()
                    if hostname:
                        return hostname
                except Exception:
                    pass

                # Fallback 4: Use Python's built-in reverse lookup.
                try:
                    return socket.gethostbyaddr(ip)[0]
                except Exception:
                    return "Unknown"

            # For Windows, if no method worked, return "Unknown".
            return "Unknown"

# -----------------------------------Select_Your_NIC ~-~Ω<(-.-)>Ω~-~ Select_Your_NIC---------------------------------

def Choose_NIC(NIC_info, preselected_nic=None): # Lists NICs found on Computer
     global online_ips
     online_ips = []

     if not NIC_info:
          print(BR + Y + f"No NIC's No Scans - Better Luck Next Time"+ SR)
          return None

     print(R + f"=" * 70)
     print(G + f"Enumerated NICs")
     print(R + F"-" * 70)

     NIC_List = list(NIC_info.keys())
     for i, NIC in enumerate(NIC_List, start=1):
          IP, Subnet =NIC_info[NIC]
          print(G + f"{i}. {NIC} | IP:{IP} | Subnet:{Subnet}")
     print(R + f"=" * 70)


     if preselected_nic:
        selected_IP, selected_Subnet = NIC_info[preselected_nic]
        return preselected_nic, selected_IP, selected_Subnet
     
     if not sys.stdin or not sys.stdin.isatty():
        return None

     while True:
          choice = input(C + f"\n>> Arm a NIC by selecting a number: "+ M)
          
          if choice.isdigit():
               choice = int(choice)
               if 1 <= choice <= len(NIC_List):
                    selected_NIC = NIC_List[choice - 1]
                    selected_IP, selected_Subnet = NIC_info[selected_NIC]
                    return selected_NIC, selected_IP, selected_Subnet
                    
          print(BR + Y + f"\nX Invalid Input - Select a NIC by Index Number " + SR)
          print("\n\n")

Public_IPV4 = None
Public_IPV6 = None

# ---------------------------------Public_IP_Grabber ~-~Ω<(-.-)>Ω~-~ Public_IP_Grabber-------------------------------

def Public_Grabber(selected_NIC, Passed_From_GUI=bool): # Grabs the public IP address of teh current network
    global CREATE_NO_WINDOW
    global Public_IPV4
    global Public_IPV6
    global selected_IP
    global selected_Subnet
    #selected_NIC
    Public_IP_Results =''

    if not selected_NIC:
        print(BR + Y + '\nYou haven\'t selected a network interface yet' + SR)
        print('\n\n')

        
        nic_result = Choose_NIC(NICs)
        if nic_result is None:
            # gracefully exit if no NIC selected and not running interactively
            sys.exit()
        selected_NIC, selected_IP, selected_Subnet = nic_result



    else:
        if Passed_From_GUI == False:
            print('\n')
            user_input = input(C + 'Are you sure you want to grab the public IP of the network? (y/n): ' + M).strip().lower()
            print("\n")
        elif Passed_From_GUI == True:
            user_input = 'y'


        if user_input == 'y':
            public_ipv4 = subprocess.run(["curl", "https://api.ipify.org"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            Public_IPV4 = public_ipv4.stdout.strip()
            print(R + f"=" * 50)
            print(G + f"Public IPv4 Address: ", C + f"{public_ipv4.stdout.strip()}")
            print(R + f"-" * 50)
            Public_IP_Results += f"=" * 50
            Public_IP_Results += '\n'
            Public_IP_Results += f"Public IPv4 Address: {public_ipv4.stdout.strip()}"
            Public_IP_Results += '\n'
            Public_IP_Results += f"-" * 50
            Public_IP_Results += '\n'
            public_ipv6 = subprocess.run(["curl", "https://api64.ipify.org"], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW)
            Public_IPV6 = public_ipv6.stdout.strip()
            print(G + f"Public IPv6 Address: ", C + f"{public_ipv6.stdout.strip()}")
            print(R + "=" * 50)
            print("\n")
            Public_IP_Results += f"Public IPv6 Address: {public_ipv6.stdout.strip()}"
            Public_IP_Results += '\n\n'
       
        elif user_input == 'n':
            nic_result = Choose_NIC(NICs)
            if nic_result is None:
                # gracefully exit if no NIC selected and not running interactively
                sys.exit()
            selected_NIC, selected_IP, selected_Subnet = nic_result
        
        else:
            print(BR + Y + f"X Invalid selection. Try (y/n)."+ SR)
            print("\n\n")
            Public_Grabber()
    return Public_IP_Results
# -------------------------------------Scan_for_IP's ~-~Ω<(-.-)>Ω~-~ Scan_for_IP's-----------------------------------

def Initial_Scan_Options(): # Initial Scan Options to Enumerate IPs or DNS Lookup

    if selected_NIC: # Displays Selected NIC
        print("\n")
        print(R + f"=" * 70)
        print(G + f"{selected_NIC} | {selected_IP} | {selected_Subnet} =", BR + Y + f" Is Armed "+ SR)


    print(R + f"=" * 70)
    print(G + f"Network Probing Options")
    print(R + f"-" * 70)
    print(G + f"1. Scan for Active IP's on the Network")
    print(G + f"2. DNS Lookup (Requires Internet or Local DNS Server)")
    print(G + f"3. Collect the Public IP of the selected Network")
    print(R + f"=" * 70)

    while True:
        choice = input(C + f"\n>> Select a Scan option: "+ M).strip()
        if choice in ["1", "2", "3"]:
            return choice
        print(SR + f"\n")
        print(BR + Y + f"X Invalid selection. Try again."+ SR)
        print("\n")

# -----------------------------------------Ping_Scan ~-~Ω<(-.-)>Ω~-~ Ping_Scan---------------------------------------
online_ips = [] # All collected IPs get added to this list
scanning_done = False

def ping(ip, local_dns_servers): # Ping -a will collect IPs and Hostnames 
    global CREATE_NO_WINDOW
    if os_windows:
        result = subprocess.run(["cmd", "/c", f"ping -a -n 3 {ip}"], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)

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

    elif os_posix:
        result = subprocess.run([f"ping", "-c", "3", f"{ip}"], capture_output=True, text=True, shell=False)
        
        hostname = "Unknown"

        if f"3 packets transmitted, 3 received" in result.stdout:
            
            match = re.search(r'PING (\d+\.\d+\.\d+\.\d+)', result.stdout)
                 
            if match:
                if hostname == "Unknown":
                    hostname = reverse_dns_lookup(ip, local_dns_servers)

                if hostname == "Unknown":
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                    except socket.herror:
                        hostname = "Unknown"
                elif hostname == "Unknown":
                    try:
                        hostname = subprocess.run([f"getent", "hosts", f"{ip}"], capture_output=True, text=True, shell=False)
                        hostname = hostname.stdout.strip()
                    except subprocess.CalledProcessError as e:
                        hostname = "Unknown"
                elif hostname == "Unknown":
                    try:
                        result = subprocess.run(["dig", "-x", ip, "+short"], capture_output=True, text=True)
                        hostname = result.stdout.strip()
                    except subprocess.CalledProcessError as e:
                        hostname = "Unknown" 
                
            online_ips.append((ip, hostname))            

def subnet_to_cidr(subnet): # Converts a Subnet Mask to Cider Notation
    try:
        cidr_value = sum(bin(int(octet)).count('1') for octet in subnet.split('.'))
        return cidr_value
    except Exception as e:
        return None

def Ping_Scan(ip, subnet, local_dns_servers): # Uses CIDR and Ping operations and sorts the multithreaded output in numerical order
    global online_ips, scanning_done
    scanning_done = False

    def Progress_indicator():

        spinner = [BR + Y + f'<(^O^)>  .<(^-^)>', '<(^o^)> . <(^o^)>', '<(^-^)>.  <(^O^)>', '<(^o^)> . <(^o^)>']
        idx = 0
        while not scanning_done:
            sys.stdout.write(BR + Y + f"\rScanning in progress... please wait {spinner[idx % len(spinner)]}"+ SR)
            sys.stdout.flush()
            idx += 1
            time.sleep(0.15)
        # Clear the line after done:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()
        return

    cidr = subnet_to_cidr(subnet)
    if cidr is None:
        scanning_done = True
        progress_thread.join()
        return

    Active_network = f"{ip}/{cidr}"
    print("\n")
    print(R +f'=' * 70)
    print(G + f"Using",C +f'{ip}',G +f"to find active IP's on subnet",C +f"{subnet} ")
    print(R +f'=' * 70)
    print('\n\n')
    progress_thread = threading.Thread(target=Progress_indicator)
    progress_thread.start()
    
    try:
        network = ipaddress.IPv4Network(Active_network, strict=False)
    except ValueError as e:
        print(BR + Y +f"X Invalid Subnet Range. ERROR {e}"+ SR)
        scanning_done = True
        progress_thread.join()
        return

    threads = []
    for host in network.hosts():
        thread = threading.Thread(target=ping, args=(str(host), local_dns_servers))
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
    global CREATE_NO_WINDOW
    global online_ips

    if os_windows:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)
    elif os_posix:
        result = subprocess.run(["ip", "neigh"], capture_output=True, text=True, shell=False)

    arp_entries = []
    try:
        cidr = sum(bin(int(octet)).count('1') for octet in selected_Subnet.split('.'))
        network = ipaddress.IPv4Network(f"{selected_IP}/{cidr}", strict=False)
    except ValueError:
        print(BR + Y + f"ERROR: Invalid Subnet Mask or IP Address"+ SR)
        print("\n\n")
        return

    for line in result.stdout.split("\n"):
        line = line.strip()

        if os_windows:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+(\w+)", line)
            if match:
                ip, mac, arp_type = match.groups()
            else:
                continue

        elif os_posix:
            match = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+lladdr\s+([\w:]+)", line)
            if match:
                ip, mac = match.groups()
                arp_type = "DYNAMIC"
            else:
                continue
        else:
            continue

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

def Combined_Scan(selected_IP, selected_Subnet, local_dns_servers):
    # Run Ping Scan first (this collects (ip, hostname) tuples in online_ips)
    Ping_Scan(selected_IP, selected_Subnet, local_dns_servers)
    
    # Run ARP Scan to update online_ips with MAC addresses.
    ARP_Scan(selected_IP, selected_Subnet)

    time.sleep(1)

    online_ips.sort(key=lambda x: tuple(map(int, x[0].split("."))))

    # Now print the combined results, which should have real MAC addresses
    Ping_result = ""
    
    if online_ips:
        print(G + f"\nEnumerated Hosts:")
        print(R + f"=" * 70)
        print(G + f"{'IP Address':<20}{'Host Name':<25}{'MAC Address':<20}")
        print(R + f"=" * 70)
        Ping_result += "=" * 70 + "\n"
        Ping_result += "Enumerated Hosts:\n"
        Ping_result += "-" * 70 + "\n"
        Ping_result += f"{'IP Address':<20}{'Host Name':<25}{'MAC Address':<20}\n"
        #Ping_result += "=" * 70 + "\n"
        for ip, hostname, mac in online_ips:
            print(G + f"{ip:<20}{hostname:<25}{mac:<20}")
            Ping_result += f"{ip:<20}{hostname:<25}{mac:<20}\n"
        print(R + f"=" * 70)
        Ping_result += "\n"
    else:
        print(BR + Y + f"\nX No hosts found.")
        Ping_result += "\nX No hosts found.\n"
    return Ping_result

# ----------------------------------------DNS_Lookup ~-~Ω<(-.-)>Ω~-~ DNS_Lookup--------------------------------------

def DNS_Lookup(dns_entered=None): # General DNS lookup, Internet needed for domain searches unless host names are registered in a local DNS server.

    global CREATE_NO_WINDOW
    global Init_Scan
    global local_dns_servers
    global selected_NIC
    global selected_IP
    global selected_Subnet
    global dns_search_results
    dns_search_results = ''

    print(SR +"\n\n")
    print(R + f"=" * 70)
    print(G + f"DNS Lookup")
    print(R + f"=" * 70)
    print("\n")

    if dns_entered:
        dns_search = dns_entered
        dns_from_gui = True
    else:
        dns_from_gui = False
        dns_search = input(C + f">> Please enter a website (Example.com) or IP for DNS Lookup: "+ M).strip()
    if not dns_search:
        print(BR + Y + f"X No DNS Search found. Cannot proceed with DNS Lookup."+ SR)
        return []
    
    print("\n")
    print(R + f"=" * 70)
    print(G + f"Running DNS Lookup on",C + f"{dns_search}",G + f"...")
    print(R + f"-" * 70)
    result = subprocess.run(["nslookup", dns_search], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)
    if "can't find" in result.stdout.lower() or "non-existent" in result.stdout.lower():
        print(BR + Y + f"X DNS Lookup failed. Check if the domain or IP is valid."+ SR)
        dns_search_results += f"X DNS Lookup failed. Check if the domain or IP is valid."
    else:
        print(G + result.stdout)
        print(R + f"=" * 70)
        dns_search_results += '\n'
        dns_search_results += f"=" * 70 + '\n'
        dns_search_results += result.stdout

    if dns_from_gui == False:
        new_scan = input(C + f"\n>> Would you like to run another DNS lookup? (y/n): "+ M).strip().lower()
        if new_scan == "y":
            DNS_Lookup()
        else:
            print(R + f"=" * 70)
            quit_program = input(C + f"\n>> would you like to quit? (y/n): "+ M).strip().lower()
            print(R + f"=" * 70)
            if quit_program == "y":
                save_findings()
            else:
                print("\n\n\n")
                NICs, local_dns_servers = NIC_Scanner()
                nic_result = Choose_NIC(NICs)
                if nic_result is None:
                    # gracefully exit if no NIC selected and not running interactively
                    sys.exit()
                selected_NIC, selected_IP, selected_Subnet = nic_result
                Init_Scan = None
    elif dns_from_gui == True:
        return dns_search_results


# -------------------------------------Scan_for_More ~-~Ω<(-.-)>Ω~-~ Scan_for_More-----------------------------------

def Secondary_Scan_Options(): # Secondary Scan options for Port Scan and Traceroute
    print("\n\n")
    print(R + f"=" * 70)
    print(G + f"Secondary Scan Types: ")
    print(R + f"-" * 70)
    print(G + f"1. Port Scan ")
    print(G + f"2. Traceroute ")
    print(R + f"=" * 70)

    while True:
        choice =input(C + f"\n>> Select scan types separated by comma or -A for All scans: "+ M).strip()
        if choice == "-A":
            return ["3"]
        selected_scans = [s.strip() for s in choice.split(",") if s.strip() in ["1", "2"]]
        if selected_scans:
            return selected_scans    
        print(BR + Y + f"X Invalid selection. Try again."+ SR)

if online_ips:
    selected_scans = Secondary_Scan_Options()

# --------------------------------------Port_Scanner ~-~Ω<(-.-)>Ω~-~ Port_Scanner------------------------------------

def Port_Scanner(selected_ips, selected_ports, gui_callback=None): # Checks for selected IPs and Ports from Scan Option Selection Logic

    if not selected_ips:
        if gui_callback:
            gui_callback("X No IPs selected for Port Scan.")
        print(BR + Y + f"X No IPs selected for Port Scan."+ SR)
        return

    for ip in selected_ips: 
        Port_Scan(ip, selected_ports, gui_callback)
        

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


def Port_Scan(target_ip, ports, gui_callback=None): # Runs Multithreaded port scan using selection data

    global os_posix

    def strip_ansi_codes(text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    if gui_callback:
        gui_callback(f"=" * 50)
        gui_callback(f"Scanning {target_ip}...")

    print("\n")
    print(R + f"=" * 50)
    print(G + f"Scanning",C +f"{target_ip}",G +f"...")

    if os_posix:
        soft_descriptor_limit, hard_descriptor_limit = resource.getrlimit(resource.RLIMIT_NOFILE)
        desired_limit = 20000
        if soft_descriptor_limit < desired_limit:
            try:
                # Set the soft limit to desired_limit and keep the hard limit as is.
                resource.setrlimit(resource.RLIMIT_NOFILE, (desired_limit, hard_descriptor_limit))
            except ValueError as e:
                print(f"If You See This Error, increase your ulimit to above 25,000 with 'ulimit -n 25000': {e}")

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
        print(R + f"-" * 50)
        print(G + f"!! Open Ports on {target_ip}:")

        if gui_callback:
            gui_callback(f"-" * 50)
            gui_callback(f"!! Open Ports on {target_ip}:")

        for port, service in sorted(open_ports):
            clean_service = strip_ansi_codes(service)
            print(G + f" - Port", R + f"{port}", G + f":", C + f"{clean_service}")
            if gui_callback:
                gui_callback(f" - Port {port}: {clean_service}")
        if gui_callback:
            gui_callback('\n')

    else:
        print(R + f"-" * 50)
        print(G + f"X No open ports found on {target_ip}.")
        print(R + f"=" * 50)
        if gui_callback:
            gui_callback(f"-" * 50)
            gui_callback(f"X No open ports found on {target_ip}.\n")

    return gui_callback
# ----------------------------------------Traceroute ~-~Ω<(-.-)>Ω~-~ Traceroute--------------------------------------

def Traceroute(selected_ips, gui_callback=None): # Baisc Traceroute Scan
    
    global CREATE_NO_WINDOW
    
    if not selected_ips:
        if gui_callback: 
            gui_callback("\nX No online IPs found. Run a Ping Scan first.")
        else:
            print(BR + Y + f"\nX No online IPs found. Run a Ping Scan first."+ SR)  
        return

    for ip in selected_ips:
        if gui_callback:
            gui_callback("=" * 50)
            gui_callback(f"Running Traceroute on {ip}...")
            gui_callback("-" * 50)

        else:
            print("\n\n")
            print(R + f"=" * 50)
            print(G + f"Running Traceroute on",C + f"{ip}",G + f"...")
            print(R + f"-" * 50)
        if os_windows:
            result = subprocess.run(["tracert", ip], capture_output=True, text=True, shell=False, creationflags=CREATE_NO_WINDOW)

        elif os_posix:
            result = subprocess.run(["traceroute", "-I", ip], capture_output=True, text=True, shell=False)
        
        if gui_callback:
            gui_callback(result.stdout)

        else:
            print(G + result.stdout)
            print(R + f"=" * 50)

# --------------------------------------Target_Ports ~-~Ω<(-.-)>Ω~-~ Target_Ports------------------------------------

def get_ports(gui_port_selection=None): # User selects port numbers or all ports 1 - 65,535.
        if gui_port_selection:
            choice = gui_port_selection
        else: 
            choice = input(C + f"\n>> Enter port numbers separated by comma (80,443) or -A for scan All ports: "+ M)
            print("\n")

        if choice == "-A" or choice =='all':
            return range(1, 65536)
        else:
            try:
                return [int(port) for port in choice.split(",") if port.isdigit()]
            
            except ValueError:
                print(BR + Y + f"X Invalid port selection."+ SR)
                return get_ports(gui_port_selection=None)

# -----------------------------------------Target_IP ~-~Ω<(-.-)>Ω~-~ Target_IP---------------------------------------

def select_target_ips(online_ips): # User input to select IPs found in Ping or Arp scan
    if not online_ips:
        print(BR + Y + f"X No online devices found. Cannot proceed with scan."+ SR)
        return []
    
    online_ips = list({(entry[0], entry[1]) for entry in online_ips})
    online_ips.sort(key=lambda x: tuple(map(int, x[0].split(".")))) 

    print("\n")
    print(R + f"=" * 50)
    print(G + f"Available IPs:")
    print(R + f"-" * 50)
    print(G + f"{'Index':<8}{'IP Address':<20}{'Host Name'}")
    print(R + f"=" * 50)

    for index, (ip, hostname) in enumerate(online_ips, start=1):
        print(G + f"{index:<8}{ip:<20}{hostname}")
    print(R + f"=" * 50)

    while True:
        choice = input(C + f"\n>> Select one or more IPs by Index separated by a comma (1,2,3) or -A for All: "+ M).strip()
       
        if choice == "-A":
            return [ip for ip, _ in online_ips]

        selected_indexes = [c.strip() for c in choice.split(",") if c.strip().isdigit()]
        selected_ips = [online_ips[int(i) - 1][0] for i in selected_indexes if i.isdigit() and 1 <= int(i) <= len(online_ips)]
        
        if selected_ips:
            return selected_ips 
        print(BR + Y + f"X Invalid selection. Enter numbers from the list or '-A' for all."+ SR)

# --------------------------------------------Ctrl+S ~-~Ω<(-.-)>Ω~-~ Ctrl+S------------------------------------------

def select_save_folder():
    root = Tk()
    root.withdraw()
    root.update()  # Force the window to update
    folder = filedialog.askdirectory(initialdir=os.path.expanduser("~"), title="Select Folder to Save Scan Results")
    root.destroy()
    return folder

def save_findings(gui_call=bool):

    def strip_ansi_codes(text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    if gui_call == False:
        save_choice = input(C + f"\n>> Would you like to save the scan findings? (y/n): "+ M).strip().lower()
        if save_choice != "y":
            exit()
    

    # Now ask for a folder location
    save_path = select_save_folder()
    if not save_path:
        print(BR + Y + f"No folder selected. Scan findings not saved."+ SR)
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
            f.write("=" * 70 + "\n\n\n")

            if Public_IPV4 or Public_IPV6:
                f.write("=" * 70 + "\n")
                f.write("Public IP:\n")
                f.write("-" * 50)
                f.write(f"\nPublic IPv4 Address: {Public_IPV4}\n")
                f.write("-" * 50)
                f.write(f"\nPublic IPv6 Address: {Public_IPV6}\n")
                f.write("=" * 70 + "\n\n")

            if port_scan_results:
                f.write("\n" + "=" * 70 + "\n")
                f.write("Port Scan Results:\n")
                f.write("-" * 70 + "\n")
                for target_ip, open_ports in port_scan_results:
                    f.write(f"Target: {target_ip}\n")
                    for port, services in open_ports:
                        f.write(strip_ansi_codes(f" - Port {port}: {services}\n"))
                    f.write("-" * 70 + "\n\n")

        print(G + f"\nFindings saved to {full_path}")
    except Exception as e:
        print(BR + Y + f"Error saving file: {e}")
        return
    
    if gui_call == False:
        if os_windows:
            open_file = input(C + f">> Open the results in Notepad? (y/n): "+ M).strip().lower()
            if open_file == "y":
                try:
                    subprocess.Popen(["notepad.exe", full_path])
                except Exception as e:
                    print(BR + Y + f"Error opening file in Notepad: {e}")
            exit()

        if os_posix:
            open_file = input(C + f">> Open the results in Nano? (y/n): "+ M).strip().lower()
            if open_file == "y":
                try:
                    with open('/dev/tty', 'r') as tty:
                        subprocess.run(["nano", full_path], stdin=tty)
                except Exception as e:
                    print(f"Error opening file in nano: {e}")
            exit()

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
# ------------------------------------------- Collector Function for GUI--------------------------------------------
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

def Get_NIC_Info():
    NIC_info, _ = NIC_Scanner()
    return [f"{i+1}. {nic} | IP: {ip} | Subnet: {subnet}" for i, (nic, (ip, subnet)) in enumerate(NIC_info.items())]

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

if __name__ == "__main__":

# ----------------------------------------Banner ~ - ~ Ω <(-.-)> Ω ~ - ~ Banner--------------------------------------

    def Banner():
        banner = G + f"""
    ███╗   ██╗███████╗████████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║   ██║████╗ ████║
    ██╔██╗ ██║█████╗     ██║   █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
    ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
    ██║ ╚████║███████╗   ██║   ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝"""
        Banner2 = R + f"""
    -----------------------------------------------------------------"""
        Banner3 = G + f"""
                        Advanced Network Scanner   """
        Banner4 = R + f"""
    -----------------------------------------------------------------"""
        Banner5 = G + f"""
     ~-~-~-~-~- Network ~-~-~Ω <(-.-)> Ω~-~-~ Enumeration -~-~-~-~-~
    ------------------------"""
        Banner6 = C + f""" Version 2.0 """
        Banner7 = G + f"""--------------------------"""
        Banner8 = R + f"""
    -----------------------------------------------------------------
    """ + SR
        print(banner, Banner2, Banner3, Banner4, Banner5, Banner6, Banner7, Banner8)
    Banner()


    NICs, local_dns_servers = NIC_Scanner()
    nic_result = Choose_NIC(NICs)
    if nic_result is None:
        # gracefully exit if no NIC selected and not running interactively
        sys.exit()
    selected_NIC, selected_IP, selected_Subnet = nic_result

# -----------------------Scan_Option_Selection_Logic ~-~Ω<(-.-)>Ω~-~ Scan_Option_Selection_Logic---------------------

    while True: # Initial and secondary Scan Selection logic 
        
        if 'Init_Scan' not in locals() or Init_Scan is None:
            Init_Scan = Initial_Scan_Options()

        #  Handle Ping Scan Selection
        if Init_Scan == "1":  
            Combined_Scan(selected_IP, selected_Subnet, local_dns_servers)

        #  Handle ARP Scan Selection
        elif Init_Scan == "2":  
            DNS_Lookup()
            Init_Scan = None
            continue

        #  Handle ARP Scan Selection
        elif Init_Scan == "3":  
            Public_Grabber(selected_NIC, Passed_From_GUI=False)
            Init_Scan = None
            continue


        selected_scans = []

        #  After initial scans, allow secondary scan options if online IPs exist
        if online_ips:
            proceed_to_secondary = input(C + f"\n\n>> Would you like to run a secondary scan (Port Scan / Traceroute)? (y/n): "+ M).strip().lower()
            if proceed_to_secondary == "y":
                selected_scans = Secondary_Scan_Options()
            else:
                quit_program = input(C +f"\n>> Do you wish to quit? (y/n): "+ M).strip().lower()
                if quit_program == "y":
                    save_findings(gui_call=False)
                else:
                    nic_result = Choose_NIC(NICs)
                    if nic_result is None:
                        # gracefully exit if no NIC selected and not running interactively
                        sys.exit()
                    selected_NIC, selected_IP, selected_Subnet = nic_result  # Restart NIC selection
                    
            selected_ips = None  #  Initializes selected_ips as None

            if "1" in selected_scans:  # If only Port Scan is selected
                selected_ips = select_target_ips(online_ips)
                selected_ports = get_ports(gui_port_selection=None)
                Port_Scanner(selected_ips, selected_ports, gui_callback=None)

            elif "2" in selected_scans:  # If only Traceroute is selected
                selected_ips = select_target_ips(online_ips)
                Traceroute(selected_ips)

            elif "3" in selected_scans: # If the user selects -A (both scans)
                selected_ips = select_target_ips(online_ips)
                selected_ports = get_ports(gui_port_selection=None)
                Port_Scanner(selected_ips, selected_ports, gui_callback=None)
                Traceroute(selected_ips)

        #  After running secondary scans, return to **initial scan menu**
        select_a_different_scan = input(C + f"\n\n>> Would you like to pick another scan type? (y/n): "+ M).strip().lower()
        print("\n\n")

        if select_a_different_scan == "y":
            Init_Scan = None  #  Reset Initial Scan selection before looping
            continue
        else:
            quit_program = input(C + f"\n>> Do you wish to quit? (y/n): "+ M).strip().lower()
            if quit_program == "y":
                save_findings(gui_call=False)
            else:
                selected_scans.clear()
                nic_result = Choose_NIC(NICs)
                if nic_result is None:
                    # gracefully exit if no NIC selected and not running interactively
                    sys.exit()
                selected_NIC, selected_IP, selected_Subnet = nic_result  # Restart NIC selection

# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
