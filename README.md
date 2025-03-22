# NetEnum V 1.4.0

A Network Enumeration tool: Scan for IPs, Find Open Ports, Traceroute, and DNS Lookup.

---------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ----------------------------

---------------------------- VERSION 1.4.0 -------------------------------

v1.4.0 Added color theme, Public IP Grabber in IPv4 & IPv6, Enhanced port probing for service header responses.

Added every port, service name and description rom [Iana's registry of ports and services](https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xml) 

The Grab_Banner (Port_Grabber.py) function was separated from the NetEnum file to reduce the over all size of the NetEnum script due to the addition of all the registered ports from the Iana registry (around 6,000+ registered ports in total).

An error was produced if the name of the network interface on the computer had a customized name, causing the program to crash, this has been fixed.

---------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ ----------------------------

NetEnum is a Network Enumeration tool that will check for the computers NIC(s) and allow the selection of whichever interface you'd like to use.

After selecting your NIC, you can scan for IPs, or DNS Lookup, or grab the public IP of the current network.

Once IPs are enumerated you can select either a Port scan, or Traceroute.

Choose one, multiple, or -A for All IPs

Selecting a specific port to scan, Multiple separated by a comma, or -A for all 65,535 ports. With Probe data to get a service header response. If no response is given but the port is open,  "Probe Header Attempt Failed (Common Service: service_name)" will be displayed.

Traceroute simply does it's thing.

Save your results to a .txt file in a directory of your choice.

more additions to come...

![NetEnum_Logo](https://github.com/user-attachments/assets/9b271625-1b94-4dce-b769-94d32ddd443d)

![image](https://github.com/user-attachments/assets/901c56e1-081c-40f2-b986-c993cdea502b)

![image](https://github.com/user-attachments/assets/e698bd11-e929-4f8d-a442-b18c3323f4fb)
