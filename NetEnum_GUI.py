# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------
#
# ---------------------------------------------- ~ The GUI for NetEnum ~ --------------------------------------------
#
# ---------------------- VERSION 2.0 ----------------- VERSION 2.0 ------------------ VERSION 2.0 -------------------
#
# ---------------------------------------------- ~ - ~ Ω <(-.-)> Ω ~ - ~ --------------------------------------------

import customtkinter as ctk
from tkinter import PhotoImage
import NetEnum_V2 as NET
import threading
import os
import sys

# -------------------------------------------Colors  ~-~Ω<(-.-)>Ω~-~ Colors -----------------------------------------

# Colors
Black = '#000000'
White = '#ffffff'
lg = '#c2c2c2'
mlg = '#9c9c9c'
mg = '#6b6b6b'
dg = '#3d3d3d'
avg = '#242424'
Grey = '#a3a3a3'
Red = '#FF0000'
Blue = '#0000FF'
Green = '#37ff00'
Cyan = '#00f7ff'
Magenta = '#aa00ff'
Bkg = '#727573'

# ---------------------------------------Global Vars ~-~Ω<(-.-)>Ω~-~ Global Vars-------------------------------------

global Output_Box, scanning_done
Output_Box = None
scanning_done = False
first_scan_done = False

# ---------------------------------------Main Window ~-~Ω<(-.-)>Ω~-~ Main Window-------------------------------------

def Net_GUI():
    def resource_path(relative_path):
        try:
            base_path = sys._MEIPASS  # PyInstaller's temp dir
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    # Main Window
    NetEnum_Main_Window = ctk.CTk()
    NetEnum_Main_Window.geometry("1500x750") 
    NetEnum_Main_Window.resizable(False, False)
    NetEnum_Main_Window.title("NetEnum - Advanced Network Enumeration Tool")
    if os == 'nt':
        NetEnum_Main_Window.iconbitmap(resource_path("NetEnum_Logo_icon.ico"))
    elif os =='posix':
        NetEnum_Main_Window.iconbitmap(resource_path("NetEnum_Logo_icon.png"))
    
    # Theme
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("dark-blue")

# --------------------------------------------Frames ~-~Ω<(-.-)>Ω~-~ Frames------------------------------------------

    # Frames
    Left_Frame = ctk.CTkFrame(NetEnum_Main_Window, fg_color=avg, border_color=mg, border_width=2)
    Left_Frame.place(relx=0.01, rely=0, relwidth=0.45, relheight=1.0)
    Right_Frame = ctk.CTkFrame(NetEnum_Main_Window, fg_color=avg, border_color=mg, border_width=2)
    Right_Frame.place(relx=0.48, rely=0, relwidth=0.51, relheight=1.0)

# ---------------------------------------------Fonts ~-~Ω<(-.-)>Ω~-~ Fonts-------------------------------------------

    # Fonts
    Banner = ctk.CTkFont(family='Courier New', size=14, weight='bold')
    Title = ctk.CTkFont(family='Segoe UI', size=20)
    Action = ctk.CTkFont(family='Segoe UI', size=16)
    Output = ctk.CTkFont(family='Courier New', size=14)

# ----------------------------------------Text Boxes ~-~Ω<(-.-)>Ω~-~ Text Boxes--------------------------------------

    #text box for scan results
    global Output_Box
    Output_Box = ctk.CTkTextbox(Right_Frame, font=Banner, fg_color='black', border_color='green', border_width=2, width=590, height=650)
    Output_Box.place(relx=0.02, rely=0.06, relwidth=0.96, relheight=0.91)
    Output_Box.insert('0.0', '''    
                                     Welcome to   
                                        
            ███╗   ██╗███████╗████████╗███████╗███╗   ██╗██╗   ██╗███╗   ███╗
            ████╗  ██║██╔════╝╚══██╔══╝██╔════╝████╗  ██║██║   ██║████╗ ████║
            ██╔██╗ ██║█████╗     ██║   █████╗  ██╔██╗ ██║██║   ██║██╔████╔██║
            ██║╚██╗██║██╔══╝     ██║   ██╔══╝  ██║╚██╗██║██║   ██║██║╚██╔╝██║
            ██║ ╚████║███████╗   ██║   ███████╗██║ ╚████║╚██████╔╝██║ ╚═╝ ██║
            ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝     ╚═╝
                            
                Select a Network Interface and Enumerate the Network.
                       ~ - ~ - ~ - ~ - <(-.-)> - ~ - ~ - ~ - ~ 
                      
                      
                            Scan Results Will Display Here...\n''')
    Output_Box.configure(state="disabled")

# -----------------------------------------Variables ~-~Ω<(-.-)>Ω~-~ Variables---------------------------------------

    #Collecting NIC_Scanner data
    NICs, local_dns_servers = NET.NIC_Scanner()

    # Nic_Selectors returns value to Active_Nic
    Active_Nic = ctk.StringVar()

    Online_Nics = []
    Nic_Display_Info = {}
    Armed_Nic = {}

# -------------------------------------Nic Selection ~-~Ω<(-.-)>Ω~-~ Nic Selection-----------------------------------

    #Selected_Network = Active_Nic
    def Nic_Selectors(Display_Name):
        nic_name = Nic_Display_Info[Display_Name]
        ip, subnet = NICs[nic_name]
        Active_Nic.set(f"Armed: {nic_name} IP: {ip} Subnet: {subnet}")
        Armed_Nic.clear()
        Armed_Nic.update({nic_name: (ip, subnet)})
        NET.Choose_NIC(NICs, preselected_nic=nic_name)
        Scan_Options()

    # For loop to creat multiple buttons based on enumerated NICs
    for i, nic_name in enumerate(NICs):
        ip, subnet = NICs[nic_name]
        ComboBox_Text = f"{i+1}. {nic_name} | IP: {ip} | Subnet: {subnet}"
        Online_Nics.append(ComboBox_Text)
        Nic_Display_Info[ComboBox_Text] = nic_name

    # Nic Selection ComboBox
    Nic_options = ctk.CTkComboBox(Left_Frame, dropdown_font=Action, justify='center', values=Online_Nics, command=Nic_Selectors, font=Action, corner_radius=10, width=600, state='readonly', button_color='#1F6AA5', dropdown_hover_color='#0E3655')
    Nic_options.pack(pady=20)
    Nic_options.set('Arm a NIC for Network Enumeration')

# --------------------------------------Scan Options ~-~Ω<(-.-)>Ω~-~ Scan Option-------------------------------------

    def Scan_1_Selection(Value):
        global nic_name, scanning_done
        scanning_done = False

        if Value == "Scan for IP's":
            Segmented_Scan_Options.set('')
            nic_name, (ip, subnet) = list(Armed_Nic.items())[0]
            Progress_indicator_gui()

            def Running_Ping():
                global scanning_done, Scan_Output
                Scan_Output = NET.Combined_Scan(selected_IP=ip, selected_Subnet=subnet, local_dns_servers=local_dns_servers)
                scanning_done = True
                Secondary_Scan_Options()
                Display_Ping_Scan_Results(Scan_Output)
                
            threading.Thread(target=Running_Ping).start()

        elif Value == "DNS Lookup":
            Segmented_Scan_Options.set('')
            # Function pulls up a dialog box when called, captures input and adds it to a label
            def DNS_Search_Entry():
                dns_search_dialog = ctk.CTkInputDialog(text='Please enter a website (Example.com) or IP for DNS Lookup', title='DNS Search') 
                dns_search_dialog.geometry("+700+300")               
                dns_search = dns_search_dialog.get_input()
                return dns_search
            
            dns_entered = DNS_Search_Entry()
            DNS_Results = NET.DNS_Lookup(dns_entered=dns_entered)
            Display_DNS_Scan_Results(DNS_Results)
            
        elif Value == "Collect Public IP":
            Segmented_Scan_Options.set('')
            nic_name, (ip, subnet) = list(Armed_Nic.items())[0]
            Public_IP_Results = NET.Public_Grabber(selected_NIC=nic_name, Passed_From_GUI=True)
            Display_Public_IP_Results(Public_IP_Results)

    # Once a NIC is selected This function opens new options
    def Scan_Options():

        global Output_Box
        global Scan_Progress_Label

        Scan_Progress_Label = ctk.CTkLabel(Right_Frame, text="", font=Output, text_color='yellow')
        Scan_Progress_Label.pack(pady=5)

    Optional_Scans = ["Scan for IP's", "DNS Lookup", "Collect Public IP"]
    # Ping, DNS, and Publid IP grabber Option buttons
    Segmented_Scan_Options = ctk.CTkSegmentedButton(Left_Frame,font=Action, values=Optional_Scans, command=Scan_1_Selection, unselected_hover_color='#1F6AA5')
    Segmented_Scan_Options.pack(pady=5)

# ----------------------------Secondary Scan Options ~-~Ω<(-.-)>Ω~-~ Secondary Scan Options--------------------------

    def Scan_2_Selection(value):
        global selected_ips
        selected_ips = [ip for ip, switch in Selected_IPs.items() if switch.get() == 1]

        def Port_Scan():
            global scanning_done
            Segmented_Scan_Options2.set('')
            Select_Port_Dialog = ctk.CTkInputDialog(text='Select ports (22,23,80,443,8080) or type ALL', title='Port Selection')
            Select_Port_Dialog.geometry("+700+300")
            port_input = Select_Port_Dialog.get_input()
            
            
            if port_input:
                port_input = port_input.lower()
                if port_input == 'all':
                    ports = list(range(1, 65536))
                else:
                    ports = [int(p.strip()) for p in port_input.split(',') if p.strip().isdigit()]

                scanning_done = False
                Progress_indicator_gui()

                def run_port_scan():
                    global scanning_done
                    NET.Port_Scanner(selected_ips=selected_ips, selected_ports=ports, gui_callback=Display_Port_Results)
                    scanning_done = True
                    
                threading.Thread(target=run_port_scan).start()

        def Traceroute():
                Segmented_Scan_Options2.set('')
                def Run_Traceroute():
                    NET.Traceroute(selected_ips=selected_ips, gui_callback=Tracerout_Scan_Results)
                    
                threading.Thread(target=Run_Traceroute).start()

        if value == 'Port Scanner':
            Port_Scan()

        elif value == 'Traceroute':
            Traceroute()

    Secondary_Options = ['Port Scanner', 'Traceroute',]

    def Secondary_Scan_Options():
        global Selected_IPs
        Selected_IPs = {}

        # Importing online IPs post scan 
        from NetEnum_V2 import online_ips

        # IP Selection Switches
        for ip, hostname, mac in online_ips:
            IP_Options = ctk.CTkSwitch(Secondary_Scrollable_Frame, text=f'{ip} | {hostname} | {mac}',font=Action, onvalue=1, offvalue=0)
            IP_Options.pack(anchor="w", pady=2)
            Selected_IPs[ip] = IP_Options
            
    # Ping, DNS, and Publid IP grabber Option buttons
    Segmented_Scan_Options2 = ctk.CTkSegmentedButton(Left_Frame,font=Action, values=Secondary_Options, command=Scan_2_Selection, unselected_hover_color='#1F6AA5')
    Segmented_Scan_Options2.pack(pady=10)

    #Scrollable Frame for Secondary Scan
    Secondary_Scrollable_Frame = ctk.CTkScrollableFrame(Left_Frame, fg_color=dg, label_text='Select IPs for Secondary Scan')
    Secondary_Scrollable_Frame.place(relx=0.1, rely=0.25, relwidth=0.8, relheight=0.49)

# --------------------------------------Text Display ~-~Ω<(-.-)>Ω~-~ Text Displayon----------------------------------

    # Prints the Ping Scan results to the Text Box
    def Display_Ping_Scan_Results(text):
        global first_scan_done
        Output_Box.configure(state="normal")
        if not first_scan_done:
            Output_Box.delete('0.0', 'end')
            first_scan_done = True
        Output_Box.insert("end", text)
        Output_Box.configure(state="disabled")

    def Display_DNS_Scan_Results(text):
        global first_scan_done
        Output_Box.configure(state="normal")
        if not first_scan_done:
            Output_Box.delete('0.0', 'end')
            first_scan_done = True
        Output_Box.insert("end", text)
        Output_Box.configure(state="disabled")

    def Display_Public_IP_Results(text):
        global first_scan_done
        Output_Box.configure(state="normal")
        if not first_scan_done:
            Output_Box.delete('0.0', 'end')
            first_scan_done = True
        Output_Box.insert("end", text)
        Output_Box.configure(state="disabled")

    def Display_Port_Results(text):
        global first_scan_done
        Output_Box.configure(state="normal")
        if not first_scan_done:
            Output_Box.delete('0.0', 'end')
            first_scan_done = True
        Output_Box.insert("end", text + "\n")
        Output_Box.see("end")
        Output_Box.configure(state="disabled")

    def Tracerout_Scan_Results(text):
        global first_scan_done
        Output_Box.configure(state="normal")
        if not first_scan_done:
            Output_Box.delete('0.0', 'end')
            first_scan_done = True
        Output_Box.insert("end", text + "\n")
        Output_Box.see("end")
        Output_Box.configure(state="disabled")

# ----------------------------------Progress Scanner ~-~Ω<(-.-)>Ω~-~ Progress Scanner--------------------------------

    #scanning_done = False
    def Progress_indicator_gui():
        spinner = ['<(^O^)>  .<(^-^)>', '<(^o^)> . <(^o^)>', '<(^-^)>.  <(^O^)>', '<(^o^)> . <(^o^)>']
        idx = 0

        def update_spinner():
            nonlocal idx
            if scanning_done:
                Scan_Progress_Label.configure(text="Scan Complete")
                Scan_Progress_Label.after(3000, lambda: Scan_Progress_Label.configure(text=''))
                return

            Scan_Progress_Label.configure(text=f"Scanning in progress... please wait {spinner[idx % len(spinner)]}")

            idx += 1
            Scan_Progress_Label.after(150, update_spinner)

        update_spinner()  # start the loop
    
    def Scan_Saver():
        NET.save_findings(gui_call=True)

    Save_Button_Label = ctk.CTkLabel(Left_Frame, font=Title, text='Export to a .txt file')
    Save_Button_Label.place(relx=0.385, rely=0.775)
    Save_Button = ctk.CTkButton(Left_Frame, font=Title, text='Save Scan', command=Scan_Saver, fg_color='#1F6AA5', hover_color='#144870')
    Save_Button.place(relx=0.4, rely=0.825)

    NetEnum_Main_Window.mainloop()

    return Net_GUI

Net_GUI()