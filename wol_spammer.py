from scapy.all import ARP, Ether, srp
import socket
import tkinter as tk
from threading import Thread

class NetworkManager:
    def __init__(self, root):
        self.root = root
        self.root.title("MAC Address Sniffer & WOL Sender")
        
        # Text area for displaying detected devices
        self.device_text = tk.Text(root, height=15, width=50)
        self.device_text.pack()

        # Button to start scanning for devices
        self.scan_button = tk.Button(root, text="Scan Network for Devices", command=self.start_scan)
        self.scan_button.pack()

        # Button to send WOL signals
        self.wol_button = tk.Button(root, text="Send WOL Signal", command=self.send_wol_signals)
        self.wol_button.pack()

        # List to store detected devices
        self.devices = []

    def scan_network(self):
        # Define the target network (Change this to your network if necessary)
        target_ip = "192.168.1.1/24"  # Example for typical home networks
        # Create an ARP request to discover devices
        arp_request = ARP(pdst=target_ip)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
        packet = ether / arp_request
        
        # Send the packet and receive the response
        result = srp(packet, timeout=2, verbose=False)[0]
        
        # Process the responses
        self.devices = []
        self.device_text.delete(1.0, tk.END)  # Clear previous results
        self.device_text.insert(tk.END, "IP Address\t\tMAC Address\n")
        self.device_text.insert(tk.END, "-" * 50 + "\n")
        
        for sent, received in result:
            device_info = {'ip': received.psrc, 'mac': received.hwsrc}
            self.devices.append(device_info)
            self.device_text.insert(tk.END, f"{device_info['ip']}\t\t{device_info['mac']}\n")

    def send_wol(self, mac_address):
        # Format the MAC address
        mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))
        # Create the WOL magic packet
        wol_packet = b'\xff' * 6 + mac_bytes * 16
        # Broadcast the WOL packet
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(wol_packet, ('<broadcast>', 9))  # Port 9 is the standard for WOL

    def send_wol_signals(self):
        for device in self.devices:
            try:
                self.send_wol(device['mac'])
                self.device_text.insert(tk.END, f"WOL signal sent to {device['mac']}\n")
            except Exception as e:
                self.device_text.insert(tk.END, f"Failed to send WOL to {device['mac']}: {str(e)}\n")

    def start_scan(self):
        Thread(target=self.scan_network).start()

# Create the main window
root = tk.Tk()
manager = NetworkManager(root)
root.mainloop()
