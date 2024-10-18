from scapy.all import ARP, Ether, srp
import socket
import time

def scan_network(target_ip):
    # Create an ARP request to discover devices
    arp_request = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp_request
    
    # Send the packet and receive the response
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    print("IP Address\t\tMAC Address")
    print("-" * 50)
    
    for sent, received in result:
        device_info = {'ip': received.psrc, 'mac': received.hwsrc}
        devices.append(device_info)
        print(f"{device_info['ip']}\t\t{device_info['mac']}")
    
    return devices

def send_wol(mac_address):
    # Format the MAC address
    mac_bytes = bytes.fromhex(mac_address.replace(":", "").replace("-", ""))
    # Create the WOL magic packet
    wol_packet = b'\xff' * 6 + mac_bytes * 16
    # Broadcast the WOL packet
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(wol_packet, ('<broadcast>', 9))  # Port 9 is the standard for WOL

def main():
    # Define the target network (Change this to your network if necessary)
    target_ip = "192.168.1.1/24"  # Example for typical home networks
    
    print("Scanning network for devices...")
    devices = scan_network(target_ip)
    
    # Send WOL signals to all detected devices
    for device in devices:
        print(f"Sending WOL signal to {device['mac']}...")
        send_wol(device['mac'])
        time.sleep(1)  # Delay between sending packets

if __name__ == "__main__":
    main()
