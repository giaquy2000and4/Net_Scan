# Net_Scan
This Python-based program allows users to scan their local network, identify connected devices, and block/unblock devices for research and network security purposes. The program uses the Scapy library for ARP spoofing and packet manipulation, enabling users to explore their network and manage devices effectively.
Features:
Network Scanning: Detect all devices connected to the local network, including their IP and MAC addresses.
Save Device Information: Export connected device information to a text file for later use.
Block Devices: Temporarily block devices from accessing the network using ARP spoofing.
Unblock Devices: Restore blocked devices back to normal functionality.
Real-Time Control: Intuitive menu-driven interface with real-time updates.
Use Cases:
Network security research and testing.
Learning and experimenting with ARP spoofing techniques.
Monitoring and managing connected devices on your local network.
Important Notes:
For Educational Purposes Only: This tool should only be used on networks you own or have explicit permission to test. Misuse of this tool may violate laws and regulations.
Requires administrative/root privileges to run.
Technologies Used:
Scapy: For crafting and sending network packets.
Psutil: For retrieving network interface information.
Python Threading: For non-blocking operations.
Requirements:
Python 3.x
Scapy library (pip install scapy)
Psutil library (pip install psutil)
Disclaimer:
This project is intended for educational purposes and ethical network security research only. The author is not responsible for any misuse of this program.


