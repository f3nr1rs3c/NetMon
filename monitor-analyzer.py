import argparse
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore, Style
import pyfiglet

# Initialize colorama for colored output
init()

# Function to display the banner
def display_banner():
    banner = pyfiglet.figlet_format("Network Monitor")
    print(Fore.MAGENTA + banner)
    print(Fore.CYAN + "=" * 60)
    print(Fore.YELLOW + "Created by: F3nr1r")
    print(Fore.YELLOW + "Purpose: Monitor network traffic by protocol")
    print(Fore.CYAN + "=" * 60 + Style.RESET_ALL)

# Function to handle packets
def packet_callback(packet):
    if IP in packet:  # Check if packet has an IP layer
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if TCP in packet:
            print(Fore.GREEN + f"[TCP] {ip_src} -> {ip_dst}" + Style.RESET_ALL)
        elif UDP in packet:
            print(Fore.BLUE + f"[UDP] {ip_src} -> {ip_dst}" + Style.RESET_ALL)
        elif ICMP in packet:
            print(Fore.YELLOW + f"[ICMP] {ip_src} -> {ip_dst}" + Style.RESET_ALL)
        else:
            print(Fore.RED + f"[Other Protocol] {ip_src} -> {ip_dst}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "Non-IP Packet Detected" + Style.RESET_ALL)

# Main function
def main():
    # Argument parser for command-line interface
    parser = argparse.ArgumentParser(description="Network Traffic Monitoring Tool")
    parser.add_argument("-i", "--interface", type=str, help="Specify the network interface", required=True)
    args = parser.parse_args()

    # Display the banner
    display_banner()

    # Notify user of selected interface
    print(Fore.CYAN + f"Monitoring traffic on interface: {args.interface}" + Style.RESET_ALL)

    # Start sniffing packets on the specified interface
    try:
        sniff(iface=args.interface, prn=packet_callback, store=False)
    except PermissionError:
        print(Fore.RED + "Permission Denied: Please run the script as root or administrator." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An error occurred: {e}" + Style.RESET_ALL)

if __name__ == "__main__":
    main()
