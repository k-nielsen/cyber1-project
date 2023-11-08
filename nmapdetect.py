# Shreyas Srinivasa
#Do not share with other groups!!!!
import scapy.all as scapy​

def detect_nmap_scan(packet):
    if packet.haslayer(scapy.TCP):
        flags = packet[scapy.TCP].flags
        # Check for Nmap-like scan patterns
        if flags == 0x12 or flags == 0x14 or flags == 0x18: #You have to let me know what these flags mean in our next meeting! :)
            print("[+] Possible Nmap scan detected from {}:{}".format(packet[scapy.IP].src, packet[scapy.TCP].sport))

def main(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=detect_nmap_scan)
    except KeyboardInterrupt:
        print("[-] Stopping the Nmap scan detection tool.")

if __name__ == "__main__":
    interface = "eth0"  # Change this to your network interface
    main(interface)
