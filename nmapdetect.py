# Shreyas Srinivasa
#Do not share with other groups!!!!
import scapy.all as scapy
from datetime import datetime

last_packet_time = None

def detect_nmap_scan(packet):
    global last_packet_time
    current_time = datetime.now()
    if packet.haslayer(scapy.TCP) and last_packet_time is not None:
        time_diff = (current_time - last_packet_time).total_seconds()
        flags = packet[scapy.TCP].flags
        # Check for Nmap-like scan patterns
        if time_diff < 0.1 and (flags == 0x12 or flags == 0x14 or flags == 0x18): #You have to let me know what these flags mean in our next meeting! :)
            print("Possible Nmap scan detected, Time diff: {}".format(time_diff))
            #print("[+] Possible Nmap scan detected, packet show: {}".format(packet.show()))
    last_packet_time = current_time
    
def main(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=detect_nmap_scan)
    except KeyboardInterrupt:
        print("[-] Stopping the Nmap scan detection tool.")

if __name__ == "__main__":
    interface = "ens33"  # Change this to your network interface
    main(interface)
