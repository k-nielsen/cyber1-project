# Shreyas Srinivasa
#Do not share with other groups!!!!

import scapy.all as scapy

def detect_nmap_scan(packet):
    if packet.haslayer(scapy.TCP):
        flags = packet[scapy.TCP].flags
        # Check for Nmap-like scan patterns
        # if flags == 0x12 or flags == 0x14 or flags == 0x18: #You have to let me know what these flags mean in our next meeting! :)
        #     print("[+] Possible Nmap scan detected from {}:{}".format(packet[scapy.IP].src, packet[scapy.TCP].sport))
        #     print("Flag is: {}".format(flags))
        #     print("Packet length is: {}".format(len(packet)))
        #     print("Packet is: {}".format(str(packet)))
        #     packet.show()
        #     print("Stuff")
        #     print("")
        #     print("More stuff")
        #     print(packet.raw_packet_cache)
        #     print("More more stuff")
        #     for i in packet.fields:
        #         print(i, packet.fields[i])
        #     print("Even more stuff")
        #     packet.payload.show()
        #     print("Even more more stuff")
        #     print("Packet header???: {}".format(str(packet)[:(packet[scapy.IP].ihl * 4)]))
        if flags == 0x02 or flags == 0x12: #TCP_SYN scan Zmap??? # Flags in of themselves are not usefull to be certain something is from an internet scanner
            print("[+] Possible Zmap scan detected from {}:{}".format(packet[scapy.IP].src, packet[scapy.TCP].sport))
            print("Flag is: {}".format(flags))
            print("Packet length is: {}".format(len(packet)))
            packet.show()
            print("")
            print("Stuff")
            print(packet.raw_packet_cache)
            print("More stuff")
            for i in packet.fields:
                print(i, packet.fields[i])
            print("Even more stuff")
            packet.payload.show()
            print("Even more more stuff")
            print("Packet header???: {}".format(str(packet)[:(packet[scapy.IP].ihl * 4)]))

def main(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=detect_nmap_scan)
    except KeyboardInterrupt:
        print("[-] Stopping the Nmap scan detection tool.")

if __name__ == "__main__":
    interface = "ens33"  # Change this to your network interface
    main(interface)
