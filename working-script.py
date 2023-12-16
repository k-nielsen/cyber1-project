import scapy.all as scapy
from collections import defaultdict
import time


######### Constants
threshold = 10 # Adjust the threshold as needed
rate_threshold = 15000 # Adjust the threshold as needed
my_ip = "192.168.56.106" # Change this to your IP
interface = "enp0s3"  # Change this to your network interface

######### Dictionaries
source_of_traffic = {}
packet_count = defaultdict(int) # Dictionary to store packet count per source IP
conversation_completeness = {} # Dictionary to track TCP conversation completeness by source and destination IP pairs
incomplete_conversations_count = {} # Dictionary to count incomplete conversations by source IP
sources_of_traffic_ports = {} # Dictionary for tracking attempts on not hosted ports

# Function to calculate packet rate
def calculate_packet_rate(src_ip):
    current_time = time.time()
    if src_ip in packet_count:
        elapsed_time = current_time - packet_count[src_ip]['timestamp']
        packet_rate = packet_count[src_ip]['count'] / elapsed_time
        return packet_rate
    else:
        return 0

# Function to generate the final report
def generate_final_report():
    for src_ip, reasons in source_of_traffic.items():
        if "HIGH_RATE" in reasons:
            print(f"[+] Possible port scan from {src_ip} based to high packet rate")
        if "CC" in reasons:
            print(f"[+] Possible port scan from {src_ip} based o, incomplete conversations")
        if "CLOSED_PORTS" in reasons:
            print(f"[+] Possible port scan detected from {src_ip} based on probes to unused ports")
        
        # Note that this check return irregardless of a possible port scan being detected
        # This is due to ZMap usually only sending one packet, to one or few ports, making the port scan detection techniques presented less reliable
        if "ZMap_ID" in reasons:
            print(f"[+] ZMap suspected from {src_ip} based on IP ID field check")
        
        else:
            if "Nmap_W" in reasons and "Nmap_HL" in reasons:
                print(f'[+] Nmap -sS scan suspected from {src_ip}, based on window size and TCP header length')
            elif "Nmap_W" in reasons or "Nmap_HL" in reasons:    
                print(f'[+] Nmap -sS scan suspected from {src_ip}, based on either window size or TCP header length')
                
def port_scan_detection(packet):
    # Make sure it is a TCP packet and not traffic from our IP
    if packet.haslayer(scapy.TCP) and packet[scapy.IP].src != my_ip:
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport

        # Initiate tracking of connecting IP's
        if src_ip not in source_of_traffic: 
            source_of_traffic[src_ip] = "SEEN;"

############# Port scan detection: Packet rate #############
        # Check for high packet rate
        packet_rate = calculate_packet_rate(src_ip)
        if packet_rate > rate_threshold: 
            #print(f"High packet rate detected from {src_ip} to {dst_ip} on port {dst_port} with packet rate: {packet_rate}") # Debug print
            if "HIGH_RATE" not in source_of_traffic[src_ip]:
                # Flag a source IP has having a high rate of traffic.
                source_of_traffic[src_ip] += "HIGH_RATE;"            
        
        # Update packet count for the source IP
        if src_ip in packet_count:
            packet_count[src_ip]['count'] += 1
            packet_count[src_ip]['timestamp'] = time.time()
        else:
            packet_count[src_ip] = {'count': 1, 'timestamp': time.time()}

############# Port scan detection: Conversation completeness #############
############# Inpsired by Wireshark #############
        # Mapped using https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html as inspiration
        tcp_flags_map = {
            "S": 1, #SYN
            "SA": 2, #SYN-ACK
            "A": 4, #ACK
            "PA": 8, #Using PSH flag (combined with ACK) as indicator of DATA
            "FA": 16, #Using FIN in combination with ACK as indicator of finished conversation
            "RA": 32, #RST in combination with ACK as indicator of reset conversation
        }
        # Calculate a unique conversation identifier based on source and destination IPs and ports
        conversation_id = hash(str(sorted((f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"))))
        
        # Calculate a value representing the packet's TCP flags
        tcp_flags = packet[scapy.TCP].flags
        if str(tcp_flags) in tcp_flags_map:         
            if conversation_id in conversation_completeness:
                conversation_completeness[conversation_id] |= tcp_flags_map[str(tcp_flags)]
            else:
                conversation_completeness[conversation_id] = tcp_flags_map[str(tcp_flags)]
            
        # For debugging purposes a notice of completed conversations
        # if conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63:  # This indicates a complete conversation with data transfer (SYN, SYN-ACK, ACK, DATA, FIN)
        #     print(f"[+] Complete conversation with data transfer: {conversation_id} \n {conversation_completeness}")
        #     print("********************************* \n")

        if "F" in str(tcp_flags) or "R" in str(tcp_flags):
            # Check for incomplete conversations
            if not (conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63):
                # Assert our IP is not tracked
                if src_ip != my_ip:
                    if src_ip in incomplete_conversations_count:
                        incomplete_conversations_count[src_ip] += 1
                        if incomplete_conversations_count[src_ip] >= threshold: 
                            if "CC" not in source_of_traffic[src_ip]:
                                source_of_traffic[src_ip] += "CC;"
                        #    print(f"[+] Possible Port Scan from {src_ip} as it has meet or exceeded **{threshold}** number of incomplete conversations \n Number of incomplete conversations: {incomplete_conversations_count[src_ip]}")
                        #    print("********************************* \n")
                    else:
                        incomplete_conversations_count[src_ip] = 1
                else:
                    pass 

############# Port scan detection: One source many ports #############
############# Basically keeps track of a threshold of probes to IP's/Ports known not to have a service running #############
############# Based on inspiration from Jung et al. 2004, Fast Portscan Detection Using Sequential Hypothesis Testing #############
        # A dictionary containing which hosts (IP's) has services on defined ports within our network
        known_services = {
           my_ip: [8080, 22, 23] # Adjust ports for hosted services as needed
        }
        
        if dst_ip == my_ip:
           if int(dst_port) not in [port for ports in known_services.values() for port in ports]:
               if src_ip in sources_of_traffic_ports:
                   sources_of_traffic_ports[src_ip] += 1
                   if sources_of_traffic_ports[src_ip] >= threshold:  # Adjust the threshold as needed
                       if "CLOSED_PORTS" not in source_of_traffic[src_ip]:
                           source_of_traffic[src_ip] += "CLOSED_PORTS;"
                    #    print(f"[+] Possible port scan detected, based on probes to unused ports, meeting or exceeding threshold: **{threshold}** \n From:  {src_ip}")
                    #    print("********************************* \n")
               else:
                  sources_of_traffic_ports[src_ip] = 1

############# Tool distinction: Nmap -sS checks #############
############# Tool distinction: Nmap -sS checks / Window size #############
        if packet[scapy.TCP].flags == 0x02 and packet[scapy.TCP].window == 1024:
            if "Nmap_W" not in source_of_traffic[src_ip]:
                source_of_traffic[src_ip] += "Nmap_W;"

############# Tool distinction: Nmap -sS checks / TCP Header length #############
        if packet[scapy.TCP].flags == 0x02 and len(packet[scapy.TCP]) == 26:
            if "Nmap_HL" not in source_of_traffic[src_ip]:
                source_of_traffic[src_ip] += "Nmap_HL;"

############# Tool distinction: ZMap checks #############
############# Tool distinction: ZMap checks / IP ID Field #############
        if packet[scapy.IP].id == 54321:
            if "ZMap_ID" not in source_of_traffic[src_ip]:
                source_of_traffic[src_ip] += "ZMap_ID;"


        generate_final_report()


def main(interface):
    try:
        scapy.sniff(iface=interface, store=False, prn=port_scan_detection)
    except KeyboardInterrupt:
        print("[-] Stopping the scan detection tool.")

if __name__ == "__main__":
    main(interface)


