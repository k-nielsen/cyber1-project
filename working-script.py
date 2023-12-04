import scapy.all as scapy
from collections import defaultdict
import time


# Dictionary to track TCP conversation completeness by source and destination IP pairs
conversation_completeness = {}
# Dictionary to count incomplete conversations by source IP
incomplete_conversations_count = {}

# Dictionary for tracking sources of traffic (used for Stealth detection)
sources_of_traffic_stealth = {}

# Dictionary for tracking attempts on not hosted ports
sources_of_traffic_ports = {}

# Mapped using https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html as inspiration
tcp_flags_map = {
	"S": 1, #SYN
	"SA": 2, #SYN-ACK
	"A": 4, #ACK
	"PA": 8, #Using PSH flag (combined with ACK) as indicator of DATA
	"FA": 16, #Using FIN in combination with ACK as indicator of finished conversation
	"RA": 32, #RST in combination with ACK as indicator of reset conversation
}

# Dictionary to store packet count per source IP
packet_count = defaultdict(int)

# Maybe not needed after all...
# def elapsed_time(ip_src):
#     current_time = time.time()
#     elapsed_time = current_time - packet_count[ip_src]['timestamp']
#     return elapsed_time

# Function to calculate packet rate
def calculate_packet_rate(ip_src):
    current_time = time.time()
    if ip_src in packet_count:
        elapsed_time = current_time - packet_count[ip_src]['timestamp']
        packet_rate = packet_count[ip_src]['count'] / elapsed_time
        return packet_rate
    else:
        return 0

# Function to handle packet callback
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        # print(ip_src)
        #Check if the packet has TCP layer (ZMap typically uses TCP)
        if packet.haslayer(scapy.TCP):
            tcp_sport = packet[scapy.TCP].sport
            tcp_dport = packet[scapy.TCP].dport
            
            # Check for high packet rate
            packet_rate = calculate_packet_rate(ip_src)
            if packet_rate > 10000:  # Adjust the threshold as needed
                print(f"High packet rate detected from {ip_src} to {ip_dst} on port {tcp_dport}")
                is_zmap(packet)

            # Check for large packet size
            if len(packet) > 1500:  # Adjust the threshold as needed
                print(f"Large packet size detected from {ip_src} to {ip_dst} on port {tcp_dport}")
                is_zmap(packet)

            # Update packet count for the source IP
            if ip_src in packet_count:
                packet_count[ip_src]['count'] += 1
                packet_count[ip_src]['timestamp'] = time.time()
            else:
                packet_count[ip_src] = {'count': 1, 'timestamp': time.time()}
            # packet_count[ip_src] = {'count': packet_count[ip_src]['count'] + 1, 'timestamp': time.time()}
            print(packet_count)
          
          
def detect_TCP_scan(packet):
    # Make sure it is a TCP packet
    if packet.haslayer(scapy.TCP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        src_port = packet[scapy.TCP].sport
        dst_port = packet[scapy.TCP].dport

        # Calculate a unique conversation identifier based on source and destination IPs and ports, initially only used in "Conversation Completeness detection"
        conversation_id = hash(str(sorted((f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"))))
        
        ############# Checking for conversation completeness as an indicator of port scanning #############
        ############# Inpsired by Wireshark Conversation Completeness #############
        # Calculate a value representing the packet's TCP flags
        tcp_flags = packet[scapy.TCP].flags

        if str(tcp_flags) in tcp_flags_map:         
            if conversation_id in conversation_completeness:
                conversation_completeness[conversation_id] |= tcp_flags_map[str(tcp_flags)]
            else:
                conversation_completeness[conversation_id] = tcp_flags_map[str(tcp_flags)]
            
        # For debugging purposes a notice of completed conversations
        if conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63:  # This indicates a complete conversation with data transfer (SYN, SYN-ACK, ACK, DATA, FIN)
            print(f"[+] Complete conversation with data transfer: {conversation_id} \n {conversation_completeness}")
            print("********************************* \n")

        # Check for incomplete conversations
        if not (conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63):
        #   # Disregards you own IP when potentially generating alerts, FIXME: maybe not the right way to do it?
           if src_ip != my_ip:
               if src_ip in incomplete_conversations_count:
                   incomplete_conversations_count[src_ip] += 1
                   if incomplete_conversations_count[src_ip] >= threshold: 
                       print(f"[+] Possible Port Scan from {src_ip} as it has meet or exceeded **{threshold}** number of incomplete conversations \n Number of incomplete conversations: {incomplete_conversations_count[src_ip]}")
                       print("********************************* \n")
               else:
                   incomplete_conversations_count[src_ip] = 1
           else:
               pass
        

############# Nmap half-open (stealth) scan Detection #############
############# Detects based on the default settings of Nmap -sS #############
        # Detecting -sS scans based on SYN flag, Small Window Size (1024) and small TCP header lenght (26)
        if packet[scapy.TCP].flags == 0x02 and packet[scapy.TCP].window==1024 and len(packet[scapy.TCP]) == 26:
            # Mechanism (if the program is left running) which captures slow scans
            if src_ip in sources_of_traffic_stealth:
                sources_of_traffic_stealth[src_ip] += 1
                if sources_of_traffic_stealth[src_ip] >= threshold:  # Adjust the threshold as needed
                    print(f"[+] Possible Nmap STEALTH scan detected from {src_ip}:{packet[scapy.TCP].sport}")
                    print("********************************* \n")
            else:
                sources_of_traffic_stealth[src_ip] = 1

############# Method for detecting port scans, based on prior knowledge and mapping of own services #############
############# Basically keeps track of a threshold of probes to IP's/Ports known not to have a service running #############
############# Based on inspiration from Jung et al. 2004, Fast Portscan Detection Using Sequential Hypothesis Testing #############
    
        # # A dictionary containing which hosts (IP's) has services on defined ports within our network
        known_services = {
           my_ip: [443, 22] # Adjust ports for hosted services as needed
        }
        
        if dst_ip == my_ip:
           if int(dst_port) not in [port for ports in known_services.values() for port in ports]:
               if src_ip in sources_of_traffic_ports:
                   sources_of_traffic_ports[src_ip] += 1
                   if sources_of_traffic_ports[src_ip] >= threshold:  # Adjust the threshold as needed
                       print(f"[+] Possible port scan detected, based on probes to unused ports, meeting or exceeding threshold: **{threshold}** \n From:  {src_ip}")
                       print("********************************* \n")
            
               else:
                  sources_of_traffic_ports[src_ip] = 1  
            
############# Zmap Detection #############
def is_zmap(packet):
    # Based on the default IP Id set by Zmap
        if packet[scapy.IP].id == 54321:
            print("[+] Potential ZMap scan")
            print("********************************* \n")

def main(interface):
	try:
		scapy.sniff(iface=interface, store=False, prn=packet_callback)
	except KeyboardInterrupt:
		print("[-] Stopping the scan detection tool.")

if __name__ == "__main__":
	threshold = 5 # Adjust the threshold as needed, sensitivity on both -sS and full connect scans
	my_ip = "172.16.210.134" # Change this to your IP
	interface = "ens33"  # Change this to your network interface
	main(interface)


# Experiment:
# Shared time frame (e.g. 10 seconds)
# Calculate the packet rate using the script
# (Maybe test how fast the scanners are to sending the packets??)

# Setup:
# Script runs on VM0 along with Wireshark (using capture filters) and a Python http server (python3 -m http.server -)
# Two sepearate VMs (one running both Nmap and ZMap and the other only running ZMap):
# VM running both ZMap and Nmap: Send 10 packets with the default settings on port 22 and port 8080
# VM only running ZMap: send 10 packets with default flags on port 8080
#
# Example commands with place holders
# sudo zmap IP -p 22
# sudo zmap IP -p 69
# nmap -p 22,80 IP

# Results (to be written in the report):
# The script intercepted x packets from vm1 and y packet from vm 2...


# After Wednesday:
# Look into using ML on our existing pcap files and the one we produced in the
# experiment (potentially along with some more training data e.g. just some web browsing)
