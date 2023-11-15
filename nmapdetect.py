
## Ideas for program: "bonsaiviking - they see me scannin they hatin"

import scapy.all as scapy

# Dictionary to track TCP conversation completeness by source and destination IP pairs
conversation_completeness = {}
# Dictionary to count incomplete conversations by source IP
incomplete_conversations_count = {}

# Dictionary for tracking sources of traffic (used for Stealth detection)
sources_of_traffic = {}

# Mapped using https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html as inspiration
tcp_flags_map = {
	"S": 1, #SYN
	"SA": 2, #SYN-ACK
	"A": 4, #ACK
	"PA": 8, #Using PSH flag (combined with ACK) as indicator of DATA
	"FA": 16, #Using FIN in combination with ACK as indicator of finished conversation
	"RA": 32, #RST in combination with ACK as indicator of reset conversation
}


def detect_nmap_scan(packet):
	# Make sure it is a TCP packet
	if packet.haslayer(scapy.TCP):
		print("[+] Possible Zmap scan detected from {}:{}".format(packet[scapy.IP].src, packet[scapy.TCP].sport))
            	print("Flag is: {}".format(flags))
	        print("Packet length is: {}".format(len(packet)))
	        packet.show()
	        print("")
	        print(packet.raw_packet_cache)
	        for i in packet.fields:
	        	print(i, packet.fields[i])
	        packet.payload.show()
	        print("Packet header???: {}".format(str(packet)[:(packet[scapy.IP].ihl * 4)]))

		src_ip = packet[scapy.IP].src
		dst_ip = packet[scapy.IP].dst
		src_port = packet[scapy.TCP].sport
		dst_port = packet[scapy.TCP].dport

		# Calculate a unique conversation identifier based on source and destination IPs and ports
		conversation_id = hash(str(sorted((f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"))))
		
		# Checking for conversation completeness as an indicator of port scanning
		# Calculate a value representing the packet's TCP flags
		tcp_flags = packet[scapy.TCP].flags
		
		# Use the map inpsired from Wireshark documentation to calculate conversation completeness
		if str(tcp_flags) in tcp_flags_map:			
			if conversation_id in conversation_completeness:
				conversation_completeness[conversation_id] |= tcp_flags_map[str(tcp_flags)]
			else:
				conversation_completeness[conversation_id] = tcp_flags_map[str(tcp_flags)]
			
		# For debugging purposes
		# Check for complete conversations with data transfer, values from Wireshark inspiration
		if conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63:  # This indicates a complete conversation with data transfer (SYN, SYN-ACK, ACK, DATA, FIN)
			print(f"[+] Complete conversation with data transfer: {conversation_id} \n {conversation_completeness}")

		# Check for incomplete conversations
		if not (conversation_completeness[conversation_id] == 31 or conversation_completeness[conversation_id] == 47 or conversation_completeness[conversation_id] == 63):
			# Disregards you own IP when potentially generating alerts, FIXME: maybe not the right way to do it?
			if src_ip != my_ip:
				if src_ip in incomplete_conversations_count:
					incomplete_conversations_count[src_ip] += 1
					if incomplete_conversations_count[src_ip] >= threshold: 
						print(f"[+] Possible Port Scan from {src_ip} as it has more than **{threshold}** number of incomplete conversations \n Number of incomplete conversations: {incomplete_conversations_count[src_ip]}")
						print("*********************************")
				else:
					incomplete_conversations_count[src_ip] = 1
			else:
				pass

		# Detecting -sS scans based on SYN flag, Small Window Size (1024) and small TCP header lenght (26)
		if packet[scapy.TCP].flags == 0x02 and packet[scapy.TCP].window==1024 and len(packet[scapy.TCP]) == 26:
			
			# Mechanism (if the program is left running) which captures slow scans
			if src_ip in sources_of_traffic:
				sources_of_traffic[src_ip] += 1
				if sources_of_traffic[src_ip] >= threshold:  # Adjust the threshold as needed
					print(f"[+] Possible Nmap STEALTH scan detected from {src_ip}:{packet[scapy.TCP].sport}")
					
			else:
				sources_of_traffic[src_ip] = 1

	


def main(interface):
	try:
		scapy.sniff(iface=interface, store=False, prn=detect_nmap_scan)
	except KeyboardInterrupt:
		print("[-] Stopping the Nmap scan detection tool.")

if __name__ == "__main__":
	threshold = 5 # Adjust the threshold as needed, sensitivity on both -sS and full connect scans
	my_ip = "192.168.56.101" # Change this to your IP
	interface = "enp0s3"  # Change this to your network interface
	main(interface)
