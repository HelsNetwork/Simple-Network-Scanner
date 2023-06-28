from scapy.all import ARP, Ether, srp, wrpcap


def scan_network(target_ip):
    # ARP packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=5, verbose=0)[0]
    clients = []

    for sent, received in result:
        clients.append({"ip": received.psrc, "mac": received.hwsrc})

    return clients


def save_to_pcap(clients, filename):
    packets = []
    for client in clients:
        arp = ARP(pdst=client["ip"], hwdst=client["mac"])
        ether = Ether(dst=client["mac"])
        packet = ether / arp
        packets.append(packet)

    wrpcap(filename, packets)
    print(f"Captured packets saved to {filename}")


def print_scan_results(clients):
    print("Available devices on the network:")
    print("IP" + " "*18 + "MAC")
    for client in clients:
        print("{:16}     {}".format(client["ip"], client["mac"]))


if __name__ == "__main__":
    target_ip = input("Enter your IP address to scan the network: ")

    # Perform network scan
    clients = scan_network(target_ip)

    # Print scan results
    print_scan_results(clients)

    # Prompt the user to input the filename for saving captured packets
    filename = input("Enter the filename to save the captured packets (e.g., network_scan.pcap): ")

    # Save captured packets to the specified filename
    save_to_pcap(clients, filename)
