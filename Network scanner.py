from scapy.all import ARP, Ether, srp

target_ip = "IP ADDRESS"
# ARP packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp
result = srp(packet, timeout=3, verbose=0)[0]
clients = []

for sent, received in result:
    # for each reponse, append ip and mac address tp 'clients' list
    clients.append({"ip": received.psrc, "mac": received.hwsrc})
    # print clients
    print("Available devices on the network:")
    print("IP" + "MAC")
    for client in clients:
        print("{:16}     {}".format(client["ip"], client["mac"]))
