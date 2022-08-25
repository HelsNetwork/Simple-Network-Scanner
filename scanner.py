from scapy.all import ARP, Ether, srp


while True:
       target_ip = (input('Enter an IP address: '))

       if target_ip == "":
        print("Please enter a valid IP address.")

       else: 
            break
   
# ARP packet
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")
packet = ether / arp
result = srp(packet, timeout=5)[0]
clients = []

for sent, received in result:
            clients.append({"ip": received.psrc, "mac": received.hwsrc})
        # print clients
print("Available devices on the network:")
print("IP" + "MAC")
for client in clients:
            print("{:16}     {}".format(client["ip"], client["mac"]))
