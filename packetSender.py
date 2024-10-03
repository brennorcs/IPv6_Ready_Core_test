from scapy.all import *
import time
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--source", help = "IPv6 source address", type= str)
parser.add_argument("-d", "--destine", help = "IPv6 destine address", type= str)
parser.add_argument("-T", help = "1 for run Test V6LX1.3.1, 2 for run Test V6LX1.3.2 and 3 for run Test V6LX1.3.3", type = int )
args = parser.parse_args()

myIP = args.source  # IPv6 fonte
dstIP = args.destine  # IPv6 destino

# Fragmento A1
A1 = IPv6(src=myIP, dst=dstIP, nh=44)  # Next Header: 44 (Fragment Header)
FH_A1 = IPv6ExtHdrFragment(nh=58, offset=0, m=1, id=1)  # Next Header: 58 (ICMPv6), More Fragments flag: 1, Offset: 0
icmp_req = ICMPv6EchoRequest(data='A'*32)  # Payload de 32 bytes
icmp_req.cksum = 0x91f8
fragment_A1 = A1 / FH_A1 / icmp_req  # Fragmento A1 completo
print("Fragmento A1\r\n")
fragment_A1.show()
print("\r\n")

# Fragmento A2 (32 bytes de dados)
A2 = IPv6(src=myIP, dst=dstIP, nh=44)  # Next Header: 44 (Fragment Header)
FH_A2 = IPv6ExtHdrFragment(nh=58, offset=4, m=1, id=1)  # Offset: 4 (32 bytes), More Fragments flag: 1
data_A2 = Raw(load='B'*32)  # Fragment Data de 32 bytes
fragment_A2 = A2 / FH_A2 / data_A2  # Fragmento A2 completo
print("Fragmento A2\r\n")
fragment_A2.show()
print("\r\n")

# Fragmento A3 (24 bytes de dados, último fragmento)
A3 = IPv6(src=myIP, dst=dstIP, nh=44)  # Next Header: 44 (Fragment Header)
FH_A3 = IPv6ExtHdrFragment(nh=58, offset=8, m=0, id=1)  # Offset: 8 (64 bytes), More Fragments flag: 0 (último fragmento)
data_A3 = Raw(load='C'*24)  # Fragment Data de 24 bytes
fragment_A3 = A3 / FH_A3 / data_A3  # Fragmento A3 completo
print("Fragmento A3\r\n")
fragment_A3.show()
print("\r\n")


if(args.T == 1 ):
    # Test v6LC.1.3.1: Fragment Reassembly A
    print("Test v6LC.1.3.1: Fragment Reassembly A\r\n")
    send(fragment_A1)
    print(f"Enviado fragmento A1: {fragment_A1.summary()}")

    send(fragment_A2)
    print(f"Enviado fragmento A2: {fragment_A2.summary()}")

    send(fragment_A3)
    print(f"Enviado fragmento A3: {fragment_A3.summary()}")
    time.sleep(15)
    #Test v6LC.1.3.1: Fragment Reassembly B
    print("Test v6LC.1.3.1: Fragment Reassembly B\r\n")
    send(fragment_A3)
    print(f"Enviado fragmento A3: {fragment_A3.summary()}")

    send(fragment_A2)
    print(f"Enviado fragmento A2: {fragment_A2.summary()}")

    send(fragment_A1)
    print(f"Enviado fragmento A1: {fragment_A1.summary()}")
elif(args.T == 2):
    #Test v6LC.1.3.2: Reassembly Time Exceeded A
    print("Test v6LC.1.3.2: Reassembly Time Exceeded A\r\n")
    send(fragment_A1)
    print(f"Enviado fragmento A1: {fragment_A1.summary()}")

    time.sleep(55)

    send(fragment_A2)
    print(f"Enviado fragmento A2: {fragment_A2.summary()}")

    time.sleep(55)

    send(fragment_A3)
    print(f"Enviado fragmento A3: {fragment_A3.summary()}")
    time.sleep(15)
    #Test v6LC.1.3.2: Reassembly Time Exceeded B
    print("Test v6LC.1.3.2: Reassembly Time Exceeded B\r\n")
    send(fragment_A1)
    print(f"Enviado fragmento A1: {fragment_A1.summary()}")

    time.sleep(65)

    send(fragment_A2)
    print(f"Enviado fragmento A2: {fragment_A2.summary()}")

    time.sleep(65)

    send(fragment_A3)
    print(f"Enviado fragmento A3: {fragment_A3.summary()}")
    time.sleep(15)
    #Test v6LC.1.3.2: Reassembly Time Exceeded C
    print("Test v6LC.1.3.2: Reassembly Time Exceeded C\r\n")
    send(fragment_A1)
    print(f"Enviado fragmento A1: {fragment_A1.summary()}")
elif(args.T ==3):
    #Test v6LC.1.3.3: Fragment Header M-Bit Set, Payload Length Invalid

    print("Test v6LC.1.3.3: Fragment Header M-Bit Set, Payload Length Invalid\r\n")
    # Fragmento B
    B = IPv6(src=myIP, dst=dstIP, nh=44)  # Next Header: 44 (Fragment Header)
    FH_B = IPv6ExtHdrFragment(nh=58, offset=0, m=1, id=1)  # Next Header: 58 (ICMPv6), More Fragments flag: 1, Offset: 0
    icmp_req = ICMPv6EchoRequest(data='ABCDE')  # Payload de 5 bytes
    fragment_B = B / FH_B / icmp_req  # Fragmento A1 completo
    fragment_B.plen = 21

    print("Fragmento A\r\n")
    fragment_B.show()
    print("\r\n")
    send(fragment_B)
    print(f"Enviado fragmento B: {fragment_B.summary()}")

