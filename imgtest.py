from scapy.layers.inet import IP, UDP, TCP, ICMP
from scapy.layers.dot11 import RadioTap, Dot11QoS, Dot11, Dot11FCS
from scapy.layers.l2 import LLC, Ether
from scapy.layers.rtp import RTP

from scapy.packet import Packet, Raw
from scapy.sendrecv import sniff, sr1

from scapy.utils import PcapNgReader, PcapWriter


def main():
    with PcapNgReader("/home/brendon/Desktop/dronecaps/nosehill/takeoffUpLand.pcapng") as reader:
        with PcapWriter("/home/brendon/Desktop/dronecaps/isolated/stripped.pcap") as writer:
            for t, packet in enumerate(reader):
                packet: RadioTap

                try:
                    if IP in packet:
                        stripped = packet[IP]
                        stripped = Dot11(addr1=packet[Dot11FCS].addr1, addr2=packet[Dot11FCS].addr2) / stripped
                        writer.write(stripped)
                    #
                    # if stripped.src == "192.168.169.1":
                    #     # stripped.src = "127.0.0.1"
                    #     # stripped.dst = "127.0.0.1"
                    #     ether = Ether(src="00:0c:29:4f:03:be", dst="00:0c:29:4f:03:be") / stripped
                    #
                    #     rtp = RTP(ether[UDP].load)
                    #
                    #     rtp.sequence = t
                    #     rtp.timestamp = t * 1000
                    #     rtp.payload_type = 96  # First dynamic type ID
                    #
                    #     ether[UDP].payload = rtp

                    #ether.show()
                    #print("-"*100)

                    writer.write(packet)

                    if t % 1000 == 0:
                        print(t)
                except IndexError as e:
                    print(e)
                    pass

main()