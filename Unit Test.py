import unittest
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import Ether

# Import the function and global lists from your module if split into files
# For now, assume everything is in the same file or defined above

# Re-define the global lists so they're accessible
s_ip, d_ip, s_port, d_port, protocols = [], [], [], [], []

# Re-define the process_packet function here (or import if modularized)
def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    else:
        return

    if TCP in packet:
        source_port = packet[TCP].sport
        dest_port = packet[TCP].dport
        protocol = 'TCP'
    elif UDP in packet:
        source_port = packet[UDP].sport
        dest_port = packet[UDP].dport
        protocol = 'UDP'
    else:
        return

    s_ip.append(src_ip)
    d_ip.append(dst_ip)
    s_port.append(source_port)
    d_port.append(dest_port)
    protocols.append(protocol)

# Now the unittest class
class TestPacketProcessing(unittest.TestCase):

    def setUp(self):
        # Clear global lists before each test to avoid test pollution
        s_ip.clear()
        d_ip.clear()
        s_port.clear()
        d_port.clear()
        protocols.clear()

    def test_tcp_packet(self):
        pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80)
        process_packet(pkt)
        self.assertEqual(s_ip[0], "10.0.0.1")
        self.assertEqual(d_ip[0], "10.0.0.2")
        self.assertEqual(s_port[0], 1234)
        self.assertEqual(d_port[0], 80)
        self.assertEqual(protocols[0], "TCP")

    def test_udp_packet(self):
        pkt = Ether()/IP(src="192.168.1.10", dst="192.168.1.20")/UDP(sport=53, dport=5353)
        process_packet(pkt)
        self.assertEqual(s_ip[0], "192.168.1.10")
        self.assertEqual(d_ip[0], "192.168.1.20")
        self.assertEqual(s_port[0], 53)
        self.assertEqual(d_port[0], 5353)
        self.assertEqual(protocols[0], "UDP")

    def test_non_ip_packet(self):
        pkt = Ether()  # No IP layer
        process_packet(pkt)
        self.assertEqual(len(s_ip), 0)  # Should not add anything

if __name__ == '__main__':
    unittest.main()
