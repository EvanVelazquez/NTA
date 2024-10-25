from scapy.all import rdpcap

pcap = '/Users/evanvelazquez/Downloads/extracting-objects-from-pcap-example-01.pcap'

# Load packets from the PCAP file #
packets = rdpcap(pcap)
def process_packet(packet):
    pass
for packet in packets:
    process_packet(packet)

from scapy.layers.inet import IP, TCP, UDP
import pandas as pd

# lists to store extracted data #
s_ip = []
d_ip = []
s_port = []
d_port = []
protocols = []

# function to extract relevant info from each packet #
def process_packet(packet):

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst

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

    # Append extracted data #
    s_ip.append(src_ip)
    d_ip.append(dst_ip)
    s_port.append(source_port)
    d_port.append(dest_port)
    protocols.append(protocol)

for packet in packets:
    process_packet(packet)

# Data Frame #
df = pd.DataFrame({
    'Source IP': s_ip,
    'Destination IP': d_ip,
    'Source Port': s_port,
    'Destination Port': d_port,
    'Protocol': protocols
})

print(df)

# Graphs using matplotlib #

import matplotlib.pyplot as plt

sumstats = df.describe()
print("Summary Statistics:")
print(sumstats)

# Pie plot #
p_counts = df['Protocol'].value_counts()
plt.figure(figsize=(8, 6))
p_counts.plot(kind='pie', color='blue')
plt.title('Protocol Distribution')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.xticks(rotation=50)
plt.show()

# Bar Plot #
p_counts = df['Protocol'].value_counts()
plt.figure(figsize=(8, 6))
p_counts.plot(kind='bar', color='red')
plt.title('Protocol Distribution')
plt.xlabel('Protocol')
plt.ylabel('Count')
plt.xticks(rotation=50)
plt.show()

